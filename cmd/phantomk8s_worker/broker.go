package main

// C launch-broker pool — an alternative claim/start data plane that bypasses
// containerd's runc-v2 shim (and its Go ForkLock / GOMAXPROCS=4 serialization).
//
// We run N tiny single-threaded C broker processes. Each is an independent
// spawn lane: fork + setns(netns) + cgroup-attach + exec. N brokers => N
// independent fork locks, so concurrent claims scale with N instead of
// serializing through one shim. A broker-launched process is NOT a containerd
// task — it is a real isolated process in a pool bundle (netns + cgroup),
// reachable via the in-bundle socket activator. This is the data-plane-floor
// arm (sanctioned-seam-minus on the nativeness taxonomy: real OCI rootfs/mnt
// isolation is future work; today it is netns + cgroup + host-exec).

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// brokerSource is compiled at startup. Protocol on stdin/stdout, line-based:
//
//	SPAWN <netns|-> <cgroup_procs|-> <exe> [args...]  ->  PID <pid> <fork_us> | ERR <msg>
//	KILL  <pid> <sig>                                 ->  OK | ERR <msg>
//
// Children are NOT auto-reaped here (we want KILL+status); a SIGCHLD handler
// reaps asynchronously so zombies don't accumulate.
const brokerSource = `
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sched.h>
#include <time.h>
#include <sys/wait.h>

static long now_us(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts);
    return ts.tv_sec*1000000L + ts.tv_nsec/1000L; }

static void reaper(int sig){ (void)sig; while (waitpid(-1,NULL,WNOHANG)>0){} }

int main(void){
    struct sigaction sa = {0};
    sa.sa_handler = reaper; sa.sa_flags = SA_RESTART|SA_NOCLDSTOP;
    sigaction(SIGCHLD,&sa,NULL);
    setvbuf(stdout,NULL,_IOLBF,0);
    printf("READY %d\n", getpid());

    char line[8192]; char *argv[64];
    while (fgets(line,sizeof line,stdin)){
        line[strcspn(line,"\n")] = 0;
        if (!strncmp(line,"QUIT",4)) break;
        if (!strncmp(line,"KILL ",5)){
            int pid=0,sig=0; sscanf(line+5,"%d %d",&pid,&sig);
            printf(kill(pid,sig)==0 ? "OK\n" : "ERR kill\n");
            continue;
        }
        if (strncmp(line,"SPAWN ",6)){ printf("ERR proto\n"); continue; }

        int argc=0; char *save=NULL;
        char *netns = strtok_r(line+6," ",&save);
        char *cgroup = strtok_r(NULL," ",&save);
        char *tok;
        while ((tok=strtok_r(NULL," ",&save)) && argc<62) argv[argc++]=tok;
        argv[argc]=NULL;
        if (!netns||!cgroup||argc==0){ printf("ERR args\n"); continue; }

        long t0=now_us();
        pid_t pid=fork();
	        if (pid<0){ printf("ERR fork\n"); continue; }
	        if (pid==0){
	            int nullfd=open("/dev/null",O_RDWR);
	            if (nullfd>=0){
	                dup2(nullfd,STDIN_FILENO);
	                dup2(nullfd,STDOUT_FILENO);
	                dup2(nullfd,STDERR_FILENO);
	                if (nullfd>STDERR_FILENO) close(nullfd);
	            }
	            if (netns[0]!='-'){
	                int fd=open(netns,O_RDONLY|O_CLOEXEC);
	                if (fd<0 || setns(fd,CLONE_NEWNET)!=0) _exit(91);
            }
            execv(argv[0],argv);
            _exit(92);
        }
        /* parent: attach cgroup best-effort (process migrates even post-exec) */
        if (cgroup[0]!='-'){
            int fd=open(cgroup,O_WRONLY);
            if (fd>=0){ char b[32]; int n=snprintf(b,sizeof b,"%d",pid); write(fd,b,n); close(fd); }
        }
        printf("PID %d %ld\n", pid, now_us()-t0);
    }
    return 0;
}
`

// broker is one C spawn lane.
type broker struct {
	cmd    *exec.Cmd
	stdin  io.Writer
	stdout *bufio.Reader
	mu     sync.Mutex // one in-flight command per lane
	pid    int
}

func startBroker(binPath string) (*broker, error) {
	cmd := exec.Command(binPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	r := bufio.NewReader(stdout)
	ready, err := r.ReadString('\n')
	if err != nil || !strings.HasPrefix(ready, "READY") {
		cmd.Process.Kill()
		return nil, fmt.Errorf("broker handshake failed: %q (%v)", ready, err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(ready, "READY ")))
	return &broker{cmd: cmd, stdin: stdin, stdout: r, pid: pid}, nil
}

func (b *broker) command(line string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, err := io.WriteString(b.stdin, line+"\n"); err != nil {
		return "", err
	}
	return b.stdout.ReadString('\n')
}

// BrokerPool shards launches across N broker lanes.
type BrokerPool struct {
	brokers []*broker
	next    atomic.Uint64
	binPath string
}

// NewBrokerPool compiles the broker and starts n lanes.
func NewBrokerPool(n int) (*BrokerPool, error) {
	if n <= 0 {
		return nil, fmt.Errorf("broker pool size must be > 0")
	}
	dir, err := os.MkdirTemp("", "rune-broker")
	if err != nil {
		return nil, err
	}
	src := filepath.Join(dir, "broker.c")
	bin := filepath.Join(dir, "broker")
	if err := os.WriteFile(src, []byte(brokerSource), 0644); err != nil {
		return nil, err
	}
	if out, err := exec.Command("cc", "-O2", "-o", bin, src).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("compile broker: %v: %s", err, out)
	}
	bp := &BrokerPool{binPath: bin}
	for i := 0; i < n; i++ {
		br, err := startBroker(bin)
		if err != nil {
			bp.Close()
			return nil, fmt.Errorf("start broker %d: %w", i, err)
		}
		bp.brokers = append(bp.brokers, br)
	}
	return bp, nil
}

// laneFor maps a key (bundle ID) to a lane; round-robin if key < 0.
func (bp *BrokerPool) laneFor(key int) *broker {
	if key >= 0 {
		return bp.brokers[key%len(bp.brokers)]
	}
	i := bp.next.Add(1) - 1
	return bp.brokers[int(i)%len(bp.brokers)]
}

// Launch forks an isolated process in the bundle (netns + cgroup) and execs
// exe+args. Returns (pid, fork_us). cgroupProcs/netns may be "" to skip.
func (bp *BrokerPool) Launch(slotKey int, netns, cgroupProcs, exe string, args []string) (int, float64, error) {
	if netns == "" {
		netns = "-"
	}
	if cgroupProcs == "" {
		cgroupProcs = "-"
	}
	cmd := "SPAWN " + netns + " " + cgroupProcs + " " + exe
	if len(args) > 0 {
		cmd += " " + strings.Join(args, " ")
	}
	reply, err := bp.laneFor(slotKey).command(cmd)
	if err != nil {
		return 0, 0, err
	}
	f := strings.Fields(strings.TrimSpace(reply))
	if len(f) < 3 || f[0] != "PID" {
		return 0, 0, fmt.Errorf("broker launch failed: %q", strings.TrimSpace(reply))
	}
	pid, _ := strconv.Atoi(f[1])
	forkUs, _ := strconv.ParseFloat(f[2], 64)
	return pid, forkUs, nil
}

// Kill signals a broker-launched process via the lane that owns its bundle.
func (bp *BrokerPool) Kill(slotKey, pid, sig int) error {
	reply, err := bp.laneFor(slotKey).command(fmt.Sprintf("KILL %d %d", pid, sig))
	if err != nil {
		return err
	}
	if !strings.HasPrefix(reply, "OK") {
		return fmt.Errorf("broker kill: %q", strings.TrimSpace(reply))
	}
	return nil
}

func (bp *BrokerPool) Size() int { return len(bp.brokers) }

func (bp *BrokerPool) Close() {
	for _, b := range bp.brokers {
		io.WriteString(b.stdin, "QUIT\n")
		b.cmd.Process.Kill()
	}
}
