package main

// Migrate-then-start pod-cgroup adoption.
//
// At activation the parked task's init is a ~1MB pre-execve stub charged to
// the bundle cgroup. Before task.Start, the worker creates the EXACT pod
// cgroup the kubelet would compute for this pod UID (Guaranteed QoS →
// kubepods/pod<uid>), applies the phantom's full limit set, and migrates the
// parked PID into it. Only then does the function execve — so every byte it
// allocates is charged to the kubelet-shaped cgroup from byte 0.
//
// When the kubelet later adopts the pod, EnsureExists sees the cgroup already
// present and returns immediately (pod_container_manager_linux.go: the
// limit-application branch only runs when !alreadyExists). That makes this
// worker SOLELY AUTHORITATIVE for the limits — nothing re-applies them — so
// the full Guaranteed set is written here: memory.max, cpu.max, cpu.weight,
// and pids.max when configured.
//
// Two drivers, matching the kubelet's two cgroup drivers:
//   cgroupfs: mkdir <root>/kubepods/pod<uid> + direct file writes (µs).
//   systemd:  StartTransientUnit("kubepods-pod<uid esc>.slice") over the
//             systemd private socket, with the same limits as unit properties.
//             UID dashes become underscores (kubelet escapeSystemdCgroupName)
//             — the exact unit name is what makes the kubelet's Exists() true.

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	sd "github.com/coreos/go-systemd/v22/dbus"
	godbus "github.com/godbus/dbus/v5"
)

var (
	cgroupDriverFlag = flag.String("cgroup-driver", "off", "pod-cgroup adoption driver: off|cgroupfs|systemd|auto. When enabled and the create request carries pod_uid, the parked PID is migrated into kubepods/pod<uid> (with the phantom's limits) BEFORE task start")
	cgroupRoot       = flag.String("cgroup-root", "/sys/fs/cgroup", "cgroup v2 unified hierarchy mountpoint")
	podPidsMax       = flag.Int64("pod-pids-max", 0, "pids.max / TasksMax for adopted pod cgroups (0 = leave unlimited, matching a kubelet without --pod-max-pids)")

	cgroupDriver string // resolved at startup: "", "cgroupfs", or "systemd"

	systemdConnMu sync.Mutex
	systemdConn   *sd.Conn
)

// podCgroups maps sandbox ID -> adopted pod cgroup fs path, so delete can
// remove the cgroup (cgroupfs) or stop the transient slice (systemd).
var podCgroups sync.Map

// preparedSlices maps pod cgroup fs path -> true for cgroups created at
// REGISTRATION time (via /cgroup/prepare). These are registration-owned:
// claim-time adoption skips dbus entirely (just a cgroup.procs write), and
// sandbox delete leaves them standing for the next claim of the same phantom.
// Rationale: StartTransientUnit serializes through PID 1 — measured p50
// 236ms at one-node burst-10 when on the claim path; hoisted to registration
// it costs nothing per activation.
//
// Prepared-ness must survive worker restarts (cgroup dirs persist on the
// host while this map does not), so it is mirrored as marker files under
// preparedMarkerDir; the map is just a cache over them.
var preparedSlices sync.Map

const preparedMarkerDir = "/run/rune/prepared-cgroups"

func markPrepared(dir string) {
	preparedSlices.Store(dir, true)
	_ = os.MkdirAll(preparedMarkerDir, 0o755)
	_ = os.WriteFile(filepath.Join(preparedMarkerDir, filepath.Base(dir)), nil, 0o644)
}

func isPrepared(dir string) bool {
	if _, ok := preparedSlices.Load(dir); ok {
		return true
	}
	if _, err := os.Stat(filepath.Join(preparedMarkerDir, filepath.Base(dir))); err == nil {
		preparedSlices.Store(dir, true)
		return true
	}
	return false
}

// podCgroupSpec is the limit set applied to the adopted pod cgroup. For a
// Guaranteed phantom, requests == limits; CPURequestMilli only feeds cpu.weight.
type podCgroupSpec struct {
	PodUID          string
	MemoryLimitKB   int64 // 0 = no memory.max
	CPULimitMilli   int64 // 0 = no cpu.max
	CPURequestMilli int64 // 0 = default cpu.weight (100)
}

// resolveCgroupDriver pins the driver once at startup. "auto" prefers the
// driver of an existing kubepods tree; with no kubelet on the node yet it
// falls back to cgroupfs (the worker creates the tree itself, and k3s's
// default kubelet driver is cgroupfs).
func resolveCgroupDriver() string {
	switch *cgroupDriverFlag {
	case "off", "":
		return ""
	case "cgroupfs", "systemd":
		return *cgroupDriverFlag
	case "auto":
		// The kubelet's driver is whichever tree it POPULATED (QoS children),
		// not whichever directory merely exists — k3s nodes can have an empty
		// kubepods.slice alongside a live cgroupfs kubepods tree.
		if _, err := os.Stat(filepath.Join(*cgroupRoot, "kubepods.slice", "kubepods-besteffort.slice")); err == nil {
			return "systemd"
		}
		if _, err := os.Stat(filepath.Join(*cgroupRoot, "kubepods", "besteffort")); err == nil {
			return "cgroupfs"
		}
		if _, err := os.Stat(filepath.Join(*cgroupRoot, "kubepods.slice")); err == nil {
			return "systemd"
		}
		if _, err := os.Stat(filepath.Join(*cgroupRoot, "kubepods")); err == nil {
			return "cgroupfs"
		}
		log.Printf("[cgroup] auto: no kubepods tree found under %s, defaulting to cgroupfs", *cgroupRoot)
		return "cgroupfs"
	default:
		log.Fatalf("[cgroup] unknown --cgroup-driver %q (off|cgroupfs|systemd|auto)", *cgroupDriverFlag)
		return ""
	}
}

// adoptPodCgroup creates the kubelet-shaped pod cgroup with the full limit
// set and migrates pid into it. Returns the cgroup fs path for teardown.
func adoptPodCgroup(spec podCgroupSpec, pid int) (string, error) {
	switch cgroupDriver {
	case "cgroupfs":
		return adoptCgroupfs(spec, pid)
	case "systemd":
		return adoptSystemd(spec, pid)
	}
	return "", fmt.Errorf("cgroup adoption disabled")
}

// --- cgroupfs driver: mkdir + file writes, microseconds on the hot path ---

func adoptCgroupfs(spec podCgroupSpec, pid int) (string, error) {
	kubepods := filepath.Join(*cgroupRoot, "kubepods")
	dir := filepath.Join(kubepods, "pod"+spec.PodUID)

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", dir, err)
	}
	// Pod limits live on pod<uid>, which needs cpu/memory/pids enabled in the
	// parent's subtree_control. Idempotent when a kubelet already did this;
	// necessary when the worker creates the kubepods tree itself.
	ensureSubtreeControllers(*cgroupRoot)
	ensureSubtreeControllers(kubepods)

	if err := writePodLimits(dir, spec); err != nil {
		_ = os.Remove(dir)
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o644); err != nil {
		_ = os.Remove(dir)
		return "", fmt.Errorf("migrate pid %d: %w", pid, err)
	}
	return dir, nil
}

// ensureSubtreeControllers enables cpu, memory and pids in dir's
// cgroup.subtree_control. One token per write — a single failing controller
// must not abort the others — and failures are non-fatal (already enabled, or
// controller absent on this kernel).
func ensureSubtreeControllers(dir string) {
	path := filepath.Join(dir, "cgroup.subtree_control")
	for _, c := range []string{"+cpu", "+memory", "+pids"} {
		_ = os.WriteFile(path, []byte(c), 0o644)
	}
}

func writePodLimits(dir string, spec podCgroupSpec) error {
	if spec.MemoryLimitKB > 0 {
		v := strconv.FormatInt(spec.MemoryLimitKB*1024, 10)
		if err := os.WriteFile(filepath.Join(dir, "memory.max"), []byte(v), 0o644); err != nil {
			return fmt.Errorf("memory.max: %w", err)
		}
	}
	if spec.CPULimitMilli > 0 {
		// kubelet CFS math: quota = milliCPU * period / 1000, period 100ms.
		quota := spec.CPULimitMilli * 100000 / 1000
		v := fmt.Sprintf("%d 100000", quota)
		if err := os.WriteFile(filepath.Join(dir, "cpu.max"), []byte(v), 0o644); err != nil {
			return fmt.Errorf("cpu.max: %w", err)
		}
	}
	if w := cpuWeightFromMilli(spec.CPURequestMilli); w > 0 {
		if err := os.WriteFile(filepath.Join(dir, "cpu.weight"), []byte(strconv.FormatInt(w, 10)), 0o644); err != nil {
			return fmt.Errorf("cpu.weight: %w", err)
		}
	}
	if *podPidsMax > 0 {
		if err := os.WriteFile(filepath.Join(dir, "pids.max"), []byte(strconv.FormatInt(*podPidsMax, 10)), 0o644); err != nil {
			return fmt.Errorf("pids.max: %w", err)
		}
	}
	return nil
}

// --- systemd driver: StartTransientUnit over the systemd private socket ---

func adoptSystemd(spec podCgroupSpec, pid int) (string, error) {
	unit := "kubepods-pod" + escapeSystemdUID(spec.PodUID) + ".slice"
	dir := filepath.Join(*cgroupRoot, "kubepods.slice", unit)

	// Fast path: slice pre-created at registration (or by a previous claim of
	// this phantom). Adoption is then a single cgroup.procs write — no dbus,
	// no PID-1 serialization on the hot path.
	if _, serr := os.Stat(dir); serr == nil {
		if werr := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o644); werr != nil {
			return "", fmt.Errorf("migrate pid %d into existing %s: %w", pid, unit, werr)
		}
		return dir, nil
	}

	if _, err := createSystemdSlice(spec, unit, dir); err != nil {
		return "", err
	}

	// Migrate the parked PID into the slice. systemd never places processes in
	// slices itself, but the kernel allows it: the slice has no scopes yet, so
	// its subtree_control is empty and the internal-process constraint is moot.
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o644); err != nil {
		return "", fmt.Errorf("migrate pid %d into %s: %w", pid, unit, err)
	}
	return dir, nil
}

// createSystemdSlice creates the kubelet-shaped pod slice via StartTransientUnit
// with the FULL Guaranteed property set (the kubelet never re-applies limits on
// its EnsureExists exists-path, so whatever is set here is final).
func createSystemdSlice(spec podCgroupSpec, unit, dir string) (string, error) {
	conn, err := getSystemdConn()
	if err != nil {
		return "", err
	}

	props := []sd.Property{
		{Name: "Description", Value: godbus.MakeVariant("PhantomK8s pod " + spec.PodUID)},
		// No Slice= property: slice units nest by NAME ("Slice may not be set
		// for slice units") — kubepods-podX.slice is a child of kubepods.slice.
		{Name: "MemoryAccounting", Value: godbus.MakeVariant(true)},
		{Name: "CPUAccounting", Value: godbus.MakeVariant(true)},
		{Name: "TasksAccounting", Value: godbus.MakeVariant(true)},
	}
	if spec.MemoryLimitKB > 0 {
		props = append(props, sd.Property{Name: "MemoryMax", Value: godbus.MakeVariant(uint64(spec.MemoryLimitKB * 1024))})
	}
	if spec.CPULimitMilli > 0 {
		// CPUQuotaPerSecUSec: µs of CPU per second → milliCPU * 1000.
		props = append(props, sd.Property{Name: "CPUQuotaPerSecUSec", Value: godbus.MakeVariant(uint64(spec.CPULimitMilli * 1000))})
	}
	if w := cpuWeightFromMilli(spec.CPURequestMilli); w > 0 {
		props = append(props, sd.Property{Name: "CPUWeight", Value: godbus.MakeVariant(uint64(w))})
	}
	if *podPidsMax > 0 {
		props = append(props, sd.Property{Name: "TasksMax", Value: godbus.MakeVariant(uint64(*podPidsMax))})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan string, 1)
	_, err = conn.StartTransientUnitContext(ctx, unit, "replace", props, done)
	if err != nil && strings.Contains(err.Error(), "closed") {
		// Stale connection (systemd restarted) — reconnect and retry once.
		resetSystemdConn()
		if conn, err = getSystemdConn(); err == nil {
			_, err = conn.StartTransientUnitContext(ctx, unit, "replace", props, done)
		}
	}
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			// Stale slice from a previous run — reuse it, refresh the limits.
			if serr := conn.SetUnitPropertiesContext(ctx, unit, true, props...); serr != nil {
				return "", fmt.Errorf("refresh stale slice %s: %w", unit, serr)
			}
		} else {
			return "", fmt.Errorf("StartTransientUnit %s: %w", unit, err)
		}
	} else {
		select {
		case status := <-done:
			if status != "done" {
				return "", fmt.Errorf("StartTransientUnit %s: job %s", unit, status)
			}
		case <-ctx.Done():
			return "", fmt.Errorf("StartTransientUnit %s: timeout", unit)
		}
	}
	return dir, nil
}

// escapeSystemdUID mirrors kubelet escapeSystemdCgroupName
// (cgroup_manager_linux.go): dashes become underscores. Getting this exact
// name wrong makes the kubelet's Exists() false → it creates a second slice
// and accounting splits.
func escapeSystemdUID(uid string) string {
	return strings.ReplaceAll(uid, "-", "_")
}

func resetSystemdConn() {
	systemdConnMu.Lock()
	defer systemdConnMu.Unlock()
	if systemdConn != nil {
		systemdConn.Close()
		systemdConn = nil
	}
}

func getSystemdConn() (*sd.Conn, error) {
	systemdConnMu.Lock()
	defer systemdConnMu.Unlock()
	if systemdConn != nil {
		return systemdConn, nil
	}
	// Background context on purpose: godbus ties the CONNECTION lifetime to
	// this context (WithContext), so a timeout+cancel here closes the
	// connection as soon as we return ("dbus: connection closed by user").
	conn, err := sd.NewSystemdConnectionContext(context.Background())
	if err != nil {
		return nil, fmt.Errorf("systemd private socket: %w", err)
	}
	systemdConn = conn
	return conn, nil
}

// releasePodCgroup tears down an adopted pod cgroup after sandbox delete.
// The task kill is asynchronous, so the cgroup may briefly hold dying PIDs —
// retry the removal for a couple of seconds. Run in a goroutine.
func releasePodCgroup(sandboxID string) {
	raw, ok := podCgroups.LoadAndDelete(sandboxID)
	if !ok {
		return
	}
	removePodCgroupPath(raw.(string))
}

// preparePodCgroup creates the kubelet-shaped pod cgroup with the full limit
// set at REGISTRATION time, without migrating any PID. Claims then take the
// exists fast path (procs write only). Idempotent.
func preparePodCgroup(spec podCgroupSpec) (string, error) {
	switch cgroupDriver {
	case "cgroupfs":
		kubepods := filepath.Join(*cgroupRoot, "kubepods")
		dir := filepath.Join(kubepods, "pod"+spec.PodUID)
		if _, err := os.Stat(dir); err != nil {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return "", fmt.Errorf("mkdir %s: %w", dir, err)
			}
			ensureSubtreeControllers(*cgroupRoot)
			ensureSubtreeControllers(kubepods)
			if err := writePodLimits(dir, spec); err != nil {
				_ = os.Remove(dir)
				return "", err
			}
		}
		markPrepared(dir)
		return dir, nil
	case "systemd":
		unit := "kubepods-pod" + escapeSystemdUID(spec.PodUID) + ".slice"
		dir := filepath.Join(*cgroupRoot, "kubepods.slice", unit)
		if _, err := os.Stat(dir); err != nil {
			if _, err := createSystemdSlice(spec, unit, dir); err != nil {
				return "", err
			}
		}
		markPrepared(dir)
		return dir, nil
	}
	return "", fmt.Errorf("cgroup adoption disabled")
}

// removePodCgroupPath removes an adopted pod cgroup by fs path. Used directly
// when a launch fails before a sandbox ID exists to key the podCgroups map.
// Registration-owned (prepared) cgroups are left standing.
func removePodCgroupPath(dir string) {
	if isPrepared(dir) {
		return
	}
	removePodCgroupPathForce(dir)
}

func removePodCgroupPathForce(dir string) {
	if cgroupDriver == "systemd" {
		unit := filepath.Base(dir)
		if conn, err := getSystemdConn(); err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if _, err := conn.StopUnitContext(ctx, unit, "replace", nil); err != nil {
				log.Printf("[cgroup] stop %s: %v", unit, err)
			}
			cancel()
		}
		// StopUnit removes the slice cgroup once empty; fall through to the
		// rmdir loop as a backstop in case systemd lost track of it.
	}
	for i := 0; i < 15; i++ {
		err := os.Remove(dir)
		if err == nil || os.IsNotExist(err) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	log.Printf("[cgroup] could not remove %s after retries (still has procs?)", dir)
}

// cpuWeightFromMilli converts a CPU request to a cgroup v2 weight using the
// kubelet's exact two-step math: milli → v1 shares → v2 weight.
func cpuWeightFromMilli(milli int64) int64 {
	if milli <= 0 {
		return 0
	}
	shares := milli * 1024 / 1000
	if shares < 2 {
		shares = 2
	}
	return 1 + ((shares-2)*9999)/262142
}

// parseCPUMilli parses a K8s CPU quantity ("500m", "1", "1.5") into millicores.
func parseCPUMilli(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if strings.HasSuffix(s, "m") {
		v, err := strconv.ParseInt(strings.TrimSuffix(s, "m"), 10, 64)
		if err != nil {
			return 0
		}
		return v
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return int64(v * 1000)
}
