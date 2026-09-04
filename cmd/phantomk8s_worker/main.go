/*
 * PhantomK8s Sandbox Manager — standalone mode.
 *
 * Reuses Dirigent's containerd sandbox runtime but exposes a simple HTTP API
 * that the PhantomK8s gateway (or agent) can call directly.
 *
 * No Dirigent control plane required. No gRPC dependency on the hot path.
 *
 * Usage:
 *   sudo ./phantomk8s_worker \
 *       --port 10010 \
 *       --containerd-sock /run/containerd/containerd.sock \
 *       --cni-config /etc/cni/net.d/10-flannel.conflist
 *
 * API:
 *   POST /sandbox/create   {name, image, guest_port, netns}  -> {id, ip, host_port, breakdown}
 *   POST /sandbox/delete   {id, host_port}                   -> {success}
 *   GET  /sandbox/list                                       -> {endpoints}
 *   GET  /healthz                                            -> 200 OK
 */
package main

import (
	"cluster_manager/api/proto"
	"cluster_manager/internal/worker_node/managers"
	ctrd "cluster_manager/internal/worker_node/sandbox/containerd"
	"cluster_manager/pkg/config"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/containerd/containerd/namespaces"
	"google.golang.org/protobuf/types/known/emptypb"
)

var (
	port           = flag.Int("port", 10010, "HTTP listen port")
	containerdSock = flag.String("containerd-sock", "/run/containerd/containerd.sock", "containerd socket path")
	cniConfig      = flag.String("cni-config", "/etc/cni/net.d/10-flannel.conflist", "CNI config file path")
	cniBinDir      = flag.String("cni-bin-dir", "", "CNI plugin binary directory (e.g. /var/lib/rancher/k3s/data/cni)")
	prefetch       = flag.Bool("prefetch", false, "prefetch default images on startup")
	poolAgent      = flag.String("pool-agent", "", "node-local PhantomK8s pool agent URL (e.g. http://127.0.0.1:9091); when set, sandboxes join pre-created bundle netns and CNI is skipped")

	precreateShimGroup  = flag.String("precreate-shim-group", "", "runc-v2 shim group ID for parked precreated tasks; empty disables shim grouping")
	precreateRuntimeBin = flag.String("precreate-runtime-binary", "", "OCI runtime binary for parked precreated tasks, e.g. crun; empty uses containerd default runc")

	adoptableSandboxes = flag.Bool("adoptable-sandboxes", false, "create sandboxes in the k8s.io containerd namespace (instead of cm) with kubelet-attribution labels (io.kubernetes.pod.{uid,name,namespace}, io.cri-containerd.kind=sandbox) and CRI sandbox annotations, so materialized sandboxes sit at the coordinates the kubelet's runtime looks at. Requires images to be present/pullable in the k8s.io namespace (e.g. ctr -n k8s.io images import). See cmd/phantomk8s_worker/ADOPTION.md for what this does and does not buy.")

	brokerPoolSize = flag.Int("broker-pool", 0, "N C launch-broker lanes; when >0, /sandbox/create launches the function via a broker (fork+setns+cgroup+exec) instead of containerd, bypassing the shim ForkLock. Requires --pool-agent and --broker-exec.")
	brokerExec     = flag.String("broker-exec", "", "host path to the function executable launched by brokers (broker arm only)")
	brokerPool     *BrokerPool

	admissionGate     = flag.Bool("admission-gate", false, "enable node-local dynamic-residual admission gate (committed-memory accounting + PSI/MemAvailable pressure) before each launch")
	gateBudgetMB      = flag.Int64("gate-budget-mb", 0, "L1 phantom memory budget in MB (0 = half of MemTotal)")
	gateMemAvailMinMB = flag.Int64("gate-memavail-min-mb", 256, "L2 reject launch if MemAvailable below this MB")
	gatePSISomeMax    = flag.Float64("gate-psi-some-max", 0, "L2 reject launch if /proc/pressure/memory some avg10 above this (0 = disabled)")
	gateParkedCostMB  = flag.Int64("gate-parked-cost-mb", 2, "idle parked-slot cost in MB, subtracted from the phantom limit to get the activation delta")
	gate              *AdmissionGate
)

// admissionDeltas maps sandbox ID -> reserved committed-memory delta (KB), so
// handleDelete / launch failure can release it back to the gate budget.
var admissionDeltas sync.Map

// releaseAdmission returns a sandbox's held admission reservation to the gate.
func releaseAdmission(sandboxID string) {
	if raw, ok := admissionDeltas.LoadAndDelete(sandboxID); ok {
		if d, ok := raw.(int64); ok {
			gate.releaseIf(d)
		}
	}
}

// brokerProc tracks a broker-launched process for teardown/reclaim.
type brokerProc struct {
	pid         int
	bundleID    int
	bundleLease uint64
}

var brokerProcs sync.Map // sandbox ID ("broker-<pid>") -> brokerProc

// sandboxBundle pairs a pool bundle ID with the lease under which it was
// acquired, so reclaims are fenced (a stale reclaim after the bundle was
// re-leased is an idempotent no-op on the pool side). The lease travels with
// the sandbox record, like the containerd namespace does.
type sandboxBundle struct {
	id    int
	lease uint64
}

// sandboxBundles maps containerID -> sandboxBundle so handleDelete can
// reclaim the bundle (fenced by its lease) after the sandbox is torn down.
var sandboxBundles sync.Map

// poolClient is used for node-local pool agent acquire/reclaim calls.
var poolClient = &http.Client{Timeout: 2 * time.Second}

// poolBundle mirrors the fields of rune/domain.PoolBundle the worker needs.
type poolBundle struct {
	BundleID   int    `json:"bundle_id"`
	NetNSPath  string `json:"netns_path"`
	CgroupPath string `json:"cgroup_path"`
	IP         string `json:"ip"`
	LeaseID    uint64 `json:"lease_id"` // reclaim fence; 0 = pool without lease fencing
}

func acquireBundle(agentURL string) (*poolBundle, error) {
	resp, err := poolClient.Post(agentURL+"/acquire", "application/json", nil)
	if err != nil {
		return nil, fmt.Errorf("pool acquire: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pool acquire: status %d", resp.StatusCode)
	}
	var b poolBundle
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		return nil, fmt.Errorf("pool acquire decode: %w", err)
	}
	if b.NetNSPath == "" || b.IP == "" {
		// Bundle has no usable netns (agent likely running with --skip-netns).
		// Return it immediately so it isn't leaked.
		reclaimBundle(agentURL, b.BundleID, b.LeaseID)
		return nil, fmt.Errorf("pool acquire: bundle %d has no netns/IP (agent running with --skip-netns?)", b.BundleID)
	}
	return &b, nil
}

// reclaimClient tolerates the pool's serialized netns rebuilds (~50ms each
// under one mutex): a burst of reclaims queues linearly, so a 2s timeout
// abandoned bundles under churn (measured: ~110 leaked bundles in one
// matrix run). Reclaims are async off the hot path — a long timeout is free.
var reclaimClient = &http.Client{Timeout: 60 * time.Second}

// reclaimBundle returns a bundle to the pool. leaseID (from the /acquire
// response) fences the reclaim: the pool ignores it if the bundle has since
// been re-leased (ABA protection). 0 falls back to an unfenced reclaim for
// pools that predate lease fencing. Retries transport errors and 5xx with
// backoff; a 4xx (stale lease / unknown id) is terminal and logged.
func reclaimBundle(agentURL string, bundleID int, leaseID uint64) {
	url := fmt.Sprintf("%s/reclaim?id=%d", agentURL, bundleID)
	if leaseID != 0 {
		url = fmt.Sprintf("%s&lease_id=%d", url, leaseID)
	}
	var lastErr error
	for attempt := 1; attempt <= 4; attempt++ {
		resp, err := reclaimClient.Post(url, "application/json", nil)
		if err == nil {
			code := resp.StatusCode
			resp.Body.Close()
			if code < 300 {
				return
			}
			if code < 500 {
				log.Printf("[worker] bundle %d reclaim rejected (status %d, lease %d) — not retrying", bundleID, code, leaseID)
				return
			}
			lastErr = fmt.Errorf("status %d", code)
		} else {
			lastErr = err
		}
		time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
	}
	log.Printf("[worker] bundle %d reclaim FAILED after retries: %v — janitor will retry", bundleID, lastErr)
	failedReclaims.Store(bundleID, sandboxBundle{id: bundleID, lease: leaseID})
}

// failedReclaims holds bundles whose reclaim exhausted retries; the janitor
// retries them until the pool accepts (or fences) them.
var failedReclaims sync.Map

// CreateRequest is the JSON body for POST /sandbox/create.
type CreateRequest struct {
	Name        string `json:"name"`
	Image       string `json:"image"`
	GuestPort   int    `json:"guest_port"`
	NetNS       string `json:"netns,omitempty"`        // optional: join this pre-created netns (caller-managed)
	IP          string `json:"ip,omitempty"`           // required with netns: the netns's pre-assigned pod IP
	MemoryLimit string `json:"memory_limit,omitempty"` // phantom memory.max (K8s quantity, e.g. "256Mi") for the admission gate + pod cgroup
	PodUID      string `json:"pod_uid,omitempty"`      // API-server pod UID; with --cgroup-driver, the parked PID migrates into kubepods/pod<uid> before start
	CPULimit    string `json:"cpu_limit,omitempty"`    // phantom cpu limit (e.g. "500m") → cpu.max on the adopted pod cgroup
	CPURequest  string `json:"cpu_request,omitempty"`  // phantom cpu request → cpu.weight on the adopted pod cgroup

	// Pod identity for --adoptable-sandboxes: with PodUID they become the
	// io.kubernetes.pod.{uid,name,namespace} labels on the sandbox container.
	// PodName falls back to Name; PodNamespace falls back to "default".
	PodName      string `json:"pod_name,omitempty"`
	PodNamespace string `json:"pod_namespace,omitempty"`
}

// CreateResponse is returned from POST /sandbox/create.
type CreateResponse struct {
	Success   bool              `json:"success"`
	ID        string            `json:"id"`
	IP        string            `json:"ip"`
	HostPort  int               `json:"host_port"`
	BundleID  int               `json:"bundle_id,omitempty"` // pool bundle backing this sandbox (bundle path only)
	Path      string            `json:"path,omitempty"`      // "bundle" (netns join, no CNI) or "cni"
	Breakdown map[string]string `json:"breakdown,omitempty"`
	Error     string            `json:"error,omitempty"`
}

// DeleteRequest is the JSON body for POST /sandbox/delete.
type DeleteRequest struct {
	ID       string `json:"id"`
	HostPort int    `json:"host_port,omitempty"`
}

// PrecreateRequest is the JSON body for POST /sandbox/precreate.
// For each slot: acquire a pool bundle, create the container (snapshot +
// spec joining the bundle netns), and create the task (shim + runc create),
// parking it before execve. A later /sandbox/create with the same image pops
// a parked slot and pays only task.Start.
type PrecreateRequest struct {
	Image string `json:"image"`
	Count int    `json:"count"`
	// Stage selects how much of creation to prepay: "task" (default; full
	// parked — per-slot runc shim + runc-init held), "container" (Tier-2;
	// NewContainer + snapshot only, no processes held; claim pays
	// NewTask+Start), or "native" (parked via the node-singleton rune shim —
	// ~0.5MB C fork-server child per slot, zero per-slot shims).
	Stage string `json:"stage,omitempty"`
}

// precreatedEntry pairs a parked sandbox with the pool bundle backing it.
type precreatedEntry struct {
	pre         *ctrd.PrecreatedSandbox
	bundleID    int
	bundleLease uint64 // lease under which the bundle was acquired (reclaim fence)
	bundleOwned bool
}

var (
	precreatedMu   sync.Mutex
	precreatedPool = map[string][]*precreatedEntry{} // image -> FIFO of parked slots
)

func popPrecreated(image string) *precreatedEntry {
	precreatedMu.Lock()
	defer precreatedMu.Unlock()
	slots := precreatedPool[image]
	if len(slots) == 0 {
		return nil
	}
	e := slots[0]
	precreatedPool[image] = slots[1:]
	return e
}

func pushPrecreated(image string, e *precreatedEntry) {
	precreatedMu.Lock()
	defer precreatedMu.Unlock()
	precreatedPool[image] = append(precreatedPool[image], e)
}

func drainPrecreated() map[string][]*precreatedEntry {
	precreatedMu.Lock()
	defer precreatedMu.Unlock()
	out := precreatedPool
	precreatedPool = map[string][]*precreatedEntry{}
	return out
}

func main() {
	flag.Parse()

	if os.Getuid() != 0 {
		log.Fatal("phantomk8s_worker must be run as root")
	}

	cfg := config.WorkerNodeConfig{
		CRIType:             "containerd",
		CRIPath:             *containerdSock,
		CNIConfigPath:       *cniConfig,
		CNIBinDir:           *cniBinDir,
		PrefetchImage:       *prefetch,
		PrecreateShimGroup:  *precreateShimGroup,
		PrecreateRuntimeBin: *precreateRuntimeBin,
		SkipIptables:        true, // gateway proxies to container IPs directly
		AdoptableSandboxes:  *adoptableSandboxes,
	}

	sandboxManager := managers.NewSandboxManager(fmt.Sprintf("phantomk8s-%d", os.Getpid()))

	// Pass nil for cpApi — we don't use Dirigent's control plane.
	runtime := ctrd.NewContainerdRuntime(nil, cfg, sandboxManager)

	// Optional node-local dynamic-residual admission gate.
	if *admissionGate {
		gate = NewAdmissionGate(GateConfig{
			BudgetMB:      *gateBudgetMB,
			MemAvailMinMB: *gateMemAvailMinMB,
			PSISomeMax:    *gatePSISomeMax,
			ParkedCostMB:  *gateParkedCostMB,
		})
		c, b := gate.Stats()
		log.Printf("[worker] admission gate: budget=%dMB (committed=%dMB) memAvailMin=%dMB psiSomeMax=%.1f parkedCost=%dMB",
			b, c, *gateMemAvailMinMB, *gatePSISomeMax, *gateParkedCostMB)
	}

	// Optional migrate-then-start pod-cgroup adoption.
	cgroupDriver = resolveCgroupDriver()
	if cgroupDriver != "" {
		log.Printf("[worker] pod-cgroup adoption: driver=%s root=%s (parked PID migrates into kubepods/pod<uid> before task start)", cgroupDriver, *cgroupRoot)
	}

	// Optional C launch-broker pool (anti-ForkLock data plane).
	if *brokerPoolSize > 0 {
		if *brokerExec == "" {
			log.Fatal("--broker-pool requires --broker-exec (host path to function binary)")
		}
		bp, err := NewBrokerPool(*brokerPoolSize)
		if err != nil {
			log.Fatalf("broker pool: %v", err)
		}
		brokerPool = bp
		log.Printf("[worker] broker pool: %d lanes, exec=%q", bp.Size(), *brokerExec)
	}

	// The containerd namespace sandboxes are created in. "cm" by default;
	// "k8s.io" in adoptable mode (deletes always follow the namespace recorded
	// on the sandbox, so flipping the flag across restarts cannot orphan).
	workerNS := ctrd.NamespaceCM
	if *adoptableSandboxes {
		workerNS = ctrd.NamespaceK8s
		log.Printf("[worker] adoptable sandboxes: creating in containerd namespace %q with kubelet-attribution labels (images must be importable/pullable in this namespace)", workerNS)
	}

	// Pre-pull images if requested (same namespace as the runtime).
	if *prefetch {
		ctx := namespaces.WithNamespace(context.Background(), workerNS)
		log.Println("[worker] prefetching images...")
		ctrd.FetchImage(ctx, runtime.ContainerdClient, "docker.io/cvetkovic/dirigent_trace_function:latest")
	}

	mux := http.NewServeMux()
	startJanitor(runtime)
	mux.HandleFunc("/sandbox/create", handleCreate(runtime))
	mux.HandleFunc("/sandbox/delete", handleDelete(runtime))
	mux.HandleFunc("/sandbox/list", handleList(runtime))
	mux.HandleFunc("/sandbox/precreate", handlePrecreate(runtime))
	mux.HandleFunc("/sandbox/parked", handleParked)
	mux.HandleFunc("/sandbox/drain", handleDrain(runtime))
	mux.HandleFunc("/cgroup/prepare", handleCgroupPrepare)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	// /time returns this node's clock in unix microseconds. Benchmarks use it
	// to estimate per-node clock offset (NTP midpoint method) so cross-node
	// timestamps (e.g. containerd_start_unix_us, RunPodSandbox log lines) can
	// be compared against gateway-side clocks.
	mux.HandleFunc("/time", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"unix_us":%d}`, time.Now().UnixMicro())
	})

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("[worker] listening on %s (containerd=%s, cni=%s, precreate_group=%q, precreate_runtime=%q)", addr, *containerdSock, *cniConfig, *precreateShimGroup, *precreateRuntimeBin)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func handleCreate(runtime *ctrd.ContainerdRuntime) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Timer starts at handler entry — everything before the containerd
		// call (decode, validation) counts as worker pre-sandbox time.
		tReceived := time.Now()
		receivedUnixUs := tReceived.UnixMicro()

		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}

		var req CreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Image == "" {
			jsonError(w, "image required", http.StatusBadRequest)
			return
		}
		if req.GuestPort == 0 {
			req.GuestPort = 8080
		}

		// --- Dynamic-residual admission gate ---
		// Before acquiring any resource, run the node-local residual: L1 atomic
		// committed-memory accounting + L2 live PSI/MemAvailable drift. A reject
		// here means "node full / under pressure" — the gateway reroutes or
		// cold-starts. Reserved delta is released on launch failure or delete.
		var admDelta int64
		if gate != nil {
			d, ok, reason := gate.Admit(parseQuantityKB(req.MemoryLimit))
			if !ok {
				jsonResp(w, http.StatusServiceUnavailable, CreateResponse{
					Success: false, Path: "rejected", Error: "admission: " + reason,
				})
				return
			}
			admDelta = d
		}

		serviceInfo := &proto.ServiceInfo{
			Name:  req.Name,
			Image: req.Image,
			PortForwarding: &proto.PortMapping{
				GuestPort: int32(req.GuestPort),
			},
		}

		// Pod identity for adoptable sandboxes: the kubelet-attribution
		// coordinates stamped onto the container. Only meaningful with
		// --adoptable-sandboxes and a pod UID (phantoms are real API pods,
		// so the gateway always has one).
		var identity *ctrd.PodIdentity
		if *adoptableSandboxes && req.PodUID != "" {
			podName := req.PodName
			if podName == "" {
				podName = req.Name // gateway sends the phantom pod name as Name
			}
			podNamespace := req.PodNamespace
			if podNamespace == "" {
				podNamespace = "default"
			}
			if req.PodName == "" || req.PodNamespace == "" {
				log.Printf("[worker] adoptable create for pod %s: pod_name/pod_namespace not supplied, using fallbacks %q/%q", req.PodUID, podName, podNamespace)
			}
			identity = &ctrd.PodIdentity{UID: req.PodUID, Name: podName, Namespace: podNamespace}
		}

		// --- Broker arm ---
		// When a broker pool is configured, the function is launched by a C
		// broker (fork+setns+cgroup+exec) directly into a pool bundle, bypassing
		// containerd and its shim ForkLock entirely. Self-contained early return:
		// this path yields a process, not a containerd sandbox.
		if brokerPool != nil && *brokerExec != "" {
			handleBrokerCreate(w, tReceived, receivedUnixUs, admDelta)
			return
		}

		// Resolve the launch path: precreated parked task > caller-supplied
		// netns > node-local pool bundle (--pool-agent) > vanilla CNI.
		path := "cni"
		netnsPath := req.NetNS
		bundleIP := req.IP
		bundleID := 0
		bundleLease := uint64(0)
		bundleOwned := false
		acquireMs := 0.0
		var precreated *precreatedEntry
		if e := popPrecreated(req.Image); e != nil {
			path = "precreated"
			precreated = e
			bundleID = e.bundleID
			bundleLease = e.bundleLease
			bundleOwned = e.bundleOwned
		} else if netnsPath != "" && bundleIP != "" {
			path = "bundle"
		} else if *poolAgent != "" {
			tAcquire := time.Now()
			b, acqErr := acquireBundle(*poolAgent)
			acquireMs = float64(time.Since(tAcquire).Nanoseconds()) / 1e6
			if acqErr != nil {
				// Fall back to CNI so the worker stays usable when the pool
				// is exhausted or misconfigured — but make it loud.
				log.Printf("[worker] bundle acquire failed, falling back to CNI: %v", acqErr)
			} else {
				path = "bundle"
				netnsPath = b.NetNSPath
				bundleIP = b.IP
				bundleID = b.BundleID
				bundleLease = b.LeaseID
				bundleOwned = true
			}
		}

		// tContainerdStart marks "RunPodSandbox() begins" — the boundary
		// between orchestration/routing latency and containerd work.
		tContainerdStart := time.Now()
		var result *proto.SandboxCreationStatus
		var err error
		podCG := ""
		adoptMs := 0.0
		switch path {
		case "precreated":
			// Migrate-then-start: move the parked pre-execve PID into the
			// kubelet-shaped kubepods/pod<uid> cgroup (full Guaranteed limits)
			// BEFORE start, so the function is charged there from byte 0 and
			// the kubelet's EnsureExists adopts the cgroup as a no-op.
			// Tier-2 (container-only) entries have no parked PID yet (Task is
			// created at claim inside StartPrecreatedSandbox) — adoption there
			// is a TODO; skip rather than nil-deref.
			if cgroupDriver != "" && req.PodUID != "" && precreated.pre.Task != nil {
				tAdopt := time.Now()
				cg, aerr := adoptPodCgroup(podCgroupSpec{
					PodUID:          req.PodUID,
					MemoryLimitKB:   parseQuantityKB(req.MemoryLimit),
					CPULimitMilli:   parseCPUMilli(req.CPULimit),
					CPURequestMilli: parseCPUMilli(req.CPURequest),
				}, int(precreated.pre.Task.Pid()))
				adoptMs = float64(time.Since(tAdopt).Nanoseconds()) / 1e6
				if aerr != nil {
					// Fail open: serve from the bundle cgroup rather than 5xx.
					// The admission gate still bounds node memory; only the
					// kubelet-visible charging is lost for this invocation.
					log.Printf("[worker] pod-cgroup adoption failed (pod %s): %v — starting in bundle cgroup", req.PodUID, aerr)
				} else {
					podCG = cg
				}
			}
			result, err = runtime.StartPrecreatedSandbox(r.Context(), serviceInfo, precreated.pre, identity)
			if err != nil || result == nil || !result.Success {
				// Parked task failed to start — tear it down and free the bundle
				// (and the adopted pod cgroup, once the killed PID drains out).
				go func(e *precreatedEntry, cg string) {
					_ = runtime.DiscardPrecreatedSandbox(context.Background(), e.pre)
					if *poolAgent != "" && e.bundleOwned {
						reclaimBundle(*poolAgent, e.bundleID, e.bundleLease)
					}
					if cg != "" {
						removePodCgroupPath(cg)
					}
				}(precreated, podCG)
			}
		case "bundle":
			result, err = runtime.CreateSandboxInBundle(r.Context(), serviceInfo, netnsPath, bundleIP, identity)
			if (err != nil || result == nil || !result.Success) && bundleOwned {
				// Launch failed — return the bundle so it isn't leaked.
				go reclaimBundle(*poolAgent, bundleID, bundleLease)
			}
		default:
			result, err = runtime.CreateSandboxWithIdentity(r.Context(), serviceInfo, identity)
		}
		tContainerdDone := time.Now()
		totalMs := float64(tContainerdDone.Sub(tReceived).Nanoseconds()) / 1e6
		containerdMs := float64(tContainerdDone.Sub(tContainerdStart).Nanoseconds()) / 1e6
		queueMs := float64(tContainerdStart.Sub(tReceived).Nanoseconds()) / 1e6

		if err != nil || !result.Success {
			// Launch failed — give the reserved admission budget back.
			gate.releaseIf(admDelta)
			errMsg := "sandbox creation failed"
			if err != nil {
				errMsg = err.Error()
			}
			jsonResp(w, http.StatusInternalServerError, CreateResponse{
				Success: false,
				Error:   errMsg,
			})
			return
		}

		breakdown := make(map[string]string)
		if b := result.LatencyBreakdown; b != nil {
			breakdown["total_ms"] = fmt.Sprintf("%.1f", totalMs)
			breakdown["image_fetch_ms"] = fmt.Sprintf("%.1f", durationMs(b.ImageFetch))
			breakdown["sandbox_create_ms"] = fmt.Sprintf("%.1f", durationMs(b.SandboxCreate))
			breakdown["network_setup_ms"] = fmt.Sprintf("%.1f", durationMs(b.NetworkSetup))
			breakdown["sandbox_start_ms"] = fmt.Sprintf("%.1f", durationMs(b.SandboxStart))
			breakdown["iptables_ms"] = fmt.Sprintf("%.1f", durationMs(b.Iptables))
		}
		if timings, ok := runtime.ConsumeStartTimings(result.ID); ok {
			breakdown["new_task_ms"] = fmt.Sprintf("%.1f", durationToMs(timings.NewTask))
			breakdown["wait_ms"] = fmt.Sprintf("%.1f", durationToMs(timings.Wait))
			breakdown["task_start_ms"] = fmt.Sprintf("%.1f", durationToMs(timings.TaskStart))
		}
		breakdown["worker_queue_ms"] = fmt.Sprintf("%.3f", queueMs)
		breakdown["containerd_ms"] = fmt.Sprintf("%.1f", containerdMs)
		breakdown["received_unix_us"] = fmt.Sprintf("%d", receivedUnixUs)
		breakdown["path"] = path
		if *adoptableSandboxes {
			breakdown["ctrd_ns"] = ctrd.NamespaceK8s
			if identity != nil {
				breakdown["adoptable_pod_uid"] = identity.UID
			}
		}
		if path == "bundle" {
			breakdown["bundle_acquire_ms"] = fmt.Sprintf("%.3f", acquireMs)
			breakdown["bundle_id"] = fmt.Sprintf("%d", bundleID)
		}
		if path == "precreated" {
			breakdown["bundle_id"] = fmt.Sprintf("%d", bundleID)
			// Fill-time costs, for reference (NOT part of this request's latency).
			breakdown["precreate_fill_create_ms"] = fmt.Sprintf("%.1f", precreated.pre.CreateMs)
			breakdown["precreate_fill_new_task_ms"] = fmt.Sprintf("%.1f", precreated.pre.NewTaskMs)
			if podCG != "" {
				breakdown["pod_cgroup"] = podCG
				breakdown["cgroup_adopt_ms"] = fmt.Sprintf("%.3f", adoptMs)
			}
		}
		// "RunPodSandbox begins" marker + worker handler wall time, for
		// pre-sandbox pipeline measurement (skew-free hop estimation).
		breakdown["containerd_start_unix_us"] = fmt.Sprintf("%d", tContainerdStart.UnixMicro())
		breakdown["worker_wall_ms"] = fmt.Sprintf("%.3f", float64(tContainerdDone.Sub(tReceived).Nanoseconds())/1e6)

		// Extract the container IP from sandbox manager metadata.
		ip := ""
		hostPort := 0
		if result.PortMappings != nil {
			hostPort = int(result.PortMappings.HostPort)
		}
		if meta, ok := runtime.SandboxManager.Metadata.Get(result.ID); ok {
			ip = meta.IP
		}

		// Remember which bundle (and lease) backs this sandbox so delete can
		// reclaim it with the correct fence.
		if (path == "bundle" || path == "precreated") && bundleOwned {
			sandboxBundles.Store(result.ID, sandboxBundle{id: bundleID, lease: bundleLease})
		}
		// Hold the admission reservation until this sandbox is deleted.
		if gate != nil && admDelta > 0 {
			admissionDeltas.Store(result.ID, admDelta)
		}
		// Remember the adopted pod cgroup so delete can remove it.
		if podCG != "" {
			podCgroups.Store(result.ID, podCG)
		}

		jsonResp(w, http.StatusOK, CreateResponse{
			Success:   true,
			ID:        result.ID,
			IP:        ip,
			HostPort:  hostPort,
			BundleID:  bundleID,
			Path:      path,
			Breakdown: breakdown,
		})
	}
}

// handleBrokerCreate launches the function via a C broker lane into a freshly
// acquired pool bundle (netns + cgroup), bypassing containerd. Tracks the pid
// for teardown and returns the bundle IP. The in-bundle socket activator (pool
// agent) makes the IP reachable the instant this returns; the broker-launched
// process binds the app port a moment later.
func handleBrokerCreate(w http.ResponseWriter, tReceived time.Time, receivedUnixUs int64, admDelta int64) {
	if *poolAgent == "" {
		gate.releaseIf(admDelta)
		jsonError(w, "broker arm requires --pool-agent", http.StatusServiceUnavailable)
		return
	}

	tAcquire := time.Now()
	b, err := acquireBundle(*poolAgent)
	acquireMs := float64(time.Since(tAcquire).Nanoseconds()) / 1e6
	if err != nil {
		gate.releaseIf(admDelta)
		jsonError(w, "broker bundle acquire: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	cgroupProcs := "-"
	if b.CgroupPath != "" {
		cgroupProcs = b.CgroupPath + "/cgroup.procs"
	}
	fields := strings.Fields(*brokerExec)
	exe, args := fields[0], fields[1:]

	tLaunch := time.Now()
	pid, forkUs, lerr := brokerPool.Launch(b.BundleID, b.NetNSPath, cgroupProcs, exe, args)
	launchMs := float64(time.Since(tLaunch).Nanoseconds()) / 1e6
	if lerr != nil {
		gate.releaseIf(admDelta)
		reclaimBundle(*poolAgent, b.BundleID, b.LeaseID)
		jsonError(w, "broker launch: "+lerr.Error(), http.StatusInternalServerError)
		return
	}

	sandboxID := fmt.Sprintf("broker-%d", pid)
	brokerProcs.Store(sandboxID, brokerProc{pid: pid, bundleID: b.BundleID, bundleLease: b.LeaseID})
	if gate != nil && admDelta > 0 {
		admissionDeltas.Store(sandboxID, admDelta)
	}

	tDone := time.Now()
	breakdown := map[string]string{
		"path":                     "broker",
		"bundle_id":                fmt.Sprintf("%d", b.BundleID),
		"bundle_acquire_ms":        fmt.Sprintf("%.3f", acquireMs),
		"broker_fork_us":           fmt.Sprintf("%.1f", forkUs),
		"worker_queue_ms":          fmt.Sprintf("%.3f", float64(tAcquire.Sub(tReceived).Nanoseconds())/1e6),
		"containerd_ms":            fmt.Sprintf("%.1f", launchMs), // launch wall, for table parity
		"total_ms":                 fmt.Sprintf("%.1f", float64(tDone.Sub(tReceived).Nanoseconds())/1e6),
		"received_unix_us":         fmt.Sprintf("%d", receivedUnixUs),
		"containerd_start_unix_us": fmt.Sprintf("%d", tLaunch.UnixMicro()),
		"worker_wall_ms":           fmt.Sprintf("%.3f", float64(tDone.Sub(tReceived).Nanoseconds())/1e6),
	}

	jsonResp(w, http.StatusOK, CreateResponse{
		Success:   true,
		ID:        sandboxID,
		IP:        b.IP,
		BundleID:  b.BundleID,
		Path:      "broker",
		Breakdown: breakdown,
	})
}

// handlePrecreate fills the parked-task pool for an image: per slot, acquire a
// pool bundle, create container+task joined to the bundle netns, park before
// execve. Requires --pool-agent. Sequential by design — fill is off-path.
func handlePrecreate(runtime *ctrd.ContainerdRuntime) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		if *poolAgent == "" {
			jsonError(w, "precreate requires --pool-agent", http.StatusServiceUnavailable)
			return
		}

		var req PrecreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Image == "" {
			jsonError(w, "image required", http.StatusBadRequest)
			return
		}
		if req.Count <= 0 {
			req.Count = 1
		}

		switch req.Stage {
		case "", "task", "container", "native":
		default:
			jsonError(w, "stage must be task, container, or native", http.StatusBadRequest)
			return
		}

		t0 := time.Now()
		created := 0
		var firstErr string
		for i := 0; i < req.Count; i++ {
			b, err := acquireBundle(*poolAgent)
			if err != nil {
				if firstErr == "" {
					firstErr = err.Error()
				}
				break
			}
			pre, err := runtime.PrecreateSandboxInBundle(r.Context(), req.Image, b.NetNSPath, b.IP, req.Stage)
			if err != nil {
				reclaimBundle(*poolAgent, b.BundleID, b.LeaseID)
				if firstErr == "" {
					firstErr = err.Error()
				}
				break
			}
			pushPrecreated(req.Image, &precreatedEntry{pre: pre, bundleID: b.BundleID, bundleLease: b.LeaseID, bundleOwned: true})
			created++
		}
		fillMs := float64(time.Since(t0).Nanoseconds()) / 1e6

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"requested": req.Count,
			"created":   created,
			"fill_ms":   fillMs,
			"error":     firstErr,
		})
	}
}

// startJanitor sweeps every 30s: (1) re-attempts reclaims that exhausted
// their inline retries; (2) reclaims bundles whose sandbox has vanished
// without its delete consuming the mapping (two consecutive absent sweeps
// before acting, to avoid racing in-flight transitions). Catch-all for the
// leak class where Stop succeeds but the reclaim never lands.
func startJanitor(runtime *ctrd.ContainerdRuntime) {
	go func() {
		suspect := map[string]bool{}
		for {
			time.Sleep(30 * time.Second)
			if *poolAgent == "" {
				continue
			}
			failedReclaims.Range(func(k, v interface{}) bool {
				failedReclaims.Delete(k)
				b := v.(sandboxBundle)
				go reclaimBundle(*poolAgent, b.id, b.lease)
				return true
			})
			list, err := runtime.ListEndpoints(context.Background(), &emptypb.Empty{})
			if err != nil {
				continue
			}
			live := map[string]bool{}
			for _, e := range list.Endpoint {
				live[e.SandboxID] = true
			}
			next := map[string]bool{}
			sandboxBundles.Range(func(k, v interface{}) bool {
				id := k.(string)
				if live[id] {
					return true
				}
				if !suspect[id] {
					next[id] = true
					return true
				}
				if raw, ok := sandboxBundles.LoadAndDelete(id); ok {
					b := raw.(sandboxBundle)
					log.Printf("[worker] janitor: sandbox %s gone without delete — reclaiming bundle %d", id, b.id)
					go reclaimBundle(*poolAgent, b.id, b.lease)
				}
				return true
			})
			suspect = next
		}
	}()
}

// handleParked reports the current parked (precreated) slot depth per image,
// so a replay re-armer can observe and sustain park targets.
func handleParked(w http.ResponseWriter, r *http.Request) {
	precreatedMu.Lock()
	counts := make(map[string]int, len(precreatedPool))
	for img, slots := range precreatedPool {
		counts[img] = len(slots)
	}
	precreatedMu.Unlock()
	jsonResp(w, http.StatusOK, counts)
}

// handleDrain tears down all parked precreated sandboxes and reclaims their
// bundles. Benchmark hygiene between runs.
func handleDrain(runtime *ctrd.ContainerdRuntime) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}

		drained := 0
		for _, slots := range drainPrecreated() {
			for _, e := range slots {
				if err := runtime.DiscardPrecreatedSandbox(r.Context(), e.pre); err != nil {
					log.Printf("[worker] drain discard: %v", err)
				}
				if *poolAgent != "" && e.bundleOwned {
					reclaimBundle(*poolAgent, e.bundleID, e.bundleLease)
				}
				drained++
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"drained": drained})
	}
}

// handleCgroupPrepare pre-creates the kubelet-shaped pod cgroup (full limits,
// no PID) at REGISTRATION time, so claim-time adoption is a bare cgroup.procs
// write with no dbus/PID-1 serialization on the hot path.
func handleCgroupPrepare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		PodUID      string `json:"pod_uid"`
		MemoryLimit string `json:"memory_limit,omitempty"`
		CPULimit    string `json:"cpu_limit,omitempty"`
		CPURequest  string `json:"cpu_request,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PodUID == "" {
		jsonError(w, "pod_uid required", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if cgroupDriver == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{"prepared": false, "reason": "cgroup adoption disabled"})
		return
	}
	dir, err := preparePodCgroup(podCgroupSpec{
		PodUID:          req.PodUID,
		MemoryLimitKB:   parseQuantityKB(req.MemoryLimit),
		CPULimitMilli:   parseCPUMilli(req.CPULimit),
		CPURequestMilli: parseCPUMilli(req.CPURequest),
	})
	if err != nil {
		jsonError(w, "prepare: "+err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"prepared": true, "path": dir})
}

func handleDelete(runtime *ctrd.ContainerdRuntime) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}

		var req DeleteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Release the admission reservation this sandbox held (any path).
		releaseAdmission(req.ID)

		// Broker-launched process: SIGKILL via its lane, reclaim bundle, done
		// (it is not a containerd sandbox).
		if raw, ok := brokerProcs.LoadAndDelete(req.ID); ok {
			bp := raw.(brokerProc)
			if brokerPool != nil {
				_ = brokerPool.Kill(bp.bundleID, bp.pid, 9)
			}
			if *poolAgent != "" {
				go reclaimBundle(*poolAgent, bp.bundleID, bp.bundleLease)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
			return
		}

		result, err := runtime.DeleteSandbox(r.Context(), &proto.SandboxID{
			ID:       req.ID,
			HostPort: int32(req.HostPort),
		})
		// Reclaim the backing bundle even when DeleteSandbox errors: a
		// partially-torn-down sandbox (removed from metadata but erroring on
		// some step, or a retry hitting "not found") must not strand its
		// bundle — that was a measured leak (~110 bundles/run). The caller
		// only deletes finished workloads, so the bundle is dead either way;
		// the pool's rebuild refreshes the netns regardless of what the
		// half-deleted sandbox left behind.
		if raw, ok := sandboxBundles.LoadAndDelete(req.ID); ok && *poolAgent != "" {
			if b, ok := raw.(sandboxBundle); ok {
				if err != nil {
					log.Printf("[worker] delete %s errored (%v) — reclaiming bundle %d anyway", req.ID, err, b.id)
				}
				go reclaimBundle(*poolAgent, b.id, b.lease)
			}
		}
		if err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Remove the adopted pod cgroup (retries until the killed PIDs drain).
		go releasePodCgroup(req.ID)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": result.Success,
		})
	}
}

func handleList(runtime *ctrd.ContainerdRuntime) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := runtime.ListEndpoints(r.Context(), &emptypb.Empty{})
		if err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}

		type ep struct {
			ID      string `json:"id"`
			IP      string `json:"ip"`
			Service string `json:"service"`
			Port    int    `json:"host_port"`
		}
		out := make([]ep, 0, len(list.Endpoint))
		for _, e := range list.Endpoint {
			out = append(out, ep{
				ID:      e.SandboxID,
				IP:      e.URL,
				Service: e.ServiceName,
				Port:    int(e.HostPort),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	}
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func jsonResp(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func durationMs(d interface{ AsDuration() time.Duration }) float64 {
	if d == nil {
		return 0
	}
	return durationToMs(d.AsDuration())
}

func durationToMs(d time.Duration) float64 {
	return float64(d.Nanoseconds()) / 1e6
}
