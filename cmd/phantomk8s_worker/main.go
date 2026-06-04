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
	"time"

	"github.com/containerd/containerd/namespaces"
	"google.golang.org/protobuf/types/known/emptypb"
)

var (
	port          = flag.Int("port", 10010, "HTTP listen port")
	containerdSock = flag.String("containerd-sock", "/run/containerd/containerd.sock", "containerd socket path")
	cniConfig     = flag.String("cni-config", "/etc/cni/net.d/10-flannel.conflist", "CNI config file path")
	prefetch      = flag.Bool("prefetch", false, "prefetch default images on startup")
)

// CreateRequest is the JSON body for POST /sandbox/create.
type CreateRequest struct {
	Name      string `json:"name"`
	Image     string `json:"image"`
	GuestPort int    `json:"guest_port"`
	NetNS     string `json:"netns,omitempty"` // optional: use pre-assigned pool netns
}

// CreateResponse is returned from POST /sandbox/create.
type CreateResponse struct {
	Success   bool              `json:"success"`
	ID        string            `json:"id"`
	IP        string            `json:"ip"`
	HostPort  int               `json:"host_port"`
	Breakdown map[string]string `json:"breakdown,omitempty"`
	Error     string            `json:"error,omitempty"`
}

// DeleteRequest is the JSON body for POST /sandbox/delete.
type DeleteRequest struct {
	ID       string `json:"id"`
	HostPort int    `json:"host_port,omitempty"`
}

func main() {
	flag.Parse()

	if os.Getuid() != 0 {
		log.Fatal("phantomk8s_worker must be run as root")
	}

	cfg := config.WorkerNodeConfig{
		CRIType:       "containerd",
		CRIPath:       *containerdSock,
		CNIConfigPath: *cniConfig,
		PrefetchImage: *prefetch,
	}

	sandboxManager := managers.NewSandboxManager(fmt.Sprintf("phantomk8s-%d", os.Getpid()))

	// Pass nil for cpApi — we don't use Dirigent's control plane.
	runtime := ctrd.NewContainerdRuntime(nil, cfg, sandboxManager)

	// Pre-pull images if requested.
	if *prefetch {
		ctx := namespaces.WithNamespace(context.Background(), "phantomk8s")
		log.Println("[worker] prefetching images...")
		ctrd.FetchImage(ctx, runtime.ContainerdClient, "docker.io/cvetkovic/dirigent_trace_function:latest")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/sandbox/create", handleCreate(runtime))
	mux.HandleFunc("/sandbox/delete", handleDelete(runtime))
	mux.HandleFunc("/sandbox/list", handleList(runtime))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("[worker] listening on %s (containerd=%s, cni=%s)", addr, *containerdSock, *cniConfig)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func handleCreate(runtime *ctrd.ContainerdRuntime) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

		serviceInfo := &proto.ServiceInfo{
			Name:  req.Name,
			Image: req.Image,
			PortForwarding: &proto.PortMapping{
				GuestPort: int32(req.GuestPort),
			},
		}

		t0 := time.Now()
		result, err := runtime.CreateSandbox(r.Context(), serviceInfo)
		totalMs := float64(time.Since(t0).Nanoseconds()) / 1e6

		if err != nil || !result.Success {
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

		// Extract the container IP from sandbox manager metadata.
		ip := ""
		hostPort := 0
		if result.PortMappings != nil {
			hostPort = int(result.PortMappings.HostPort)
		}
		if meta, ok := runtime.SandboxManager.Metadata.Get(result.ID); ok {
			ip = meta.IP
		}

		jsonResp(w, http.StatusOK, CreateResponse{
			Success:   true,
			ID:        result.ID,
			IP:        ip,
			HostPort:  hostPort,
			Breakdown: breakdown,
		})
	}
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

		result, err := runtime.DeleteSandbox(r.Context(), &proto.SandboxID{
			ID:       req.ID,
			HostPort: int32(req.HostPort),
		})
		if err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}

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
	return float64(d.AsDuration().Nanoseconds()) / 1e6
}
