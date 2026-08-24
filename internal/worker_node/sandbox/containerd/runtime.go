/*
 * MIT License
 *
 * Copyright (c) 2024 EASL
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package containerd

import (
	"cluster_manager/api/proto"
	"cluster_manager/internal/worker_node/managers"
	"cluster_manager/internal/worker_node/sandbox"
	"cluster_manager/pkg/config"
	"context"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/go-cni"
	"github.com/coreos/go-iptables/iptables"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"sync"
	"time"
)

type ContainerdRuntime struct {
	sandbox.RuntimeInterface

	cpApi proto.CpiInterfaceClient

	ContainerdClient *containerd.Client
	CNIClient        cni.CNI
	IPT              *iptables.IPTables

	ImageManager   *ImageManager
	SandboxManager *managers.SandboxManager
	ProcessMonitor *managers.ProcessMonitor
	startTimings   sync.Map // sandbox ID -> StartTimings

	precreateCreateOptions ContainerCreateOptions
	skipIptables           bool // true for PhantomK8s (direct container-IP proxy); false restores upstream hostPort DNAT

	// ctrdNamespace is the containerd namespace NEW sandboxes are created in
	// ("cm" by default; "k8s.io" when adoptable is set). Deletion never uses
	// this field — it uses the namespace recorded on the sandbox itself
	// (ContainerdMetadata.CtrdNamespace / PrecreatedSandbox.Namespace), so a
	// worker restarted with the flag flipped still deletes old sandboxes from
	// the namespace they were created in.
	ctrdNamespace string
	// adoptable stamps new sandboxes with the CRI sandbox coordinate contract
	// (kind=sandbox label, kubelet pod labels, io.kubernetes.cri.* annotations).
	adoptable bool
}

type ContainerdMetadata struct {
	managers.RuntimeMetadata

	Task      containerd.Task
	Container containerd.Container

	// CtrdNamespace is the containerd namespace this sandbox was created in.
	// Empty (records predating this field) means NamespaceCM.
	CtrdNamespace string
}

func NewContainerdRuntime(cpApi proto.CpiInterfaceClient, config config.WorkerNodeConfig, sandboxManager *managers.SandboxManager) *ContainerdRuntime {
	containerdClient := GetContainerdClient(config.CRIPath)

	imageManager := NewContainerdImageManager()
	cniClient := GetCNIClient(config.CNIConfigPath, config.CNIBinDir)
	ipt, err := managers.NewIptablesUtil()

	if err != nil {
		logrus.Fatal("Error while accessing iptables - ", err)
	}

	if config.PrefetchImage {
		ctx := namespaces.WithNamespace(context.Background(), "default")

		_, err, _ = imageManager.GetImage(ctx, containerdClient, "docker.io/cvetkovic/dirigent_empty_function:latest")
		if err != nil {
			logrus.Errorf("Failed to prefetch the image")
		}

		_, err, _ = imageManager.GetImage(ctx, containerdClient, "docker.io/cvetkovic/dirigent_trace_function:latest")
		if err != nil {
			logrus.Errorf("Failed to prefetch the image")
		}
	}

	ctrdNamespace := NamespaceCM
	if config.AdoptableSandboxes {
		ctrdNamespace = NamespaceK8s
	}

	return &ContainerdRuntime{
		cpApi: cpApi,

		ContainerdClient: containerdClient,
		CNIClient:        cniClient,
		IPT:              ipt,

		ImageManager:   imageManager,
		SandboxManager: sandboxManager,
		ProcessMonitor: managers.NewProcessMonitor(),
		precreateCreateOptions: ContainerCreateOptions{
			RuncV2ShimGroup:  config.PrecreateShimGroup,
			RuntimeBinary:    config.PrecreateRuntimeBin,
			AdoptableSandbox: config.AdoptableSandboxes,
		},
		skipIptables:  config.SkipIptables,
		ctrdNamespace: ctrdNamespace,
		adoptable:     config.AdoptableSandboxes,
	}
}

// createNS returns the containerd namespace for NEW sandboxes.
func (cr *ContainerdRuntime) createNS() string {
	if cr.ctrdNamespace == "" {
		return NamespaceCM
	}
	return cr.ctrdNamespace
}

// nsCtx binds ctx to the runtime's creation namespace. Creation paths only —
// deletion paths must use the namespace recorded on the sandbox.
func (cr *ContainerdRuntime) nsCtx(ctx context.Context) context.Context {
	return namespaces.WithNamespace(ctx, cr.createNS())
}

// recordedNS resolves the containerd namespace a sandbox record was created
// in, defaulting to NamespaceCM for records that predate namespace tracking.
func recordedNS(ns string) string {
	if ns == "" {
		return NamespaceCM
	}
	return ns
}

func (cr *ContainerdRuntime) CreateSandbox(grpcCtx context.Context, in *proto.ServiceInfo) (*proto.SandboxCreationStatus, error) {
	return cr.CreateSandboxWithIdentity(grpcCtx, in, nil)
}

// CreateSandboxWithIdentity is CreateSandbox with optional kubelet pod
// attribution: when the runtime is in adoptable mode, the container is created
// in k8s.io with the CRI sandbox coordinate contract, and identity (if
// non-nil) binds it to an API pod. identity is ignored outside adoptable mode.
func (cr *ContainerdRuntime) CreateSandboxWithIdentity(grpcCtx context.Context, in *proto.ServiceInfo, identity *PodIdentity) (*proto.SandboxCreationStatus, error) {
	logrus.Debug("Create sandbox for service = '", in.Name, "'")

	start := time.Now()

	ctx := cr.nsCtx(grpcCtx)
	image, err, durationFetch := cr.ImageManager.GetImage(ctx, cr.ContainerdClient, in.Image)

	if err != nil {
		logrus.Warn("Failed fetching image - ", err)
		return &proto.SandboxCreationStatus{Success: false}, err
	}

	container, err, durationContainerCreation := CreateContainerWithOptions(ctx, cr.ContainerdClient, image, ContainerCreateOptions{
		AdoptableSandbox: cr.adoptable,
		Identity:         identity,
	})
	if err != nil {
		logrus.Warn("Failed creating a container - ", err)
		return &proto.SandboxCreationStatus{Success: false}, err
	}

	task, _, ip, netNs, err, durationContainerStart, durationCNI := StartContainer(ctx, container, cr.CNIClient)
	if err != nil {
		logrus.Warn("Failed starting a container - ", err)
		return &proto.SandboxCreationStatus{Success: false}, err
	}

	startConfigureMonitoring := time.Now()
	metadata := &managers.Metadata{
		ServiceName: in.Name,

		RuntimeMetadata: ContainerdMetadata{
			Task:          task,
			Container:     container,
			CtrdNamespace: cr.createNS(),
		},

		HostPort:  AssignRandomPort(),
		IP:        ip,
		GuestPort: int(in.PortForwarding.GuestPort),
		NetNs:     netNs,

		ExitStatusChannel: make(chan uint32),
	}

	cr.ProcessMonitor.AddChannel(task.Pid(), metadata.ExitStatusChannel)
	cr.SandboxManager.AddSandbox(container.ID(), metadata)
	configureMonitoringDuration := time.Since(startConfigureMonitoring)

	logrus.Debug("Sandbox creation took ", time.Since(start).Microseconds(), " μs (", container.ID(), ")")

	startIptables := time.Now()

	// PhantomK8s (skipIptables=true) proxies to the container IP directly and
	// needs no DNAT. Upstream Dirigent's data plane routes to workerIP:hostPort
	// and depends on these PREROUTING/OUTPUT rules — restore them for the
	// faithful Dirigent baseline arm.
	if !cr.skipIptables {
		managers.AddRules(cr.IPT, metadata.HostPort, metadata.IP, metadata.GuestPort)
	}

	durationIptables := time.Since(startIptables)

	logrus.Debug("IP tables configuration (add rule(s)) took ", durationIptables.Microseconds(), " μs")

	in.PortForwarding.HostPort = int32(metadata.HostPort)

	go WatchExitChannel(cr.cpApi, metadata, func(metadata *managers.Metadata) string {
		return metadata.RuntimeMetadata.(ContainerdMetadata).Container.ID()
	})

	return &proto.SandboxCreationStatus{
		Success:      true,
		ID:           container.ID(),
		PortMappings: in.PortForwarding,
		LatencyBreakdown: &proto.SandboxCreationBreakdown{
			Total:               durationpb.New(time.Since(start)),
			ImageFetch:          durationpb.New(durationFetch),
			SandboxCreate:       durationpb.New(durationContainerCreation),
			NetworkSetup:        durationpb.New(durationCNI),
			SandboxStart:        durationpb.New(durationContainerStart),
			Iptables:            durationpb.New(durationIptables),
			ReadinessProbing:    durationpb.New(0),
			SnapshotCreation:    durationpb.New(0),
			ConfigureMonitoring: durationpb.New(configureMonitoringDuration),
			FindSnapshot:        durationpb.New(0),
		},
	}, nil
}

// CreateSandboxInBundle creates a sandbox whose container joins a pre-created
// PhantomK8s pool bundle netns (eth0/IP/route preconfigured). CNI is skipped
// entirely; the pod IP is the bundle's pre-assigned IP. Metadata.NetNs is left
// empty so DeleteContainer skips CNI removal — the caller reclaims the bundle.
// identity (optional, adoptable mode only) attributes the sandbox to an API pod.
func (cr *ContainerdRuntime) CreateSandboxInBundle(grpcCtx context.Context, in *proto.ServiceInfo, netnsPath, ip string, identity *PodIdentity) (*proto.SandboxCreationStatus, error) {
	logrus.Debug("Create sandbox (bundle netns) for service = '", in.Name, "'")

	start := time.Now()

	ctx := cr.nsCtx(grpcCtx)
	image, err, durationFetch := cr.ImageManager.GetImage(ctx, cr.ContainerdClient, in.Image)

	if err != nil {
		logrus.Warn("Failed fetching image - ", err)
		return &proto.SandboxCreationStatus{Success: false}, err
	}

	container, err, durationContainerCreation := CreateContainerInNetNSWithOptions(ctx, cr.ContainerdClient, image, netnsPath, ContainerCreateOptions{
		AdoptableSandbox: cr.adoptable,
		Identity:         identity,
	})
	if err != nil {
		logrus.Warn("Failed creating a container - ", err)
		return &proto.SandboxCreationStatus{Success: false}, err
	}

	task, _, err, durationContainerStart, startTimings := StartContainerPrenetworked(ctx, container)
	if err != nil {
		logrus.Warn("Failed starting a container - ", err)
		return &proto.SandboxCreationStatus{Success: false}, err
	}
	cr.startTimings.Store(container.ID(), startTimings)

	startConfigureMonitoring := time.Now()
	metadata := &managers.Metadata{
		ServiceName: in.Name,

		RuntimeMetadata: ContainerdMetadata{
			Task:          task,
			Container:     container,
			CtrdNamespace: cr.createNS(),
		},

		HostPort:  AssignRandomPort(),
		IP:        ip,
		GuestPort: int(in.PortForwarding.GuestPort),
		NetNs:     "", // bundle-owned netns; CNI removal must be skipped

		ExitStatusChannel: make(chan uint32),
	}

	cr.ProcessMonitor.AddChannel(task.Pid(), metadata.ExitStatusChannel)
	cr.SandboxManager.AddSandbox(container.ID(), metadata)
	configureMonitoringDuration := time.Since(startConfigureMonitoring)

	logrus.Debug("Sandbox creation (bundle) took ", time.Since(start).Microseconds(), " μs (", container.ID(), ")")

	in.PortForwarding.HostPort = int32(metadata.HostPort)

	go WatchExitChannel(cr.cpApi, metadata, func(metadata *managers.Metadata) string {
		return metadata.RuntimeMetadata.(ContainerdMetadata).Container.ID()
	})

	return &proto.SandboxCreationStatus{
		Success:      true,
		ID:           container.ID(),
		PortMappings: in.PortForwarding,
		LatencyBreakdown: &proto.SandboxCreationBreakdown{
			Total:               durationpb.New(time.Since(start)),
			ImageFetch:          durationpb.New(durationFetch),
			SandboxCreate:       durationpb.New(durationContainerCreation),
			NetworkSetup:        durationpb.New(0), // CNI skipped — bundle netns pre-networked
			SandboxStart:        durationpb.New(durationContainerStart),
			Iptables:            durationpb.New(0),
			ReadinessProbing:    durationpb.New(0),
			SnapshotCreation:    durationpb.New(0),
			ConfigureMonitoring: durationpb.New(configureMonitoringDuration),
			FindSnapshot:        durationpb.New(0),
		},
	}, nil
}

// PrecreatedSandbox is a container whose task has been created (runc init
// parked before execve) inside a pool bundle netns. The expensive half of the
// launch — snapshot, shim spawn, runc create — is already paid; claiming it
// costs only task.Start.
type PrecreatedSandbox struct {
	Container containerd.Container
	Task      containerd.Task
	IP        string
	Image     string
	NewTaskMs float64 // fill-time cost, for reporting
	CreateMs  float64

	// Namespace is the containerd namespace this slot was created in. Start/
	// discard use it (never the current flag value), so slots parked before a
	// config change are still torn down in the right namespace. Empty = "cm".
	Namespace string
}

// PrecreateSandboxInBundle pays image-lookup + NewContainer(+snapshot) +
// NewTask (shim spawn + runc create) off the hot path and parks the task in
// Created state. Pair with StartPrecreatedSandbox on claim or
// DiscardPrecreatedSandbox on drain.
//
// Stages select how much of creation is prepaid:
//   "task" (default): NewContainer + NewTask via the per-slot runc shim —
//     parked runc-init held (shim 5.5MB + init 3.8MB per slot).
//   "container": NewContainer + snapshot only (Task == nil), Tier-2 — no
//     processes held; claim pays NewTask+Start. Also the isolation stage for
//     the staged memory delta.
//   "native": NewContainer + NewTask via the node-singleton rune shim — the
//     parked init is a ~0.5MB C fork-server child; zero per-slot shims.
func (cr *ContainerdRuntime) PrecreateSandboxInBundle(grpcCtx context.Context, imageName, netnsPath, ip, stage string) (*PrecreatedSandbox, error) {
	ctx := cr.nsCtx(grpcCtx)

	image, err, _ := cr.ImageManager.GetImage(ctx, cr.ContainerdClient, imageName)
	if err != nil {
		return nil, err
	}

	// Adoptable slots are parked before any pod identity exists: they carry
	// the sandbox-kind shape now; the pod labels are bound at claim time
	// (ApplyPodIdentityLabels in StartPrecreatedSandbox).
	createOpts := cr.precreateCreateOptions
	if stage == "native" {
		createOpts.RuneRuntime = true
	}
	container, err, durationCreate := CreateContainerInNetNSWithOptions(ctx, cr.ContainerdClient, image, netnsPath, createOpts)
	if err != nil {
		return nil, err
	}

	pre := &PrecreatedSandbox{
		Container: container,
		IP:        ip,
		Image:     imageName,
		CreateMs:  float64(durationCreate.Nanoseconds()) / 1e6,
		Namespace: cr.createNS(),
	}
	if stage == "container" {
		return pre, nil
	}

	task, err, durationNewTask := CreateParkedTask(ctx, container)
	if err != nil {
		// Roll back the container + snapshot so nothing leaks.
		_ = container.Delete(ctx, containerd.WithSnapshotCleanup)
		return nil, err
	}
	pre.Task = task
	pre.NewTaskMs = float64(durationNewTask.Nanoseconds()) / 1e6
	return pre, nil
}

// StartPrecreatedSandbox is the hot path for a precreated sandbox: Wait+Start
// (unblock parked init -> execve) plus monitoring registration. SandboxCreate
// is reported as 0 — that cost was paid at precreate time.
// identity (optional, adoptable mode only) binds the claimed slot to its API
// pod by merging the kubelet-attribution labels onto the container.
func (cr *ContainerdRuntime) StartPrecreatedSandbox(grpcCtx context.Context, in *proto.ServiceInfo, pre *PrecreatedSandbox, identity *PodIdentity) (*proto.SandboxCreationStatus, error) {
	start := time.Now()
	ctx := namespaces.WithNamespace(grpcCtx, recordedNS(pre.Namespace))

	// Bind the pod identity to this slot (labels are mutable; the container
	// was parked before the pod was known). Fail open: a failed label write
	// only loses attribution for this invocation, not the launch itself.
	if cr.adoptable && identity != nil {
		if err := ApplyPodIdentityLabels(ctx, pre.Container, identity); err != nil {
			logrus.Warnf("Failed to bind pod identity %s to precreated sandbox %s: %v", identity.UID, pre.Container.ID(), err)
		}
	}

	// Tier-2 (container-only park): no shim/init held — pay NewTask at claim.
	claimNewTask := time.Duration(0)
	if pre.Task == nil {
		task, terr, durationNewTask := CreateParkedTask(ctx, pre.Container)
		if terr != nil {
			logrus.Warn("Failed creating task for container-only precreated sandbox - ", terr)
			return &proto.SandboxCreationStatus{Success: false}, terr
		}
		pre.Task = task
		claimNewTask = durationNewTask
	}

	_, err, startTimings := StartParkedTask(ctx, pre.Task)
	if err != nil {
		logrus.Warn("Failed starting a precreated task - ", err)
		return &proto.SandboxCreationStatus{Success: false}, err
	}
	startTimings.NewTask = claimNewTask
	cr.startTimings.Store(pre.Container.ID(), startTimings)

	startConfigureMonitoring := time.Now()
	metadata := &managers.Metadata{
		ServiceName: in.Name,

		RuntimeMetadata: ContainerdMetadata{
			Task:          pre.Task,
			Container:     pre.Container,
			CtrdNamespace: recordedNS(pre.Namespace),
		},

		HostPort:  AssignRandomPort(),
		IP:        pre.IP,
		GuestPort: int(in.PortForwarding.GuestPort),
		NetNs:     "", // bundle-owned netns; CNI removal must be skipped

		ExitStatusChannel: make(chan uint32),
	}

	cr.ProcessMonitor.AddChannel(pre.Task.Pid(), metadata.ExitStatusChannel)
	cr.SandboxManager.AddSandbox(pre.Container.ID(), metadata)
	configureMonitoringDuration := time.Since(startConfigureMonitoring)

	in.PortForwarding.HostPort = int32(metadata.HostPort)

	go WatchExitChannel(cr.cpApi, metadata, func(metadata *managers.Metadata) string {
		return metadata.RuntimeMetadata.(ContainerdMetadata).Container.ID()
	})

	return &proto.SandboxCreationStatus{
		Success:      true,
		ID:           pre.Container.ID(),
		PortMappings: in.PortForwarding,
		LatencyBreakdown: &proto.SandboxCreationBreakdown{
			Total:               durationpb.New(time.Since(start)),
			ImageFetch:          durationpb.New(0),
			SandboxCreate:       durationpb.New(0), // paid at precreate time
			NetworkSetup:        durationpb.New(0), // bundle netns pre-networked
			SandboxStart:        durationpb.New(startTimings.Wait + startTimings.TaskStart),
			Iptables:            durationpb.New(0),
			ReadinessProbing:    durationpb.New(0),
			SnapshotCreation:    durationpb.New(0),
			ConfigureMonitoring: durationpb.New(configureMonitoringDuration),
			FindSnapshot:        durationpb.New(0),
		},
	}, nil
}

// DiscardPrecreatedSandbox tears down a parked (never-started) precreated
// sandbox: kill+delete the task (if one was created), delete the container
// and its snapshot.
func (cr *ContainerdRuntime) DiscardPrecreatedSandbox(grpcCtx context.Context, pre *PrecreatedSandbox) error {
	// Use the namespace the slot was CREATED in, never the current flag value.
	ctx := namespaces.WithNamespace(grpcCtx, recordedNS(pre.Namespace))
	if pre.Task != nil {
		if _, err := pre.Task.Delete(ctx, containerd.WithProcessKill); err != nil {
			logrus.Warn("discard precreated task: ", err)
		}
	}
	return pre.Container.Delete(ctx, containerd.WithSnapshotCleanup)
}

func (cr *ContainerdRuntime) ConsumeStartTimings(sandboxID string) (StartTimings, bool) {
	raw, ok := cr.startTimings.LoadAndDelete(sandboxID)
	if !ok {
		return StartTimings{}, false
	}
	timings, ok := raw.(StartTimings)
	return timings, ok
}

func (cr *ContainerdRuntime) DeleteSandbox(grpcCtx context.Context, in *proto.SandboxID) (*proto.ActionStatus, error) {
	logrus.Debug("RemoveKey sandbox with ID = '", in.ID, "'")

	metadata := cr.SandboxManager.DeleteSandbox(in.ID)

	if metadata == nil {
		logrus.Warn("Tried to delete non-existing sandbox ", in.ID)
		return &proto.ActionStatus{Success: false}, nil
	}

	// Delete from the namespace the sandbox was CREATED in (recorded on its
	// metadata), never from the namespace the current flags would pick — a
	// worker whose --adoptable-sandboxes flag changed across a restart must
	// not orphan sandboxes in the other namespace.
	deleteNS := NamespaceCM
	if cm, ok := metadata.RuntimeMetadata.(ContainerdMetadata); ok {
		deleteNS = recordedNS(cm.CtrdNamespace)
	}
	ctx := namespaces.WithNamespace(grpcCtx, deleteNS)

	start := time.Now()

	// PhantomK8s never added DNAT rules; the upstream Dirigent arm did.
	if !cr.skipIptables {
		managers.DeleteRules(cr.IPT, metadata.HostPort, metadata.IP, metadata.GuestPort)
	}
	UnassignPort(metadata.HostPort)
	logrus.Debug("IP tables configuration (remove rule(s)) took ", time.Since(start).Microseconds(), " μs")

	start = time.Now()
	err := DeleteContainer(ctx, cr.CNIClient, metadata)

	if err != nil {
		logrus.Warn(err)
		return &proto.ActionStatus{Success: false}, err
	}

	logrus.Debug("Sandbox deletion took ", time.Since(start).Microseconds(), " μs")

	return &proto.ActionStatus{Success: true}, nil
}

func (cr *ContainerdRuntime) ListEndpoints(_ context.Context, _ *emptypb.Empty) (*proto.EndpointsList, error) {
	return cr.SandboxManager.ListEndpoints()
}

func (cr *ContainerdRuntime) ValidateHostConfig() bool {
	return true
}
