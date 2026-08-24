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
	"context"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"syscall"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	containerdcontainers "github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/oci"
	containerdplugin "github.com/containerd/containerd/plugin"
	runcoptions "github.com/containerd/containerd/runtime/v2/runc/options"
	"github.com/containerd/go-cni"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

const (
	SIGKILL uint32 = 137

	RuncV2ShimGroupAnnotation = "io.containerd.runc.v2.group"
)

// Containerd namespaces sandboxes are created in. Upstream Dirigent (and the
// PhantomK8s default) uses "cm", which the kubelet never watches. Adoptable
// mode (--adoptable-sandboxes) uses the CRI plugin's "k8s.io" so materialized
// sandboxes live at the coordinates the kubelet's runtime would look at.
const (
	NamespaceCM  = "cm"
	NamespaceK8s = "k8s.io"
)

// CRI coordinate-contract label/annotation conventions. Values mirror
// containerd pkg/cri/server/helpers.go + pkg/cri/annotations (verified against
// the vendored v1.5.17) and k8s.io/kubernetes pkg/kubelet/types labels. They
// are declared locally to avoid importing the CRI plugin packages.
const (
	// Container label the CRI plugin filters on in recover() at containerd
	// restart (restart.go): kind=sandbox marks a sandbox container.
	criKindLabel   = "io.cri-containerd.kind"
	criKindSandbox = "sandbox"

	// Kubelet pod-attribution labels stamped by the kubelet onto every CRI
	// sandbox/container it creates.
	podUIDLabel       = "io.kubernetes.pod.uid"
	podNameLabel      = "io.kubernetes.pod.name"
	podNamespaceLabel = "io.kubernetes.pod.namespace"

	// CRI OCI-spec annotations (visible to shims/NRI, immutable after create).
	criContainerTypeAnnotation    = "io.kubernetes.cri.container-type"
	criContainerTypeSandbox       = "sandbox"
	criSandboxIDAnnotation        = "io.kubernetes.cri.sandbox-id"
	criSandboxNameAnnotation      = "io.kubernetes.cri.sandbox-name"
	criSandboxNamespaceAnnotation = "io.kubernetes.cri.sandbox-namespace"
	criSandboxUIDAnnotation       = "io.kubernetes.cri.sandbox-uid" // containerd >= 1.6 convention
)

// PodIdentity is the kubelet-attribution coordinate set for an adoptable
// sandbox: the API-server pod this sandbox materializes. Namespace is the K8s
// namespace of the pod, NOT a containerd namespace.
type PodIdentity struct {
	UID       string
	Name      string
	Namespace string
}

// adoptableLabels builds the containerd container labels that mark this
// container as a CRI-shaped sandbox attributed to a pod. Identity may be nil
// (precreated slots are filled before the pod is known; identity labels are
// merged at claim via ApplyPodIdentityLabels).
func adoptableLabels(id *PodIdentity) map[string]string {
	labels := map[string]string{criKindLabel: criKindSandbox}
	mergePodIdentityLabels(labels, id)
	return labels
}

func mergePodIdentityLabels(labels map[string]string, id *PodIdentity) {
	if id == nil {
		return
	}
	if id.UID != "" {
		labels[podUIDLabel] = id.UID
	}
	if id.Name != "" {
		labels[podNameLabel] = id.Name
	}
	if id.Namespace != "" {
		labels[podNamespaceLabel] = id.Namespace
	}
}

// adoptableAnnotationSpecOpts returns the CRI-shaped OCI spec annotations for
// a sandbox container. Our sandboxes are single-container (the workload IS the
// sandbox), so sandbox-id is the container's own ID.
func adoptableAnnotationSpecOpts(containerName string, id *PodIdentity) []oci.SpecOpts {
	out := []oci.SpecOpts{
		withSpecAnnotation(criContainerTypeAnnotation, criContainerTypeSandbox),
		withSpecAnnotation(criSandboxIDAnnotation, containerName),
	}
	if id != nil {
		if id.UID != "" {
			out = append(out, withSpecAnnotation(criSandboxUIDAnnotation, id.UID))
		}
		if id.Name != "" {
			out = append(out, withSpecAnnotation(criSandboxNameAnnotation, id.Name))
		}
		if id.Namespace != "" {
			out = append(out, withSpecAnnotation(criSandboxNamespaceAnnotation, id.Namespace))
		}
	}
	return out
}

// ApplyPodIdentityLabels merges the pod-attribution labels into an existing
// container at claim time. Precreated (parked) slots are created before any
// pod identity exists; when one is claimed for a pod, this binds the identity.
// Containerd labels are mutable (SetLabels merges); the OCI sandbox-uid/name/
// namespace annotations are not, so on precreated slots those stay absent —
// the labels are the canonical coordinates.
func ApplyPodIdentityLabels(ctx context.Context, container containerd.Container, id *PodIdentity) error {
	if id == nil {
		return nil
	}
	labels := map[string]string{}
	mergePodIdentityLabels(labels, id)
	if len(labels) == 0 {
		return nil
	}
	_, err := container.SetLabels(ctx, labels)
	return err
}

func GetContainerdClient(containerdSocket string) *containerd.Client {
	client, err := containerd.New(containerdSocket)
	if err != nil {
		log.Fatal("Failed to create a containerd client - ", err)
	}

	return client
}

func GetCNIClient(configFile string, pluginDirs ...string) cni.CNI {
	opts := []cni.Opt{}
	// Plugin dir must be set BEFORE loading config, because the config
	// captures the cniConfig reference at load time.
	if len(pluginDirs) > 0 && pluginDirs[0] != "" {
		opts = append(opts, cni.WithPluginDir(pluginDirs))
	}
	if strings.HasSuffix(configFile, ".conflist") {
		opts = append(opts, cni.WithConfListFile(configFile))
	} else {
		opts = append(opts, cni.WithConfFile(configFile))
	}
	network, err := cni.New(opts...)
	if err != nil {
		logrus.Fatal("Failed to create a CNI client - ", err)
	}

	return network
}

func FetchImage(ctx context.Context, client *containerd.Client, imageURL string) (containerd.Image, error) {
	// Try local image first (avoids pull for pre-imported images).
	if img, err := client.GetImage(ctx, imageURL); err == nil {
		return img, nil
	}
	image, err := client.Pull(ctx, imageURL, containerd.WithPullUnpack)
	if err != nil {
		return nil, err
	}

	return image, nil
}

func CreateContainer(ctx context.Context, client *containerd.Client, image containerd.Image) (containerd.Container, error, time.Duration) {
	return CreateContainerWithOptions(ctx, client, image, ContainerCreateOptions{})
}

// CreateContainerWithOptions is CreateContainer (fresh netns, CNI to follow)
// plus the adoptable-sandbox shape when opts request it.
func CreateContainerWithOptions(ctx context.Context, client *containerd.Client, image containerd.Image, opts ContainerCreateOptions) (containerd.Container, error, time.Duration) {
	start := time.Now()

	containerName := fmt.Sprintf("workload-%d", rand.Int())

	specOpts := []oci.SpecOpts{oci.WithImageConfig(image)}
	if opts.AdoptableSandbox {
		specOpts = append(specOpts, adoptableAnnotationSpecOpts(containerName, opts.Identity)...)
	}

	containerOpts := []containerd.NewContainerOpts{
		containerd.WithImage(image),
		containerd.WithNewSnapshot(containerName, image),
		containerd.WithNewSpec(specOpts...),
	}
	if opts.AdoptableSandbox {
		containerOpts = append(containerOpts, containerd.WithContainerLabels(adoptableLabels(opts.Identity)))
	}

	container, err := client.NewContainer(ctx, containerName, containerOpts...)

	if err != nil {
		return nil, err, time.Since(start)
	}

	return container, nil, time.Since(start)
}

// CreateContainerInNetNS creates a container whose OCI spec joins a
// pre-created network namespace (a PhantomK8s pool bundle netns with
// eth0/IP/route already configured) instead of letting runc create a
// fresh one. CNI is skipped entirely for such containers.
func CreateContainerInNetNS(ctx context.Context, client *containerd.Client, image containerd.Image, netnsPath string) (containerd.Container, error, time.Duration) {
	return CreateContainerInNetNSWithOptions(ctx, client, image, netnsPath, ContainerCreateOptions{})
}

type ContainerCreateOptions struct {
	RuncV2ShimGroup string
	RuntimeBinary   string
	// RuneRuntime routes the container through the node-singleton rune shim
	// (io.containerd.rune.v2). Its app-container fast path parks a ~0.5MB C
	// fork-server child instead of a per-slot runc shim (5.5MB) + runc init
	// (3.8MB): zero per-slot shim processes. Requires the image annotation
	// below so the shim's template registry can resolve the rootfs lowerdir.
	RuneRuntime bool

	// AdoptableSandbox stamps the container with the CRI sandbox-container
	// coordinate contract: containerd label io.cri-containerd.kind=sandbox +
	// kubelet pod-attribution labels (from Identity, when known) and the
	// io.kubernetes.cri.* sandbox annotations on the OCI spec. Pair with
	// creating in the k8s.io containerd namespace (ContainerdRuntime does this
	// when config.AdoptableSandboxes is set).
	AdoptableSandbox bool
	// Identity attributes the sandbox to an API pod. May be nil (precreated
	// slots bind identity later via ApplyPodIdentityLabels).
	Identity *PodIdentity
}

const (
	runeRuntimeName    = "io.containerd.rune.v2"
	criImageAnnotation = "io.kubernetes.cri.image-name"
)

func CreateContainerInNetNSWithOptions(ctx context.Context, client *containerd.Client, image containerd.Image, netnsPath string, opts ContainerCreateOptions) (containerd.Container, error, time.Duration) {
	start := time.Now()

	containerName := fmt.Sprintf("workload-%d", rand.Int())

	specOpts := []oci.SpecOpts{
		oci.WithImageConfig(image),
		oci.WithLinuxNamespace(specs.LinuxNamespace{
			Type: specs.NetworkNamespace,
			Path: netnsPath,
		}),
	}
	if opts.RuncV2ShimGroup != "" {
		specOpts = append(specOpts, withSpecAnnotation(RuncV2ShimGroupAnnotation, opts.RuncV2ShimGroup))
	}
	if opts.RuneRuntime {
		// The rune shim's Create reads the CRI image annotation to find its
		// rootfs template (first create per image per node takes its cold
		// path and registers the template; the rest park fork-server children).
		specOpts = append(specOpts, withSpecAnnotation(criImageAnnotation, image.Name()))
	}
	if opts.AdoptableSandbox {
		specOpts = append(specOpts, adoptableAnnotationSpecOpts(containerName, opts.Identity)...)
	}

	containerOpts := []containerd.NewContainerOpts{
		containerd.WithImage(image),
		containerd.WithNewSnapshot(containerName, image),
		containerd.WithNewSpec(specOpts...),
	}
	if opts.AdoptableSandbox {
		containerOpts = append(containerOpts, containerd.WithContainerLabels(adoptableLabels(opts.Identity)))
	}
	if opts.RuneRuntime {
		containerOpts = append(containerOpts, containerd.WithRuntime(runeRuntimeName, nil))
	} else if opts.RuntimeBinary != "" {
		containerOpts = append(containerOpts, containerd.WithRuntime(containerdplugin.RuntimeRuncV2, &runcoptions.Options{
			BinaryName: opts.RuntimeBinary,
		}))
	}

	container, err := client.NewContainer(ctx, containerName, containerOpts...)

	if err != nil {
		return nil, err, time.Since(start)
	}

	return container, nil, time.Since(start)
}

func withSpecAnnotation(key, value string) oci.SpecOpts {
	return func(_ context.Context, _ oci.Client, _ *containerdcontainers.Container, s *oci.Spec) error {
		if s.Annotations == nil {
			s.Annotations = map[string]string{}
		}
		s.Annotations[key] = value
		return nil
	}
}

type StartTimings struct {
	NewTask   time.Duration
	Wait      time.Duration
	TaskStart time.Duration
}

// StartContainerPrenetworked starts a container whose network namespace was
// joined at spec time (pool bundle) — no CNI setup on the hot path.
func StartContainerPrenetworked(ctx context.Context, container containerd.Container) (containerd.Task, <-chan containerd.ExitStatus, error, time.Duration, StartTimings) {
	start := time.Now()
	var timings StartTimings

	newTaskStart := time.Now()
	task, err := container.NewTask(ctx, cio.NewCreator())
	timings.NewTask = time.Since(newTaskStart)
	if err != nil {
		return nil, nil, err, time.Since(start), timings
	}

	waitStart := time.Now()
	statusChannel, err := task.Wait(ctx)
	timings.Wait = time.Since(waitStart)
	if err != nil {
		return nil, nil, err, time.Since(start), timings
	}

	taskStart := time.Now()
	if err := task.Start(ctx); err != nil {
		timings.TaskStart = time.Since(taskStart)
		return nil, nil, err, time.Since(start), timings
	}
	timings.TaskStart = time.Since(taskStart)

	return task, statusChannel, nil, time.Since(start), timings
}

// CreateParkedTask creates the task — shim spawn + runc create (clone init,
// join namespaces, cgroup, pivot_root) — WITHOUT starting it. The container
// init is parked before execve. This is the expensive, contention-prone half
// of the launch; calling it at pool-fill time moves it off the hot path.
func CreateParkedTask(ctx context.Context, container containerd.Container) (containerd.Task, error, time.Duration) {
	start := time.Now()
	task, err := container.NewTask(ctx, cio.NewCreator())
	return task, err, time.Since(start)
}

// StartParkedTask runs Wait+Start on a pre-created (parked) task — the entire
// hot-path containerd work for a precreated sandbox: unblock init -> execve.
func StartParkedTask(ctx context.Context, task containerd.Task) (<-chan containerd.ExitStatus, error, StartTimings) {
	var timings StartTimings

	waitStart := time.Now()
	statusChannel, err := task.Wait(ctx)
	timings.Wait = time.Since(waitStart)
	if err != nil {
		return nil, err, timings
	}

	taskStart := time.Now()
	err = task.Start(ctx)
	timings.TaskStart = time.Since(taskStart)
	if err != nil {
		return nil, err, timings
	}

	return statusChannel, nil, timings
}

func StartContainer(ctx context.Context, container containerd.Container, network cni.CNI) (containerd.Task, <-chan containerd.ExitStatus, string, string, error, time.Duration, time.Duration) {
	start := time.Now()

	task, err := container.NewTask(ctx, cio.NewCreator())
	if err != nil {
		return nil, nil, "", "", err, 0, 0
	}

	statusChannel, err := task.Wait(ctx)
	if err != nil {
		return nil, nil, "", "", err, 0, 0
	}

	//////////////////////////////////////////
	// CNI
	//////////////////////////////////////////
	cniStart := time.Now()
	netns := fmt.Sprintf("/proc/%v/ns/net", task.Pid())
	result, err := network.Setup(ctx, container.ID(), netns)

	if err != nil {
		return nil, nil, "", "", err, 0, 0
	}

	ip := result.Interfaces["eth0"].IPConfigs[0].IP.String()
	logrus.Debug("Container ", container.ID(), " has been allocated IP = ", ip)

	durationCNI := time.Since(cniStart)
	//////////////////////////////////////////
	//////////////////////////////////////////
	//////////////////////////////////////////

	err = task.Start(ctx)
	if err != nil {
		return nil, nil, "", "", err, 0, 0
	}

	return task, statusChannel, ip, netns, nil, time.Since(start) - durationCNI, durationCNI
}

func WatchExitChannel(cpApi proto.CpiInterfaceClient, metadata *managers.Metadata, extractContainerName func(*managers.Metadata) string) {
	exitCode := <-metadata.ExitStatusChannel
	containerID := extractContainerName(metadata)

	switch exitCode {
	case SIGKILL: // sent by 'Task.Kill' from 'DeleteContainer'
		logrus.Debug("Sandbox '", containerID, "' terminated by the control plane with exit code ", exitCode)
	default: // termination not caused by a signal
		if cpApi == nil {
			// TODO: in tests create fake cpApi
			return // for tests as cpApi is null
		}

		_, err := cpApi.ReportFailure(context.Background(), &proto.Failure{
			Type:        proto.FailureType_SANDBOX_FAILURE,
			ServiceName: metadata.ServiceName,
			SandboxIDs:  []string{containerID},
		})
		if err != nil {
			logrus.Warn("Failed to report container failure to the control plane for '" + metadata.ServiceName + "'.")
		}

		logrus.Debug("Control plane has been notified of failure of sandbox '", containerID, "' (exit code: ", exitCode, ")")
	}
}

func DeleteContainer(ctx context.Context, network cni.CNI, metadata *managers.Metadata) error {
	containerMetadata := (*metadata).RuntimeMetadata.(ContainerdMetadata)

	// TODO: what happens with CNI and container metadata if the container fails -- memory leak
	// NetNs == "" means the container joined a pre-created pool bundle netns:
	// CNI never ran, so there is nothing to remove (the bundle is reclaimed
	// by the worker after deletion).
	if metadata.NetNs != "" {
		if err := network.Remove(ctx, containerMetadata.Container.ID(), metadata.NetNs); err != nil {
			return err
		}
	}

	// non-graceful shutdown
	if err := containerMetadata.Task.Kill(ctx, syscall.SIGKILL, containerd.WithKillAll); err != nil {
		return err
	}

	// containerd detection failure is useless as wait on exit channel needs to be called after KILL,
	// otherwise it is useless
	exitStatus, err := containerMetadata.Task.Delete(ctx, containerd.WithProcessKill)
	if err != nil {
		return err
	}
	logrus.Debug("Sandbox terminated by SIGKILL (status code :", exitStatus.ExitCode(), ")")

	if err := containerMetadata.Container.Delete(ctx, containerd.WithSnapshotCleanup); err != nil {
		return err
	}

	return nil
}
