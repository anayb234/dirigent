# Adoptable Sandboxes (`--adoptable-sandboxes`)

Status: coordinate contract implemented; PLEG visibility NOT yet achieved (by
design impossible from containerd-direct creation — see "Path to PLEG
visibility" below). Default OFF; with the flag off the worker behaves exactly
as before (everything in the `cm` containerd namespace, no labels).

## Problem

The worker materializes sandboxes containerd-DIRECT into the `cm` containerd
namespace with no pod labels. The kubelet's runtime (containerd CRI plugin)
serves only the `k8s.io` namespace, so materialized sandboxes are invisible to
the kubelet: the patched kubelet's adoption branch is dead code, eviction is an
illusory no-op (kubelet "kills" the pod object, finds no containers, reports
success while the real sandbox keeps running), and the system is a de-facto
kubelet bypass while the thesis claims kubelet adoption.

The coordinate contract for adoption (see memory note claim2-core-thesis-
decision) has four coordinates:

1. sandbox in the `k8s.io` containerd namespace — **this flag**
2. labels `io.kubernetes.pod.{uid,name,namespace}` + CRI sandbox conventions —
   **this flag**
3. cgroup at `kubepods/<qos>/pod<uid>` — already implemented
   (`cgroup_adopt.go`, `--cgroup-driver`, verified E2E)
4. pod object exists first — already true (phantoms are real API pods)

## What the flag does

With `--adoptable-sandboxes`:

- All sandbox containers/tasks are created in the **`k8s.io`** containerd
  namespace instead of `cm` (create, bundle, precreate, prefetch).
- Containers carry the CRI sandbox-container shape:
  - containerd labels: `io.cri-containerd.kind=sandbox` plus
    `io.kubernetes.pod.uid` / `.pod.name` / `.pod.namespace` when the create
    request supplies pod identity (`pod_uid`, `pod_name`, `pod_namespace`).
  - OCI spec annotations: `io.kubernetes.cri.container-type=sandbox`,
    `io.kubernetes.cri.sandbox-id` (= container ID; our workload container IS
    the sandbox), and `io.kubernetes.cri.sandbox-{uid,name,namespace}` when
    identity is known at create time.
- Precreated (parked) slots are filled before any pod exists, so they carry
  only the sandbox-kind shape at fill; the pod labels are merged onto the
  container at claim (`ApplyPodIdentityLabels`, labels are mutable). The OCI
  sandbox-uid/name/namespace annotations are immutable and therefore stay
  absent on parked slots — the labels are the canonical coordinates.
- The containerd namespace **travels with every sandbox record**
  (`ContainerdMetadata.CtrdNamespace`, `PrecreatedSandbox.Namespace`), and all
  delete/discard paths resolve the namespace from the record, never from the
  flag. Flipping the flag across worker restarts cannot orphan sandboxes in
  the other namespace.

Operational requirements:

- Function images must be present or pullable in `k8s.io`
  (`ctr -n k8s.io images import ...`); the `cm` image store is separate.
- Because the containers carry `io.cri-containerd.kind=sandbox`, a containerd
  restart makes the CRI plugin's `recover()` attempt to load them; it fails
  ("metadata extension not found"), logs `Failed to load sandbox`, and skips
  them — the running task is untouched (verified in vendored v1.5.17
  `pkg/cri/server/restart.go`; re-verify on the node's k3s-embedded containerd
  before benchmark runs).
- Kubelet image GC cannot see that our raw containers use the fn image (usage
  is computed from CRI containers), so under disk pressure it may remove the
  image record from `k8s.io`; running containers keep their snapshots but
  later creates re-pull.

## What the flag does NOT do: the CRI runtime-visibility limitation

The kubelet's PLEG asks the CRI (`ListPodSandbox`/`ListContainers`), and
containerd's CRI plugin answers those from **in-memory stores**
(`sandboxStore`/`containerStore`), populated in exactly two places:

1. `RunPodSandbox` / `CreateContainer` (the CRI calls themselves), and
2. `recover()` at CRI plugin startup (containerd restart), which lists
   containers labeled `io.cri-containerd.kind=sandbox` and reconstructs store
   entries via `loadSandbox`.

A raw labeled container in `k8s.io` is therefore **not visible to CRI — and
hence not to PLEG — at runtime, no matter how perfect its labels are**. The
flag places our sandboxes at the right coordinates; it cannot, by itself,
make PLEG see them. The patched kubelet's materialized branch keeps deferring
(no kill, no create) exactly as before — safe, but adoption does not trigger.

## Path to PLEG visibility — three options evaluated

### (a) Restart-time `loadSandbox` — dead end

Verified against the vendored containerd v1.5.17
(`pkg/cri/server/restart.go:54` `recover()`, `:326` `loadSandbox`):

- `recover()` filters on `io.cri-containerd.kind=sandbox` — our containers ARE
  enumerated.
- `loadSandbox` then **requires the container extension
  `io.cri-containerd.sandbox.metadata`** — a typeurl-marshaled
  `sandboxstore.Metadata` holding the full CRI `PodSandboxConfig`, sandbox
  name, and `NetNSPath`. Missing → `metadata extension not found` → the
  container is logged and skipped. Our containers do not carry it, so
  loadSandbox does NOT accept our shape as-is.
- Forging the extension is technically possible (the netns side would even
  work: `loadSandbox` re-opens `meta.NetNSPath` without re-running CNI, so a
  bundle netns path is acceptable), but it binds us to the internal
  `sandboxstore.Metadata` encoding of the node's containerd (k3s v1.33 embeds
  containerd 2.x, where CRI moved to `internal/cri` with the sandbox-
  controller architecture), and it only takes effect after a containerd
  restart — not a runtime adoption mechanism. Reject.

### (b) Real CRI sandbox from the worker — recommended

Create the sandbox through the CRI API (k3s CRI socket) with the pod's
`PodSandboxConfig` (uid/name/namespace/labels), then run the function
container inside it via CRI `CreateContainer`+`StartContainer`. The CRI plugin
itself populates its stores → PLEG sees the sandbox on the next relist →
the patched kubelet's materialized branch falls through to **stock adoption**
→ status/probes/restarts/eviction become real, driven by an unmodified CRI.

Cost vs today (numbers from cluster measurements in the memory notes):

| | containerd-direct (today) | CRI at claim | CRI hoisted to registration |
|---|---|---|---|
| claim latency | 4–40 ms (native/parked) | ~85 ms typical; RunPodSandbox p95 243 ms + CNI p95 225 ms under burst | ~30–50 ms (CreateContainer+Start in existing sandbox, Tier-2-like) |
| per-slot memory | ~1.4 MB (bundle + parked child) | 0 idle | ~17 MB (pause sandbox + CRI bookkeeping) |
| CNI | skipped (bundle netns) | paid at claim | paid at register, off-path |
| PLEG visibility | none | full | full |

The registration-time hoist is the thesis move (temporal decomposition):
`RunPodSandbox` — the burst-collapsing, CNI-serialized step — is paid once at
phantom registration when the pod UID is already known, off the hot path;
claim pays only container create+start inside the standing sandbox. The
~17 MB/slot bill is real (it is why the old sandbox pool was removed), so this
becomes a **two-tier policy**: CRI-backed adoptable slots for functions that
need kubelet governance (probes, eviction, restart semantics), 1.4 MB phantom
slots for memory-tight bulk capacity. The existing kubelet-patch defer branch
remains the safety net for the annotation-flip → PLEG-relist window (~1 s).

### (c) Kubelet-patch route — rejected as primary

The patch's materialized branch already defers rather than kills; extending it
to synthesize sandbox status from pod annotations (or interposing a CRI proxy
that injects truthful records) would give "visibility" without CRI ownership.
But every downstream consumer (probes, eviction's `StopPodSandbox`, stats)
would then hit a CRI that does not know the sandbox — each needs its own shim,
which is KubeDirect's forged-data-plane architecture rebuilt piecewise, and it
moves the patch-LOC metric in the wrong direction (goal: patch → 0). Keep the
existing defer branch as (b)'s race guard; do not grow it into a data plane.

## Recommendation

Adopt **(b) with registration-time hoisting** as the adoption path. Keep
`--adoptable-sandboxes` as (i) the correct substrate/ablation arm — identical
coordinates, no CRI sandbox — for measuring exactly what CRI-backed slots buy,
and (ii) the mode that makes node-level tooling (`ctr`, attribution, teardown)
truthful today. The single blocking defect (cm namespace, no labels) is fixed;
the remaining gap to PLEG visibility is precisely one `RunPodSandbox` per
adoptable slot, paid off-path.
