# AgentProvenance closeout criteria

English · [简体中文](zh-CN/project-closeout.md)

This document defines the project's current engineering finish line. It deliberately
stops before AgentProvenance becomes a virtualization platform or a centralized
SaaS product.

## First experience: portable replay

The [v0.8.2-rc.2 prerelease](releases/v0.8.2-rc.2.md) provides CLI archives for
Linux and macOS on amd64/arm64. `agentprov demo` opens a local gallery containing
six verified signed captures and two optional evaluator guides, with the same
visual theme as the dashboard. Guides render locally with a section outline,
images, tables and code-copy controls. See the [Quickstart](../README.md#quickstart)
and [complete demo index](../demo/README.md).

Replay uses an isolated temporary store and does not execute the captured actions.
Evaluator execution and live Linux capture retain their separate requirements.
The four-platform archive gate validates replay and cleanup, not extra live
sensor coverage or long-running capture.

## Portable Producer Profiles

The implemented portability boundary is **local Linux, KVM guests and Kubernetes
Pods**, using `local-record` and `k8s-daemonset`. The same substrate-neutral
evidence model accepts an actively wrapped process and externally scheduled
Pods attributed by kernel cgroup identity. KVM runs the sensor inside the guest;
it does not require a new graph model or host-side VM introspection.

The [amd64/KVM/K3s runbook](amd64-kvm-k3s.md) documents installation and the
checked [live reports](benchmarks/amd64-kvm-k3s/README.md): syscall/TLS capture,
guest service and normal reboot, late Pod attribution, export/import,
local/Pod semantic parity, and upgrade preservation. These are bounded lab
validations, not all-kernel or all-hypervisor certification.

## Single-node scale boundary

AgentProvenance must prove:

- one node sensor observes multiple independent workloads;
- queued telemetry is bounded by batch count, total bytes, and per-batch bytes;
- ingest supports batches, durable spool, backpressure and explicit overflow
  accounting; native capture rejects new data at capacity, while the legacy
  JSONL upload spool offers `reject`/`drop_oldest` policies;
- producer health reports accepted/processed/failed/dropped batches, queued
  bytes, sensor drops, event source counts, and correlation coverage;
- a 100k-event acceptance run emits a machine-readable report containing ingest
  throughput, health/query p50/p95/p99, daemon CPU/RSS peaks, queue state, drop
  state, final event count, and coverage;
- evidence queries remain bounded and graph verification remains consistent.

The pressure report is a measured baseline, not a production SLA. Different
hosts may produce different latency and throughput values.

Reference run on the macOS development host (2026-08-04, 100,000 synthetic
Falco events): all 100,000 events were ingested with zero failed/dropped batches;
health p95 was 1.209 ms, paged-query p95 was 9.182 ms, peak daemon RSS was about
55 MiB, and end-to-end spool drain throughput was 134.14 events/s. The query and
memory behavior meet this closeout target. The throughput is an honest
single-node SQLite baseline, not a production streaming claim.
The compact checked result is
[`benchmarks/telemetry-100k-macos-arm64.json`](benchmarks/telemetry-100k-macos-arm64.json).

The original Kubernetes node gate was validated on 2026-08-05 on the arm64 Ubuntu 6.8
lab VM with single-node K3s. The gate built and deployed the real privileged
sensor DaemonSet, collected its stdout JSONL, resolved Kubernetes
pod/container identity to the cgroup ids present in that kernel stream, and
bound 8 independently scheduled BusyBox pods into one run. It observed 8
distinct cgroups, ingested 1,140 pod-scoped runtime events, and completed
`graph verify` with zero errors and zero warnings. This proves the per-node
producer shape; it is not a cluster-wide throughput benchmark.

The amd64 KVM/K3s run repeats this with **8 workloads, 8 distinct cgroups and
1,289 events**, with zero graph errors or warnings. The
[compact report](benchmarks/amd64-kvm-k3s/k3s-multiworkload.json) is checked in;
raw streams and bulky captures stay outside Git.

The lightweight attribution controller was validated separately on the same
node against K3s 1.36.2. A filtered `client-go` informer established the first
container binding, observed a real container restart under the same Pod UID,
closed/replaced that binding, and closed the replacement after Pod deletion.
The final report contained 2 created and 2 closed bindings, 0 active bindings,
1 restart, and 0 retry/failure/resolution failure. This closes the node-local
lifecycle gap; it is not a claim of operator HA or multi-node shared state.

The cross-profile semantic gate was validated on the same arm64 K3s node on
2026-08-05. The canonical `id + ls /` workload ran once under an active
`local-record` cgroup and once as an externally scheduled Pod attributed by the
passive `k8s_cgroup` source. Both graphs completed verification with zero errors
and zero warnings. Their shared semantic projection contained both workload
commands, `execve` events, `runtime_event` nodes, and `runtime_process_event`
edges. Physical PID, cgroup, container, timestamp, and event-count differences
were deliberately excluded; local confidence remained 1.0/0.9 and Kubernetes
confidence remained 0.8.

The [amd64 parity report](benchmarks/amd64-kvm-k3s/k3s-parity.json) repeats that
projection inside the KVM guest. Equivalence means shared workload commands and
runtime-event/process-edge semantics, not identical complete graphs: active
record capture has additional application context that a passive Pod lacks.

## Reliability guarantees

Native `sensor stream` persists accepted batches, retries late bindings and
recovers interrupted processing. Its [spool contract](native-capture-spool.md)
defines capacity, transaction deduplication, missing-file reporting and loss
accounting. These guarantees do not extend to Falco-specific worker recovery,
which is outside this closeout. Shared event ingestion is atomic for both paths.

`/v1/live` reports HTTP liveness; `/v1/ready` and `/v1/health` verify store/schema
availability. Database failure returns 503 and unknown counts are null. Historical
loss is shown separately from database readiness. These checks are not proof of
worker progress or gap-free evidence for each run.

Upgrade and normal guest reboot preserve the historical evidence checked by the
lab gates. Abrupt host power loss, real disk exhaustion and multi-day soak tests
remain separate operational validation, not implied by a green unit test.

## Central service boundary

The central evidence service is architecture-only. See
[central-evidence-service-design.md](central-evidence-service-design.md).

The project does not implement:

- multi-tenancy or billing;
- a generic cluster control plane;
- a scheduler or sandbox lifecycle platform;
- distributed total ordering or exactly-once delivery;
- production object-store/index-store deployment.

## Acceptance commands

```sh
go test ./...
./scripts/accept_telemetry_spool_backpressure.sh
AGENTPROV_ACCEPT_100K_REPORT=/tmp/agentprov-100k.json \
  ./scripts/accept_telemetry_100k_pressure.sh

# Linux/Kubernetes environment gate; defaults to 8 workloads.
AGENTPROV=/path/to/agentprov SENSOR=/path/to/agentprov-sensor \
  AGENTPROV_MULTIWORKLOAD_REPORT=/tmp/agentprov-k8s-multiworkload.json \
  ./scripts/accept_k8s_node_multiworkload.sh

# Linux/Kubernetes informer lifecycle gate.
AGENTPROV=/path/to/agentprov \
  AGENTPROV_K8S_INFORMER_REPORT=/tmp/agentprov-k8s-informer.json \
  ./scripts/accept_k8s_informer_controller.sh

# Same-workload local/Kubernetes semantic parity gate.
AGENTPROV=/path/to/agentprov SENSOR=/path/to/agentprov-sensor \
  AGENTPROV_K8S_PARITY_REPORT=/tmp/agentprov-local-k8s-parity.json \
  ./scripts/accept_k8s_pod_parity.sh
```

Kubernetes parity is environment-gated. Commit compact, sanitized reports when
updating a validated baseline; keep raw captures and credentials outside Git.
For native recovery, TLS discovery and daemon fault gates, use the
[amd64/KVM/K3s runbook](amd64-kvm-k3s.md). Future substrate profiles must earn
`validated` status through an equivalent live gate before advertising coverage.
