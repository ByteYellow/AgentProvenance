# Deployment Modes

English · [简体中文](zh-CN/deployment-modes.md)

Start with the local CLI or a daemon beside a workload. A centralized evidence
service is a separate design, not a prerequisite for either deployment.

## Where the Agent and its tools run

Sandbox integration starts with two questions: where does the Agent make tool
calls, and where do those calls execute? These three arrangements need different
evidence links:

| Arrangement | Example | AgentProvenance collection path |
| --- | --- | --- |
| Agent in Sandbox | A coding Agent and its tools run in one Linux VM or ordinary Pod | Record the session beside the Agent; collect system events from the task's kernel and associate them through process and cgroup identities |
| Agent uses Sandbox | An Agent on a Mac sends a command to a Linux VM | Keep the source session and Tool Call; the authenticated executor records a separate target Run, execution attempt and scope, then delivers its signed evidence |
| Agent in A uses Sandbox B | A containerized Agent delegates an independent command to another executor | Use the same handoff with distinct source and target identities; query from the source call to the remote execution or back from an effect to its recorded caller |

The delivered remote route handles independent native Claude Bash calls. Its
records include Mac and isolated-container callers, plus WSL-to-KVM acceptance.
The container case uses a shared host network and a separate executor workspace.
Sandbox provisioning, scheduling and workload isolation stay with the operator's
platform; AgentProvenance records the execution and its evidence links.

## Choose collection by kernel boundary

Execution placement and isolation technology are separate choices. Kubernetes
places workloads; the selected runtime determines which kernel handles their
system calls. Collection follows that boundary:

- **Native Linux and ordinary containers:** a Sensor in the shared Linux kernel
  observes process, file and network events. Pod/container metadata and cgroups
  identify the workload; a node Sensor can observe several workloads.
- **KVM guests and Firecracker:** the task has a guest kernel. Run the executor
  and Sensor inside that guest; the outer host sees the VM process. Firecracker
  also has a guest-image and evidence-retirement recipe.
- **gVisor:** Sentry handles the sandbox's system calls. Its SecCheck stream feeds
  a receiver outside Sentry, preserving inner task identities and lifecycle
  generations. The host's Sentry process remains a separate identity.

Code, browser and desktop sandboxes describe the tools available to an Agent,
not the kernel boundary. Browser and Notebook adapters add page, operation and
request context to explain work inside long-lived processes. Linux system
capture is configured separately. The scope table below lists current entries
and the remaining desktop and platform-specific work.

## First experience: portable replay

The [v0.10.1 release](releases/v0.10.1.md) provides CLI archives for
Linux and macOS on amd64/arm64. `agentprov demo` opens a local gallery containing
twelve signed replays, including one synthetic example, and two optional
evaluator guides, with the same
visual theme as the dashboard. Guides render locally with a section outline,
images, tables and code-copy controls. See the [Quickstart](../README.md#quickstart)
and [complete demo index](../demo/README.md).

Replay uses an isolated temporary store and does not execute the captured actions.
Evaluator execution and live Linux capture retain their separate requirements.
Archive acceptance covers replay and cleanup. Live collection requirements are
listed with each capture entry below.

## Choose a capture entry

Build the current source for the v1.0 integrations in this table; they are not
part of the v0.10.1 download. Existing `launch`, `record` and replay commands
keep their entry points.

| Workload | Where collection runs | Setup |
| --- | --- | --- |
| Native Claude command in another sandbox | Caller on Mac or Linux; authenticated executor and native Sensor inside the target Linux environment | [Execution handoff](execution-handoff.md): SSH loopback forwarding, protected route configuration, cgroup v2 and BPF access for native capture |
| Browser task | Optional Python entry owns a sandboxed Chromium context | [Browser context](browser-context.md): Python 3.12+, pinned Playwright/browser, native page/request references and optional stdio MCP |
| Notebook task | Optional recorder beside the client, or a stdio MCP server owning one kernel | [Notebook context](notebook-context.md): Python 3.11+ for MCP, pinned Jupyter dependencies and native request/output references |
| gVisor workload | SecCheck receiver outside Sentry, with a registered sandbox instance and lifecycle generation | [gVisor collection](gvisor-seccheck.md): pinned runsc, private Unix socket and durable spool; ARM64 and amd64 systrap reception, fault recovery and restore/clone acceptance |
| Firecracker guest image | systemd starts the executor and Sensor inside the guest | [Guest recipe](execution-handoff.md#guest-service-and-image): pinned image/kernel builders, private configuration and persistent evidence volumes; amd64 boot, native capture, signed delivery and retirement accepted |

Application entries retain native identities in both `basic` and `detailed`.
Text, screenshots and HAR have independent retention controls. Private source
captures and the retained evidence store have separate lifecycles; configure
both when handling sensitive workloads.

Mac can record application context, call a remote Linux executor and inspect or
share the resulting evidence. Native kernel probes run in Linux. Ordinary
shared-kernel Kubernetes Pods use the node sensor; guest kernels and Sentry use
their respective collection entries. A host runtime PID is not the inner task's
process identity.

### Workload and platform scope

Choose the operation entry and the runtime collector separately. The
[ARM64 candidate record](benchmarks/v1.0-candidate/README.md) and
[amd64 results](benchmarks/v1.0-amd64/README.md) identify the combinations actually
exercised, their binary hashes and capture coverage.

| Scenario | Current entry and evidence | Scope |
| --- | --- | --- |
| Coding, command-line data analysis and automated tests | `launch` / `record`, tool calls, independent command scopes, process/file/network evidence and signed artifacts | Native Linux collection; the remote Claude route supports independent Bash calls |
| Notebook / code interpreter | Jupyter session, kernel, request and output identities; cell text, results and optional chart attachments | The supplied recorder and stdio MCP entry; shared-kernel system events retain process/scope attribution |
| Browser / web research | Chromium page, frame, operation and request identities; text, screenshots, downloads and optional HAR | The supplied Playwright and stdio MCP entries; real Agent acceptance used application context with the native Sensor off |
| Linux desktop / office automation | Existing system collection can observe processes, files and network activity | GUI actions, window identities and before/after screenshots still need a desktop adapter and acceptance |
| Long-running and branching tasks | Sessions, execution attempts, durable delivery and lifecycle generations | Pinned gVisor memory restore and two-clone evidence continuity; browser login and external connection recovery require separate workflow checks |
| RL / batch evaluation | Per-run recording, batch manifests, EvalContext and offline evaluator results | Scheduling, training, rewards and sandbox provisioning remain with the calling platform |
| Enterprise internal platform | Authenticated local APIs, node collection, signed evidence and offline sharing | Central multi-tenant storage, SSO, quotas and HA remain outside the implemented local service |

The following integration boundaries matter when choosing a sandbox platform:

- **Native Linux, ordinary Pods and KVM guests:** use the Sensor in the kernel
  that executes the task. The Pod informer tracks containers and cgroups; it
  does not select an inner collector from a Kubernetes `RuntimeClass` handler.
- **gVisor and Firecracker:** gVisor uses a separate SecCheck producer;
  Firecracker uses the native executor inside the guest. The remote executor's
  built-in capture mode is `native`, so routing a remote tool call into Sentry
  needs its own execution-entry integration. Restore/clone acceptance is for
  gVisor; Firecracker acceptance covers boot, execution, delivery and retirement.
- **Kata, Cloud Hypervisor and other guest runtimes:** the guest collection
  approach is reusable. Image/kernel preparation, instance identity, transport
  and lifecycle acceptance remain runtime-specific work.
- **Sandbox platforms and worker pools:** E2B, OpenSandbox, SIG Agent Sandbox,
  OpenKruise, AIO and actor-based platforms have no dedicated adapter here.
  Integrators can use the existing execution and evidence interfaces, but must
  supply task-to-instance registration and lifecycle notifications. A worker
  Pod alone is too coarse an identity for several independent sandbox actors.

Browser and Notebook readers and cross-run navigation are available in the
[candidate preview](../previews/v1.0-reader/README.md). The [demo guide](demo-library.md)
groups examples by investigation. Formal Dashboard integration and site
publication await the layout review.

## 1. Library / CLI-only Recorder

This is the default entry point for RL, benchmark, evaluator, CI, and local
red-team harnesses.

Shape:

```text
agent / evaluator / batch job
  -> agentprov record -- <command>
  -> local SQLite + local content-addressed objects
  -> evidence manifest / EvalContext / trajectory signals
```

Expected properties:

- one Go binary;
- optional thin Python helper package, installable locally with
  `pip install -e .`;
- no long-running service required;
- no framework integration required;
- default capture stays lightweight: process, file diff, artifact, exit,
  resource, and summary runtime evidence;
- on Linux, optional supervised capture can pair `record` with a per-node
  `sensor stream`; the recorder creates a real cgroup scope and kernel events
  from the subtree correlate back by `cgroup_id`;
- every trajectory can have its own `run_id`;
- batch jobs can use `agentprov record batch --file jobs.jsonl --json` to get
  one `agentprovenance.record_batch/v1` manifest across many trajectories;
- `agentprov evidence batch-summary --shard/--job/--run` lets a pipeline query
  stored batch status without parsing stdout logs;
- `agentprov signal batch-context --batch/--shard/--runs` exports matching
  trajectories as EvalContext JSONL for reward, filtering, or benchmark
  consumers;
- Python users can define offline evaluator functions with `Registry` and
  `@rule`; those functions return `EvalSignal` records such as reward
  features, penalties, dataset labels, and quality signals;
- Python users can call `run_batch_pipeline(...)` to run the Deploy 1 offline
  loop in one step: record batch, export EvalContext records, evaluate Python
  rules, import EvalSignal reports, export batch forensics, and return a
  summary;
- `agentprov signal import-batch --file reports.jsonl` validates JSONL
  `EvalReport` batches after offline scoring, so RL pipelines do not need one
  import command per trajectory;
- `agentprov forensics export-batch --batch/--shard/--latest` writes one
  sha256-verified batch audit bundle with batch summary, per-run forensics
  refs, optional EvalContext records, and replay/query commands;
- outputs are JSON-friendly and batch-friendly.

Boundary:

- this mode does not provide shared query service, central retention, or
  multi-host telemetry aggregation;
- it is the easiest path for RL pipelines because the pipeline keeps ownership
  of scheduling, reward, ranking, and dataset policy.
- online security actions such as deny, kill, quarantine, or taint are not
  required for RL mode; they are opt-in controls for security deployments.
- if no sensor is enabled, synthetic scope ids plus process/file evidence are
  expected; this is not a degraded sensor path, it is the correct lightweight
  record-only path.

## 2. Sidecar / Local Daemon

This is the medium-complexity shape for sandbox workers, CI workers, local
security harnesses, or teams that need local ingest/query APIs.

Shape:

```text
agent / sandbox worker / CLI / SDK
  -> local agentprov daemon
  -> spool / backpressure / retention
  -> local query + graph verify + forensics API
```

Expected properties:

- daemon owns SQLite, object store, correlation, policy, risk, response, graph
  verification, forensics export, and telemetry spool;
- per-node native `sensor stream` can run beside the daemon or local store and
  feed normalized runtime events through the same ingest/correlation path;
- `accept_k8s_node_multiworkload.sh` is the environment gate for the actual
  sensor DaemonSet observing a configurable number of independent pod cgroups;
  it builds/imports the sensor image, deploys the DaemonSet, resolves
  pod/container metadata to kernel cgroups, ingests stdout JSONL, and verifies
  one evidence graph;
- `agentprov sandbox watch` is the node-local `client-go` informer companion:
  it List/Watches only Pods scheduled on its node, maintains exact
  container-to-cgroup bindings across restart/delete, and requires only Pod
  `get/list/watch` RBAC;
- CLI and Python helpers act as clients;
- raw telemetry can be queued and drained without blocking the control/query
  path;
- spool capacity is bounded independently by queued batch count, total queued
  bytes, and per-batch bytes;
- `telemetry producer-health` reports spool state, drops, source counts, and
  correlation coverage;
- local APIs expose observability, timeline, graph explain, security evidence,
  evidence manifest, forensics export, and signal import.

Boundary:

- this is still local-first;
- it is not a multi-tenant central service;
- it should be deployable beside a worker without requiring Kubernetes or a
  central database.
- the K8s gates prove one-node producer placement, passive attribution, and
  informer lifecycle handling. A full operator (CRDs, HA/leader election,
  upgrade control) and cluster-wide evidence service remain outside this
  mode's implemented boundary.

For **KVM guests and K3s**, the [deployment runbook](amd64-kvm-k3s.md) provides
the validated systemd collector and node-local attribution setup. A KVM guest
uses `local-record`, with the sensor observing the guest kernel. Native capture
has its own [persistent-spool contract](native-capture-spool.md); the older
JSONL/Falco worker does not inherit those restart guarantees. Do not run two
ingesting collectors over the same observations into one store.

The daemon's `/v1/live` endpoint checks HTTP liveness, while `/v1/ready` and
`/v1/health` check database/schema availability. Unknown counts remain null on
storage failure. Readiness and historical evidence coverage are different
properties; neither endpoint proves every background worker is progressing.

### API authentication and browser access

For existing deployments, see the [v0.10.1 upgrade guide](upgrading-v0.10.1.md)
for token setup, HTTP execution defaults, signed imports and migration commands.

`daemon serve` requires a bearer token by default. It reuses or generates
`<data-dir>/auth-token` with mode `0600`; `--auth-token` or
`AGENTPROV_DAEMON_TOKEN` can supply an operator-managed token. CLI clients must
use the same `--data-dir`, or set `AGENTPROV_DAEMON_TOKEN` explicitly. Only GET
`/v1/health`, `/v1/ready`, and `/v1/live` are anonymous health checks.

Writes with a body require `Content-Type: application/json`; empty DELETE and
POST requests may omit it. Browser requests must have a matching Origin, and
write requests accept only `Sec-Fetch-Site: same-origin`, `none`, or an absent
header. Origin checks use the direct HTTP/TLS connection, not untrusted
`X-Forwarded-*` headers. Authenticated CLI/SDK clients can use remote hosts and
custom DNS names without browser headers.

`--insecure-open` explicitly disables authentication. In that mode, all
non-health requests require a Host naming localhost, a literal IP, or the
hostname configured with `--listen`. Arbitrary DNS names are rejected on reads
as well as writes. Keep this mode restricted to trusted local development.

Use `POST /v1/evidence/manifest` with `{"run_id":"<run_id>"}` to materialize an
evidence manifest. Ordinary GET remains read-only. The legacy
`GET ...?materialize=1` form requires a valid bearer token; open-mode callers
must switch to POST. The CLI's `evidence manifest --materialize` handles this
automatically.

### Docker session compatibility

The compatibility `lease` / `session` / `api` commands use Docker-backed
workspaces. On Linux and macOS, new and resumed sessions default to the CLI or
daemon process's effective UID:GID, overriding the image's `USER`. This keeps
the bind-mounted workspace writable without granting `CAP_DAC_OVERRIDE` or
making it world-writable. A non-root default user gets `HOME=/tmp` inside its
container for caches; install dependencies in a workspace virtual environment
or project directory. All Linux capabilities remain dropped and
`no-new-privileges` remains enabled.

Images that require a particular account can set `user: "1000:1000"` (or a named
image user) in the task YAML. An explicit user keeps the image's home environment;
its UID/GID must have access to the workspace. With rootless Docker or user
namespace remapping, use the container identity mapped to the workspace owner
(typically `user: "0:0"` for the rootless daemon owner's files). Build packages requiring root
during image construction, before starting a session.

Docker 29.0-29.2 requires at least API 1.44, above the bundled client's default
maximum of 1.43 ([Docker API matrix](https://docs.docker.com/reference/api/engine/#api-version-matrix)).
For those servers, run these compatibility commands with
`DOCKER_API_VERSION=1.44`; session creation, execution and cleanup have been
tested on Docker 29.1.3 with this override. The override disables API negotiation;
use it only for a server that needs it. Normal `record`, `launch` and replay do not use this
Docker session client.

## 3. Central Evidence Service (design only)

This is the later enterprise shape for security, audit, SRE, compliance, and
incident review.

It is intentionally **not implemented** in the current project scope. The
component boundaries, failure model, capacity signals, and trust assumptions are
documented in [central-evidence-service-design.md](central-evidence-service-design.md).

Shape:

```text
many workers / sidecars / collectors
  -> central evidence ingest
  -> object storage + retention + auth
  -> query API + UI + audit export
```

Expected properties:

- shared ingest and query service;
- object storage for forensics and content-addressed evidence objects;
- retention, auth, tenant isolation, and audit controls;
- UI/API for investigation and evidence review;
- integration points for Falco/Tetragon/LoongCollector, webhook, Feishu,
  DingTalk, CI, and enterprise security workflows.

Boundary:

- this is not the default RL adoption path;
- it should reuse the same evidence schemas and graph invariants from the
  local modes;
- it requires explicit productization work rather than hidden assumptions in
  the local CLI.
- multi-tenancy, billing, and a complex cluster control plane are out of scope.

## Design Rule

The three modes share one evidence model:

```text
Execution Context
  -> Evidence Ingest
  -> Runtime Causality Graph
  -> Git-like Provenance DAG
  -> Evidence Query / Risk / Replay / Audit
```

Only the deployment boundary changes. RL users should be able to stay in
Library / CLI-only mode. Enterprise users can move to sidecar or central service
mode when they need shared operations.
