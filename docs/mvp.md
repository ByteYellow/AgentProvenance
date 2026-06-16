# agentprovenance MVP

`agentprovenance` is a CLI-first single-node Agent Computer Control Plane.

The first binary is `agentprov`. It manages local leases, Docker-backed sandbox
sessions, preview URL proxies, runtime/template registries, directory
snapshots, prepared workspace forks, structured Agent Computer API calls,
telemetry, MVP policy decisions, provenance traces, forensics bundles, and
run/session/node-level cost counters. It can run directly against local state or
as a client for `agentprov daemon serve`, where the daemon owns SQLite, the runtime
driver, scheduler, state store, and Docker adapter.

## Quick path

```sh
agentprov init
agentprov lease create --task examples/tasks/bugfix.yaml
agentprov session create --lease <lease_id>
agentprov session list
agentprov session inspect <session_id>
agentprov exec <session_id> --stream -- sh -lc 'echo hello > hello.txt'
agentprov runtime list
agentprov template build --task examples/tasks/bugfix.yaml --name bugfix
agentprov snapshot stack --template bugfix
agentprov snapshot create <session_id> --type directory --path /workspace --name ready
agentprov snapshot list
agentprov snapshot inspect ready
agentprov snapshot plan ready
agentprov fork ready --count 2
agentprov snapshot resume ready --lease <lease_id>
agentprov rollout start --task examples/tasks/bugfix.yaml --snapshot ready --runtime docker --fanout 3 \
  --top-k 2 \
  --strategy "probe::test -f hello.txt && echo passed::probe=test -f hello.txt && echo passed::score=contains:passed::artifact=probe.log" \
  --strategy "score::printf 42::probe=printf 42::score=number::artifact=score.txt" \
  --strategy "slow::sleep 1; echo passed::probe=echo 1::score=contains:passed::artifact=slow.log"
agentprov rollout winner run-demo-bugfix
agentprov attempt best-of --snapshot ready --max-fanout 2 --top-k 1 --max-cost 1 --early-stop \
  --strategy "probe::printf 42::probe=printf 42::budget=2::score=number::artifact=probe.txt" \
  --strategy "full::test -f hello.txt && echo passed::probe=test -f hello.txt && echo 1::budget=5::score=contains:passed::artifact=hello.txt"
agentprov policy test examples/events/metadata-egress.jsonl
agentprov policy decisions --run run-demo-bugfix
agentprov api write-file <session_id> --path notes.txt --content hello
agentprov telemetry list --session <session_id>
agentprov graph trace --run run-demo-bugfix
agentprov forensics export run-demo-bugfix
agentprov cost sample <session_id>
agentprov cost show run-demo-bugfix
agentprov bench overcommit --sessions 20 --idle-ratio 0.8 --bursty
```

Daemon-backed equivalent:

```sh
agentprov daemon serve --listen 127.0.0.1:8574
export ACF_DAEMON_URL=http://127.0.0.1:8574
agentprov lease create --task examples/tasks/bugfix.yaml
agentprov session create --lease <lease_id>
agentprov exec <session_id> --stream -- sh -lc 'echo hello'
```

## Demos

### demo_streaming_terminal

```sh
lease_id=$(agentprov lease create --task examples/tasks/bugfix.yaml)
session_id=$(agentprov session create --lease "$lease_id")
agentprov exec "$session_id" --stream -- sh -lc 'echo hello'
```

### demo_preview_url

```sh
./scripts/demo_preview_url.sh
```

This starts a tiny HTTP service inside the sandbox and exposes it through a
host-local preview URL. `port list` shows the proxy and `port close` shuts it
down without leaving a residual proxy process.

### demo_snapshot_fanout

```sh
./scripts/demo_snapshot_fanout.sh
```

Equivalent manual flow:

```sh
agentprov exec "$session_id" --stream -- sh -lc 'echo base > hello.txt'
agentprov snapshot create "$session_id" --type directory --path /workspace --name ready
agentprov snapshot list
agentprov snapshot inspect ready
agentprov fork ready --count 3
resume_lease_id=$(agentprov lease create --task examples/tasks/bugfix.yaml)
agentprov snapshot resume ready --lease "$resume_lease_id"
```

Each forked attempt prints an `attempt_id`, workspace path, and `fork_ms`.
Modify files under one attempt workspace and verify the other attempt workspaces
do not change. `snapshot resume` copies the directory snapshot back into a new
workspace and starts a new running Docker session with parent snapshot lineage.

### demo_runtime_capabilities

```sh
agentprov runtime list
agentprov runtime inspect docker
agentprov runtime inspect firecracker
```

The Docker backend reports `exec`, `stop`, `snapshot`, `fork`, and `resume` as
available, with `memory_snapshot=false`. Firecracker, gVisor, and bubblewrap are
registered as capability-gated stubs and do not report unavailable features as
usable.

### demo_snapshot_stack

```sh
agentprov template build --task examples/tasks/bugfix.yaml --name bugfix
agentprov snapshot stack --template bugfix
agentprov snapshot list
agentprov snapshot inspect <ready_snapshot_id>
agentprov snapshot plan <ready_snapshot_id>
agentprov snapshot plan <ready_snapshot_id> --policy smallest-delta
agentprov graph trace --run run-demo-bugfix
```

This records `template -> ready snapshot -> attempt workspace` lineage. Use
`snapshot inspect <snapshot_id>` to see kind, parent, manifest hash, status, and
storage bytes. `snapshot plan` and `graph trace` expose the selected snapshot,
copy plan, planner score, source policy, candidate count, semantic/physical
snapshot type, file-level delta, reason, and DAG edges for fork/resume
operations. Source policy currently supports `latest-ready`, `smallest-delta`,
`local`, and `untainted`. `graph trace --run <run_id>` keeps snapshot and
planner output scoped to that run, so parallel rollouts do not leak unrelated
snapshot decisions into the evidence chain.

### demo_best_of_forks

```sh
./scripts/demo_best_of_forks.sh
```

Equivalent manual flow:

```sh
agentprov attempt best-of --snapshot ready \
  --max-fanout 2 --top-k 1 --max-cost 1 --early-stop \
  --strategy "probe::printf 42::probe=printf 42::budget=2::score=number::artifact=probe.txt" \
  --strategy "full::test -f hello.txt && echo passed::probe=test -f hello.txt && echo 1::budget=5::score=contains:passed::artifact=hello.txt"
```

The command forks one workspace per strategy. When strategy metadata includes
`probe=<cmd>` and `--top-k` or `--early-stop` is set, AgentProvenance first executes the
cheap probe command, ranks probe results, runs the full command only for the
top-k candidates, and marks the rest as `pruned`. It records exit code, wall
time, output summary, score, `risk_status`, `budget_exceeded`, and the winning
attempt. Strategy metadata can include `probe`, `budget`,
`score=contains:<text>` or `score=number`, and `artifact`. Winner selection
prefers clean, within-budget attempts, then score, then lower cost. Cost output
includes fanout cost and saved cost when early stop, max fanout, or probe
pruning avoids full command execution.

### demo_rollout_control_plane

```sh
agentprov snapshot stack --task examples/tasks/bugfix.yaml
ACF_IO_MAX_FANOUT_PER_LOWER=100 ACF_BURST_MAX_INFLIGHT=2 \
  agentprov rollout start --task examples/tasks/bugfix.yaml --snapshot ready --runtime docker --fanout 3 \
  --top-k 2 \
  --strategy "probe::test -f README.md && echo passed::probe=test -f README.md && echo passed::score=contains:passed::artifact=probe.log" \
  --strategy "score::printf 42::probe=printf 42::score=number::artifact=score.txt" \
  --strategy "slow::sleep 1; echo passed::probe=echo 1::score=contains:passed::artifact=slow.log"
agentprov rollout attempts <rollout_id>
agentprov rollout winner <rollout_id>
agentprov evidence process
agentprov graph trace --run run-demo-bugfix
agentprov cost show run-demo-bugfix
```

This is the v0.1 Agent Rollout Control Plane path. It starts from a ready
snapshot, forks attempt workspaces, creates one short-lived Docker session and
one `tool_call` per admitted strategy, requires BurstGuard admission before
command execution, switches the container from `think` to `tool` CPU profile,
writes compact evidence, materializes `rollout -> attempt -> tool_call ->
session` graph edges asynchronously, and promotes the winning attempt through
the promotion barrier. Attempt tables and `cost show` expose risk, budget, score,
and cost so the winner is explainable.

### demo_metadata_egress_quarantine

```sh
./scripts/demo_policy_quarantine.sh
./scripts/demo_egress_proxy.sh
```

Equivalent manual flow:

```sh
agentprov egress check --run run-demo-bugfix --session <session_id> --dst-ip 169.254.169.254 --host metadata.local
agentprov policy decisions --run run-demo-bugfix
```

The metadata IP event produces a `quarantine` decision and marks the local
session as quarantined.

### demo_egress_proxy

```sh
./scripts/demo_egress_proxy.sh
```

This starts a Docker session on a session-scoped internal bridge network with an
acf egress proxy sidecar, adds `example.com` to the allowlist, verifies an
allowed HTTP request through the sidecar, verifies direct egress bypass failure,
verifies metadata IP denial, and records a redacted credential injection event.

### demo_cost_per_run

```sh
./scripts/demo_cost_accounting.sh
```

Equivalent manual flow:

```sh
agentprov cost sample <session_id>
agentprov cost show run-demo-bugfix
```

The output includes run-level `active_cpu_seconds`, `idle_seconds`,
`wall_seconds`, `snapshot_bytes`, `policy_block_count`, `quarantine_count`,
`overcommit_ratio`, `active_cpu_debt`, `queue_pressure`, and `cost_per_run`,
plus session-level and node-level cost rows. CPU and idle cost now come from
10s/60s resource windows, while raw Docker stats are short-retention input.

### demo_provenance_trace

```sh
./scripts/demo_provenance_trace.sh
```

This records file, artifact, process, tool call, policy decision, and forensics
bundle data, then prints `telemetry list` and `graph trace` output.

### demo_baseline_pool_node

```sh
agentprov baseline learn --template bugfix --run run-demo-bugfix
agentprov baseline check --template bugfix --run run-demo-bugfix
agentprov pool create --template bugfix --size 2
agentprov pool status
agentprov node register --address localhost --runtime docker --cpu 8 --memory-mb 8192
agentprov node list
agentprov scheduler status
```

Warm pool entries track hit count, cold-start savings, memory, disk footprint,
GDSF priority, and eviction reason. For seeded demo workspaces:

```sh
agentprov pool create --template bugfix --size 3 --seed-workspace ./seed --max-size 2
agentprov pool status
```

### demo_active_cpu_overcommit

```sh
agentprov bench overcommit --sessions 20 --idle-ratio 0.8 --bursty
```

This simulation uses the same single-node scheduler admission function as
`session create`. It shows how idle-heavy sessions are admitted using
`active_cpu_request + idle_cpu_request * idle_discount`, while memory is not
overcommitted. The bursty mode simulates periodic active-CPU spikes and reports
`effective_cpu`, `active_cpu_debt`, `burst_risk`, overcommit ratio, memory
pressure, and structured reject reason.

In daemon mode, resource sampling is bounded and windowed:

```sh
agentprov daemon serve \
  --sample-interval 5s \
  --sample-limit 64 \
  --sample-timeout 2s \
  --raw-retention 10m \
  --max-raw-samples 512
```

Each sampling round writes short-lived raw samples, aggregates them into
`session_resource_windows` and `node_resource_windows`, then applies raw sample
retention. Scheduler admission reads the window tables rather than scanning
unbounded raw samples.

BurstGuard adds a forward-looking admission gate for synchronized tool phases:
`exec` must reserve burst budget before the session can switch from `think` to
`tool`. If too many sessions enter tool phase at once, the default policy
rejects before CPU weight is raised. Set `ACF_BURST_OVERFLOW_POLICY=delay` and
`ACF_BURST_QUEUE_TIMEOUT_MS=<ms>` to queue briefly until a burst slot is
released.

### demo_cpu_weight_control

```sh
./scripts/demo_cpu_weight_control.sh
```

This verifies the v0.1 CPU time-sharing control loop. A new Docker session is
placed in the low-priority `think` profile, tool execution switches the
container to `tool`, and `exec` returns it to `think` after the command exits.
The demo checks Docker `CpuShares` directly and prints `cpu_weight_set`
telemetry events.

For a larger local rehearsal:

```sh
SESSIONS=50 BURST_MAX_INFLIGHT=4 ./scripts/demo_v01_50_concurrency.sh
```

The output includes admitted/rejected exec counts, `burst_reject` telemetry,
and `scheduler status` fields such as `tool_phase_inflight`,
`burst_reserved_cpu`, `burst_debt`, and `burst_reject_count`. Delay mode records
superseded queue attempts as `delayed` and admits the final reservation when a
slot becomes available.

### demo_ioaware_snapshot_planner

```sh
./scripts/demo_ioaware_snapshot_planner.sh
```

This creates hot metadata paths such as `.git`, `node_modules`, and `.venv`,
then shows `snapshot plan` output with `selected_policy`, `candidate_count`,
`semantic_type`, `physical_type`, file-level delta, `copy_up_risk`,
`metadata_ops_estimate`, `shared_lower_fanout`, `io_fanout_budget`,
`upperdir_shard`, `upperdir_device`, and `hot_metadata_paths`. It also
demonstrates I/O fanout rejection with
`ACF_IO_MAX_FANOUT_PER_LOWER=1` and uses `graph trace` to show why overlay was
not selected.

## MVP limits

- Docker must be running for `session`, `exec`, and `process` commands.
- CPU weight control uses Docker `ContainerUpdate` / `CpuShares`. On Linux
  cgroup v2 this maps to cgroup CPU weight behavior; a direct node-agent
  `cpu.weight` writer is a future Linux-specific hardening path.
- BurstGuard rejects excess synchronized tool phases by default and supports a
  bounded delay/queue mode with `ACF_BURST_OVERFLOW_POLICY=delay`.
- IO-aware snapshot planning estimates copy-up and metadata risk. It does not
  yet create real OverlayFS/reflink/COW mounts.
- Directory snapshot/fork/resume is supported; memory snapshots are
  intentionally not.
- Runtime backends are capability-gated. Docker is active; Firecracker, gVisor,
  and bubblewrap are stubs.
- Scheduler/admission is single-node and conservative. Multi-node placement is
  still a follow-up.
- `port expose` is an HTTP preview proxy, not a raw TCP tunnel.
- Egress control currently covers HTTP/HTTPS proxy workflows and blocks direct
  outbound traffic from the Docker sandbox bridge. Raw TCP protocol policy is
  still a follow-up.
- The node registry is local metadata. Multi-node scheduling is still a
  follow-up.
