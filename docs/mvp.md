# AgentProvenance MVP

`AgentProvenance` is a CLI-first Git-like provenance control plane for
sandboxed agent execution.

The command-line interface is `agentprov`. The core MVP manages execution
context binding, process/tool-call traces, runtime telemetry correlation,
file diffs, artifact refs, content-addressed provenance objects, risk signals,
baseline deviations, response actions, and audit evidence for each trajectory.
Local leases, Docker-backed sessions, directory snapshots, forks, and fanout
demos exist as substrate/stress-test support. They are not the product identity.
External RL pipelines, evaluators, or agent harnesses own final reward,
penalty, filtering, and selection decisions.

Phase 1 focuses on the immutable execution ledger and state-diff security loop:
`Execution Context -> Evidence Ingest -> Runtime Causality Graph -> Provenance
DAG -> State Diff/Blame -> Risk/Deviation -> Response/Taint -> Replay /
Trajectory / Audit Manifest`.

This is not an RL runtime, generic telemetry collector, distributed scheduler,
or reward/evaluator decision maker. Coding agents and autonomous tool-using
agents are the primary target. RL-style rollout and evaluator pipelines are
supported as high-concurrency audit and debugging consumers of the graph, not
as the only runtime target. The RL-facing value is observability over trajectory
behavior and expectation deviations, not AgentProvenance choosing a winner.

## Phase 1 risk boundaries

Phase 1 is not a full state-management or distributed merge system. It keeps
three hard boundaries:

| Risk | Phase 1 approach | Boundary |
|---|---|---|
| Storage/performance | Sparse snapshot semantics, incremental file diff, and content-addressed artifacts | Do not snapshot every step. Do not claim memory snapshot support. |
| Non-filesystem state | `ExternalEffectRecord` stores external intent, target, dry-run/mock/allowlist mode, policy decision, and optional compensation reference | External API, database, queue, and message side effects are provenance and gate records only. No rollback guarantee for the real world. |
| Merge conflict | Branch/fanout demos use taint and response gates to prevent unsafe reuse | No arbitrary branch auto-merge. Phase 1 only supports diff, blame, local candidate marking, response-gate checks, and quarantine. |

Preview URL, egress proxy, credential injection, warm pool, node metadata, and
resource scheduling commands are kept as experimental local controls. They are
useful for future drivers, but they are not the main v0.1 product surface.
Baseline deviation records, risk signals, and response action records are part
of the main security evidence model.

## Core quick path

```sh
agentprov init
agentprov adapter list
agentprov adapter inspect filtered-jsonl --json
agentprov record --run run-record-demo --workdir /tmp/agentprov-record-demo -- \
  sh -lc 'printf "value = 2\n" > app.py && echo artifact > artifact.txt'
agentprov graph explain --run run-record-demo --file app.py --json
scripts/demo_telemetry_jsonl.sh
agentprov observe summary --run run-telemetry-jsonl-demo
agentprov observe coverage --run run-telemetry-jsonl-demo
agentprov observe scopes --run run-telemetry-jsonl-demo
agentprov observe event --run run-telemetry-jsonl-demo --event <event_id>
agentprov observe process --run run-telemetry-jsonl-demo --process <process_id>
agentprov observe flow --run run-telemetry-jsonl-demo
agentprov telemetry batches --run run-telemetry-jsonl-demo
agentprov telemetry list --run run-telemetry-jsonl-demo
agentprov timeline --run run-telemetry-jsonl-demo
agentprov timeline --run run-telemetry-jsonl-demo --json
agentprov policy test examples/events/metadata-egress.jsonl
agentprov security risks --run run-demo-bugfix
agentprov security deviations --run run-demo-bugfix
agentprov security responses --run run-demo-bugfix
agentprov graph trace --run run-demo-bugfix
agentprov graph refs --run run-demo-bugfix
agentprov graph log --run run-demo-bugfix
agentprov graph materialize --run run-demo-bugfix
agentprov graph objects --run run-demo-bugfix
agentprov graph objects --run run-demo-bugfix --limit 50 --json
agentprov graph objects --run run-demo-bugfix --limit 50 --cursor <next_cursor> --json
agentprov graph verify --run run-demo-bugfix
agentprov graph verify --run run-demo-bugfix --json
agentprov graph replay --run run-demo-bugfix
agentprov graph replay --run run-demo-bugfix --json
agentprov graph trajectories --run run-demo-bugfix --json
agentprov graph diff --run run-demo-bugfix --file calculator.py
agentprov graph diff --run run-demo-bugfix --file calculator.py --json
agentprov graph blame --run run-demo-bugfix --file calculator.py
agentprov graph blame --run run-demo-bugfix --file calculator.py --json
agentprov graph explain --run run-demo-bugfix --file calculator.py
agentprov graph explain --run run-demo-bugfix --file calculator.py --json
agentprov graph explain --run run-demo-bugfix --file calculator.py --depth 4 --limit 200 --json
agentprov graph explain --run run-demo-bugfix --file calculator.py --depth 4 --limit 200 --cursor <next_cursor> --json
agentprov graph explain --tool-call <tool_call_id>
agentprov graph explain --risk <policy_decision_id> --json
agentprov effect record --run run-demo-bugfix --type api_call --target api.example.com/v1/tickets --mode dry-run --decision audit
agentprov effect list --run run-demo-bugfix
agentprov telemetry bind --run run-demo-bugfix --session <session_id> --attempt <attempt_id> --tool-call <tool_call_id> --process <process_id> --container-id <container_id> --cgroup-id <cgroup_id> --pid <pid>
agentprov telemetry ingest --raw-event raw-execve-1 --process <process_id> --type execve --payload '{"argv":["./test_calculator.sh"]}'
agentprov telemetry ingest --raw-event raw-execve-pid-child --pid <pid> --type execve --payload '{"argv":["./async_child.sh"]}'
agentprov telemetry bindings --run run-demo-bugfix
agentprov telemetry list --run run-demo-bugfix --type execve
agentprov timeline --run run-demo-bugfix --tool-call <tool_call_id> --json
```

Machine-checkable Phase 1 gate:

```sh
./scripts/accept_phase1.sh
```

The acceptance script runs a branch-heavy coding-agent stress scenario and asserts
telemetry correlation, external effect recording, quarantine/taint,
response-gate eligibility, `graph verify`, JSON verify, JSON replay, JSON
trajectory evidence, JSON diff, and JSON blame semantics.
It also verifies that an explicit `telemetry bind` receiver can map a raw
PID-only async child event back to the same `ToolCallScope`.

Daemon-backed equivalent:

```sh
agentprov daemon serve --listen 127.0.0.1:8574
export AGENTPROV_DAEMON_URL=http://127.0.0.1:8574
agentprov lease create --task examples/tasks/bugfix.yaml
agentprov session create --lease <lease_id>
agentprov exec <session_id> --stream -- sh -lc 'echo hello'
```

## Experimental controls

These commands remain documented for local experiments, but they should not be
read as the core AgentProvenance contract yet:

```sh
agentprov api write-file <session_id> --path notes.txt --content hello
agentprov telemetry list --session <session_id>
agentprov policy test examples/events/metadata-egress.jsonl
agentprov policy decisions --run run-demo-bugfix
agentprov security risks --run run-demo-bugfix
agentprov security deviations --run run-demo-bugfix
agentprov security responses --run run-demo-bugfix
agentprov forensics export run-demo-bugfix
agentprov cost sample <session_id>
agentprov bench overcommit --sessions 20 --idle-ratio 0.8 --bursty
agentprov lease create --task examples/tasks/bugfix.yaml
agentprov session create --lease <lease_id>
agentprov exec <session_id> --stream -- sh -lc 'echo hello > hello.txt'
agentprov snapshot create <session_id> --type directory --path /workspace --name ready
agentprov fork ready --count 2
agentprov snapshot resume ready --lease <lease_id>
agentprov rollout start --task examples/tasks/bugfix.yaml --snapshot ready --runtime docker --fanout 3
agentprov rollout winner run-demo-bugfix
agentprov attempt best-of --snapshot ready --max-fanout 2 --top-k 1 --max-cost 1 --early-stop
```

## Demos

### demo_coding_agent_best_of_n

```sh
./scripts/demo_coding_agent_best_of_n.sh
./scripts/accept_phase1.sh
```

This is the main AgentProvenance demo. It creates a clean coding workspace,
snapshots it, forks five attempts, runs different repair strategies, exports
patch artifacts, ingests raw runtime telemetry without `tool_call_id`,
correlates it through ToolCallScope bindings, quarantines one risky failed
branch, marks the passing candidate as locally promotable, then runs `graph trace`, `graph refs`,
`graph log`, `graph materialize`, `graph objects`, `graph verify`, `graph replay`, `graph replay
--json`, `graph objects --json`, `graph verify --json`, `graph trajectories --json`, `graph diff`,
`graph diff --json`, `graph blame`, and `graph blame --json` to expose
per-trajectory evidence for external evaluators, verify graph integrity,
reconstruct a plan-only replay, emit structured verify/replay/trajectory/diff/blame
manifests, and attribute file changes.

Expected output / acceptance:

- `telemetry list --type execve` shows a raw runtime event with
  `correlation=process_id:process_id`, proving the event did not need to carry
  `tool_call_id`.
- The same acceptance run ingests cgroup-scoped and container-scoped raw events
  and verifies `cgroup_time_window:cgroup_id+time` and
  `container_time_window:container_id+time` correlation.
- `telemetry bind` registers an explicit harness-provided ToolCallScope binding,
  and a PID-only raw event resolves through `pid_time_window:pid+time`.
- Native runtime causality edges show `tool_call -> process -> runtime_event`
  and connect a runtime-observed `file_write` event to the same
  attempt/tool_call that produced the file diff.
- PID/PPID/TGID runtime telemetry creates process-tree causality edges, so
  delayed child process events can be explained without raw `tool_call_id`.
- `graph explain --json` combines state diff, blame, runtime events, evidence,
  object refs, risks, replay refs, and bounded causality paths in one
  `agentprovenance.explain/v1` manifest. `--depth` and `--limit` make graph
  traversal explicit, and `--cursor` pages larger DAGs. Paged outputs include
  stable `result_set_id` and per-page `page_hash` metadata for evidence
  integrity checks.
- `agentprov record --json` includes `observed_processes`,
  `process_tree_count`, and scope boundary metadata so zero-SDK recordings can
  explain which child processes were sampled and later correlated. It also
  exposes `orphan_policy`, `post_root_grace_ms`, and `outlived_root` for
  descendants observed after the root command exits. When such a descendant is
  observed, record writes an `audit` policy decision with rule
  `zero_sdk_orphan_observe_only` and an `orphan_lifecycle_decision` evidence
  event.
- `graph trace` shows `execution_context_bindings:` and the correlated
  `execve` event under the same run/session/attempt/tool/process chain.
- `timeline --run <run_id> --json` emits `agentprovenance.timeline/v1`, a
  time-ordered execution view across tool calls, processes, runtime telemetry,
  evidence, policy decisions, risk signals, baseline deviations, response
  actions, and external effects.
- `observe summary --run <run_id> --json` emits
  `agentprovenance.observability_summary/v1`, a run-level coverage summary for
  application context, runtime telemetry correlation, risk, baseline, response,
  top evidence refs, and suggested drill-down commands.
- `observe coverage --run <run_id> --json` emits
  `agentprovenance.observability_coverage/v1`, a correlation-quality report for
  raw runtime telemetry, including missing `session_id`, `tool_call_id`, or
  `process_id` gaps and suggested binding keys.
- `observe scopes --run <run_id> --json` emits
  `agentprovenance.observability_scopes/v1`, a per-ToolCallScope view with
  process counts, runtime event histograms, risk/response counts, evidence refs,
  and drill-down commands.
- `observe event --run <run_id> --event <event_id> --json` emits
  `agentprovenance.observability_event/v1`, a single runtime event detail with
  correlated agent context, correlation metadata, related risk/policy/response
  evidence, and drill-down commands.
- `observe process --run <run_id> --process <process_id> --json` emits
  `agentprovenance.observability_process/v1`, a process-level detail with
  lifecycle, ToolCallScope context, runtime events, risk/policy/response
  evidence, and drill-down commands.
- `observe flow --run <run_id> --json` emits
  `agentprovenance.observability_flow/v1`, a compact causal table linking
  runtime events to direct risk signals, policy decisions, response actions, and
  drill-down commands.
- `rollout attempts` shows `wrong-constant` as `quarantined` with
  `risk=tainted`.
- `rollout winner` is a historical command name. It shows `correct-add` as the
  local clean candidate that passed the demo response gate. In real RL
  pipelines this is evidence for reward/penalty scoring, filtering, or human
  review, not the final reward or training decision.
- The same output includes `watermark`, `drain_started_at`,
  `drain_completed_at`, `drain_queued_before`, `drain_processed`, and
  `drain_pending_after=0`, proving the candidate barrier drained queued
  evidence before marking the candidate promotable.
- `graph diff --file calculator.py` prints a unified diff between the base file
  and modified attempt files. `--json` emits an `agentprovenance.diff/v1`
  manifest.
- `graph blame --file calculator.py` reports `unchanged_from_base` and
  `modified_by_attempt` records with attempt id, tool call id, strategy,
  command, artifact, and local candidate status. `--json` emits an
  `agentprovenance.blame/v1` manifest.
- The Phase 1 gate also checks `created_by_attempt` and `deleted_by_attempt`
  records, so file attribution covers created, modified, deleted, and unchanged
  workspace states.
- `graph trace` shows generated patch artifacts linked by `attempt_artifact`
  and `tool_call_artifact` edges.
- `agentprov record -- <command>` proves the zero-SDK path by snapshotting a
  working directory, running a command, computing changed files, and linking
  runtime file evidence to diff/blame.
- `effect list --run run-demo-bugfix` and `graph trace` show an
  `ExternalEffectRecord` for a dry-run API call, proving external side effects
  are recorded as gate evidence instead of rollbackable state.
- `graph verify --run run-demo-bugfix` reports `status=ok` after checking
  references, content-addressed object hashes, replay manifest generation,
  ToolCallScope correlation drift, taint/response-gate consistency, and
  local-candidate drain watermark consistency.
- `graph verify --run run-demo-bugfix --json` emits an
  `agentprovenance.verify/v1` manifest with `status`, `error_count`,
  `warning_count`, and structured issues for automation.
- `graph replay --run run-demo-bugfix` emits a plan-only reconstruction of base
  snapshot, attempts, commands, artifacts, runtime events, and external effect
  gates. `graph replay --run run-demo-bugfix --json` emits the same evidence as
  an `agentprovenance.replay/v1` manifest for automation.
- `graph trajectories --run run-demo-bugfix --json` emits an
  `agentprovenance.trajectories/v1` manifest. It groups each attempt's
  file changes, artifact, tool call, process/runtime events, external effects,
  risk, cost, and local candidate eligibility into one record for external
  evaluators or RL pipelines.
- `accept_phase1.sh` validates the same expectations with command output and
  JSON manifest assertions, so Phase 1 has a machine-checkable gate.
- Fanout stress-demo unit tests prove a quarantined/tainted attempt is rejected
  by the response gate before local candidate evidence can be emitted.
- Fanout stress-demo and verifier unit tests prove a local candidate must have a durable
  telemetry/evidence drain window and no queued evidence at or before its
  watermark.
- Fanout stress-demo unit tests prove snapshot taint propagates through
  `snapshot_edges` to descendant snapshots.

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

This is a legacy branch/fanout stress demo. It is useful for exercising
diff/blame, taint, response-gate, resource-evidence, and artifact-lineage
behavior under multiple attempts. It is not the primary product surface and
does not imply that AgentProvenance owns reward or winner decisions.

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
time, output summary, score, `risk_status`, `budget_exceeded`, and the local
candidate attempt. Strategy metadata can include `probe`, `budget`,
`score=contains:<text>` or `score=number`, and `artifact`. Local candidate
eligibility prefers clean, within-budget attempts, then score, then lower cost. Cost output
includes fanout cost and saved cost when early stop, max fanout, or probe
pruning avoids full command execution. `cost show` also prints
`rollout_cost_summary` with total attempts, executed attempts, pruned attempts,
local candidates, saved cost, and saved ratio.
When `artifact=<workspace-relative-path>` is set, AgentProvenance copies that file from the
attempt workspace into `.agentprov/artifacts/` and stores the exported result ref in
`artifact_result`; missing artifacts are recorded in the attempt output summary.
Processed evidence also adds `attempt_artifact` and `tool_call_artifact` graph
edges, and `graph trace` prints an `artifacts` section for reverse lookup from
artifact ref to attempt, tool call, strategy, and local candidate status.
Use `graph trace --artifact <artifact_ref>` to start from an exported artifact
and trace back to the attempt, tool call, stress-demo run, and graph edge that
produced it. Use `graph trace --attempt <attempt_id>` to inspect a single
attempt with its tool call, artifact, stress-demo graph edges, evidence payload,
and local candidate status. Use `graph trace --tool-call <tool_call_id>` to start from
one tool invocation and inspect its process, artifact, graph edges, evidence,
stress-demo context, and local candidate context. Use `graph trace --process <process_id>` to start
from a runtime process and trace back to the session, tool call, attempt,
artifact, telemetry event, policy decision, stress-demo run, and evidence context.
Local fanout attempts create local session/process records too, so process
trace works for quick branch-heavy demos without requiring Docker runtime.
`graph refs --run <run_id>` adds the Git-like ref view: run refs, base
snapshot refs, local candidate attempt refs, response-gate refs, tool call refs, process
refs, and artifact refs. `graph log --run <run_id>` adds the compact
chronological provenance log for fanout, attempt, tool call, process,
response-gate, evidence, and telemetry events. `graph materialize --run <run_id>`
turns the current SQLite trace into a content-addressed provenance object DAG
under `.agentprov/provenance/objects/sha256/`; each object records source id, parent
hashes, replay-oriented payload, and artifact file hashes when an artifact file
exists. `graph objects --run <run_id> --limit <n> --cursor <next_cursor> --json`
lists object refs with type, source id, hash, parent hashes, path, size, and
created time. The object page includes `result_set_id` and `page_hash`, so
clients can verify paged evidence exports. `graph verify --run <run_id>` checks reference continuity,
taint/response-gate contradictions, artifact readability, materialized object
hashes, replay manifest generation, and ToolCallScope correlation drift.
Add `--json` to emit the structured `agentprovenance.verify/v1` manifest for
automation.
`graph replay --run <run_id>` and `graph replay --attempt <attempt_id>`
emit a plan-only reconstruction of snapshot, attempt, tool call, process,
artifact, telemetry, and external effect records. Add `--json` to emit the
structured `agentprovenance.replay/v1` manifest for automation; Phase 1 does
not execute the plan or roll back real-world side effects.
`graph trace` prints the compact attempt evidence payload, including strategy,
score, saved cost, output summary, local candidate flag, and response-gate
reason, so a probe/top-k rollout can be replayed and audited without guessing
why a branch was pruned or marked evaluator-eligible.

### demo_rollout_control_plane

```sh
agentprov snapshot stack --task examples/tasks/bugfix.yaml
AGENTPROV_IO_MAX_FANOUT_PER_LOWER=100 AGENTPROV_BURST_MAX_INFLIGHT=2 \
  agentprov rollout start --task examples/tasks/bugfix.yaml --snapshot ready --runtime docker --fanout 3 \
  --top-k 2 \
  --strategy "probe::test -f README.md && echo passed::probe=test -f README.md && echo passed::score=contains:passed::artifact=probe.log" \
  --strategy "score::printf 42::probe=printf 42::score=number::artifact=score.txt" \
  --strategy "slow::sleep 1; echo passed::probe=echo 1::score=contains:passed::artifact=slow.log"
agentprov rollout attempts <rollout_id>
agentprov rollout winner <rollout_id> # historical name: local candidate evidence
agentprov evidence process
agentprov graph trace --run run-demo-bugfix
agentprov cost show run-demo-bugfix
```

This is a legacy substrate/fanout stress path. It starts from a ready
snapshot, forks attempt workspaces, creates one short-lived Docker session and
one `tool_call` per admitted strategy, requires BurstGuard admission before
command execution, switches the container from `think` to `tool` CPU profile,
writes compact evidence, materializes `rollout -> attempt -> tool_call ->
session` graph edges asynchronously, and checks local candidate eligibility
through the response gate. Attempt tables and `cost show` expose risk,
budget, score, cost, and expectation-deviation evidence so an external
evaluator can assign reward, penalty, filtering, or review decisions.

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
agentprov egress proxy sidecar, adds `example.com` to the allowlist, verifies an
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
rejects before CPU weight is raised. Set `AGENTPROV_BURST_OVERFLOW_POLICY=delay` and
`AGENTPROV_BURST_QUEUE_TIMEOUT_MS=<ms>` to queue briefly until a burst slot is
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
`AGENTPROV_IO_MAX_FANOUT_PER_LOWER=1` and uses `graph trace` to show why overlay was
not selected.

## MVP limits

- Docker must be running for `session`, `exec`, and `process` commands.
- CPU weight control uses Docker `ContainerUpdate` / `CpuShares`. On Linux
  cgroup v2 this maps to cgroup CPU weight behavior; a direct node-agent
  `cpu.weight` writer is a future Linux-specific hardening path.
- BurstGuard rejects excess synchronized tool phases by default and supports a
  bounded delay/queue mode with `AGENTPROV_BURST_OVERFLOW_POLICY=delay`.
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
