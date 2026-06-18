# AgentProvenance Product Direction

AgentProvenance is a Git-like provenance control plane for sandboxed agent
execution.

It records how an agent execution context produces state changes, runtime
events, artifacts, risk signals, and promotion evidence. The project is not a
generic sandbox runtime, generic observability dashboard, Kubernetes/Ray
replacement, or RL trainer.

The core product line is:

```text
Execution Context
  -> Evidence Ingest
  -> Runtime Causality Graph
  -> Provenance DAG
  -> State Diff / Blame / Artifact Lineage
  -> Risk / Taint Propagation
  -> Promotion Barrier
  -> Replay / Trajectory / Audit Manifest
```

## Positioning

AgentProvenance is built for autonomous tool-using agents, especially coding
agents. RL-style rollout and evaluator pipelines are important stress cases, but
they are not the only product target.

Primary scenarios:

- Coding-agent repair, refactor, test, and patch generation.
- Autonomous agent workflows with long chains of tool calls and subprocesses.
- Audit of sandboxed agent executions where state, artifacts, risk, and replay
  matter.

Stress scenarios:

- Best-of-N attempt fanout.
- Evaluator or RL pipelines that need trajectory evidence.
- High-concurrency sandbox execution where raw traces are not enough.

AgentProvenance does not choose the winner for an RL pipeline. It emits
structured trajectory evidence so the external evaluator, trainer, or harness
can make that decision.

## Two Context Modes

### White-box mode

The agent harness, SDK, tool router, or framework provides explicit context:

```text
run_id / session_id / attempt_id / tool_call_id / tool_name / args_hash
```

This mode gives the highest precision and is suitable for Agentix-style
harnesses, internal coding-agent systems, LangGraph-like execution engines, and
custom tool routers.

### Zero-SDK mode

The user runs:

```sh
agentprov record -- <agent command>
```

The Phase 1 MVP snapshots the working directory before execution, runs the
command, computes file changes after execution, and records runtime file
evidence into the graph. Deeper process-tree and kernel-level collection are
future substrate work.

AgentProvenance infers execution scope from runtime evidence:

```text
root process / process tree / cwd / timestamp / container_id / cgroup_id
  / file diff / artifact refs
```

Zero-SDK mode is broader but less precise. It is still useful because raw
system-side telemetry cannot be expected to carry application-level
`tool_call_id`.

The long-term direction is SDK-optional, proxy-optional, and vendor-neutral:
white-box context where available, runtime inference where not.

## Product Boundary

AgentProvenance owns agent execution provenance. It does not own generic
infrastructure.

It may consume:

- Docker, OpenSandbox, gVisor, Firecracker, Kata, or other sandbox runtimes.
- Kubernetes, Ray, Batch, or cloud orchestrators.
- Falco, Tetragon, LoongCollector, eBPF, auditd, wrapper telemetry, or runtime
  event streams.
- LangSmith-style traces or internal agent harness events.

Its job is to convert those signals into a causality and provenance model:

```text
execution context + runtime evidence + state diff + artifacts + risk
  -> queryable, replayable, auditable DAG
```

## What The Graph Must Answer

- What produced this artifact?
- Which snapshot did this attempt start from?
- Which tool call started this process?
- Which child process produced this runtime event?
- Which process changed this file?
- Which file state is created, modified, deleted, or unchanged from base?
- Which external effect was attempted, gated, or denied?
- Which branch was tainted or quarantined?
- Why was a candidate blocked by the promotion barrier?
- What evidence should an external evaluator inspect?
- Can this trajectory be replayed or audited later?

## Phase Plan

| Phase | Goal | Output |
|---|---|---|
| Phase 1 | Provenance correlation MVP | Execution context, evidence ingest, runtime causality DAG, diff/blame, taint, promotion barrier, replay and trajectory manifests |
| Phase 2 | Risk and auto-response MVP | RiskSignal, configurable rules, taint propagation, quarantine, promotion block, forensics export |
| Phase 3 | Zero-SDK substrate integration | deeper process tree capture, cwd/timestamp/file-diff inference, wrapper/audit/eBPF-ready event receivers |
| Phase 4 | eBPF and runtime telemetry substrate | Falco/Tetragon/LoongCollector JSONL receivers, cgroup/container/pid correlation, kernel-side filtering assumptions |
| Phase 5 | Isolation and enforcement | IsolationProfile, EscalationPolicy, seccomp/AppArmor/eBPF LSM/gVisor/Firecracker capability gates |
| Phase 6 | Scale hardening | async evidence writer, retention, content-addressed storage, snapshot GC, resource windows, high-concurrency rollout tests |

## Phase 1 Definition Of Done

Phase 1 is done when the project can prove:

- A coding-agent best-of-N demo creates multiple attempts from one base
  snapshot.
- `agentprov record -- <command>` records a command without SDK integration and
  produces file diff, blame, and runtime file evidence.
- Runtime events can be ingested without raw `tool_call_id`.
- Events can be bound to execution context through process/container/cgroup/time
  evidence.
- The graph records `execution_context -> tool_call -> process ->
  runtime_event -> file_diff/artifact`.
- PID/PPID/TGID runtime evidence creates process-tree causality edges.
- Runtime file events create file nodes that can be explained with diff/blame.
- `graph diff` and `graph blame` explain state changes.
- `graph explain --json` can explain a file, event, process, tool call,
  attempt, or artifact by combining causality and provenance evidence into an
  `agentprovenance.explain/v1` manifest.
- Risk marks taint and blocks promotion.
- Promotion records a telemetry/evidence drain watermark.
- `graph replay`, `graph verify`, and `graph trajectories --json` produce
  machine-readable audit manifests.

## Final Effect

The finished system should make a sandboxed agent execution feel like Git for
runtime state and evidence:

```text
branch: attempt
commit-like object: content-addressed evidence object
diff: file state delta from base
blame: state attribution to attempt/tool/process
tag: candidate/promoted/quarantined/tainted
log: execution history
replay: reconstruction plan and audit manifest
```

This is the durable differentiation from generic observability:
AgentProvenance is not only showing that something happened. It explains how an
agent execution state was produced, changed, branched, tainted, and made
eligible or ineligible for promotion.
