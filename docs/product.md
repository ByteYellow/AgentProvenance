# AgentProvenance Product Direction

AgentProvenance is a security-oriented execution observability and Git-like
provenance control plane for sandboxed agent execution.

It correlates application-side agent context with system-side telemetry, then
records how an agent execution context produces state changes, runtime events,
artifacts, risk signals, response decisions, and audit evidence. The project is
not a generic sandbox runtime, generic telemetry collector, generic
observability dashboard, Kubernetes/Ray replacement, or RL trainer.

The core product line is:

```text
Execution Context
  -> Evidence Ingest
  -> Runtime Causality Graph
  -> Provenance DAG
  -> State Diff / Blame / Artifact Lineage
  -> Security Analysis / Risk Decision
  -> Taint / Response Action
  -> Replay / Forensics / Audit Manifest
```

## Positioning

AgentProvenance is built for autonomous tool-using agents, especially coding
agents. RL-style rollout and evaluator pipelines are important stress cases, but
they are not the only product target.

Primary scenarios:

- Coding-agent repair, refactor, test, and patch generation.
- Autonomous agent workflows with long chains of tool calls and subprocesses.
- Security analysis of sandboxed agent executions where application context,
  system telemetry, state changes, artifacts, risk, and replay matter.
- Risk discovery and risk judgment for agent behaviors that cross process,
  file, network, and sandbox boundaries.
- Automated response prototypes: audit, deny, kill, quarantine, taint snapshot,
  export forensics, and notify operators through Feishu/DingTalk-style apps.
- Behavior baseline and deviation analysis for repeated agent/task profiles.

Stress scenarios:

- Best-of-N attempt fanout.
- Evaluator or RL pipelines that need trajectory evidence, expectation
  deviation signals, and risk context for reward/penalty shaping.
- High-concurrency sandbox execution where raw traces are not enough.

AgentProvenance does not choose the winner or define the reward function for an
RL pipeline. It emits structured trajectory evidence, behavior deviations,
runtime/security signals, and provenance context so the external evaluator,
trainer, or harness can assign reward, penalty, filtering, or review decisions.

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

AgentProvenance owns agent execution provenance and security evidence
correlation. It does not own generic infrastructure.

It may consume:

- Docker, OpenSandbox, gVisor, Firecracker, Kata, or other sandbox runtimes.
- Kubernetes, Ray, Batch, or cloud orchestrators.
- Falco, Tetragon, LoongCollector, eBPF, auditd, wrapper telemetry, or runtime
  event streams.
- LangSmith-style traces or internal agent harness events.
- system-side low-intrusion system-side observability output.

Its job is to convert those signals into a causality and provenance model:

```text
agent context + system telemetry + state diff + artifacts + risk
  -> queryable, replayable, auditable security evidence DAG
```

## Relationship To System observability, HIDS, And OpenTelemetry

system-side systems are valuable because they provide low-intrusion,
system-level ground truth for agent behavior: process activity, file access,
network behavior, and cross-process effects. AgentProvenance should learn from
that direction and can ingest that class of telemetry, but it should not present
itself as a clone of a zero-SDK eBPF observer.

The differentiation is the control-plane layer above observation:

```text
system-side telemetry + application-side agent context
  -> runtime causality graph
  -> Git-like provenance DAG
  -> security analysis / risk judgment
  -> response action / forensics / audit trail
```

The HIDS analogy is useful: AI agents in sandboxes still create host-like
monitoring needs around process, file, network, resource, and policy activity.
The difference is that AgentProvenance treats the agent context as first-class:
run, session, attempt, tool call, task, snapshot, artifact, and promotion or
quarantine state.

OpenTelemetry and LLM tracing tools remain useful inputs or exports. They are
not the core product surface. AgentProvenance focuses on evidence lineage,
diff/blame, taint propagation, risk decisions, response hooks, replay, and audit
manifests.

## What The Graph Must Answer

- What produced this artifact?
- Which snapshot did this attempt start from?
- Which tool call started this process?
- Which child process produced this runtime event?
- Which process changed this file?
- Which behavior deviated from this task or agent baseline?
- Which file state is created, modified, deleted, or unchanged from base?
- Which external effect was attempted, gated, or denied?
- Which branch was tainted or quarantined?
- Why was a candidate blocked by the promotion barrier?
- Which risk decision and response action are supported by concrete evidence?
- What evidence and deviation signals should an external evaluator or RL
  pipeline score?
- Can this trajectory be replayed or audited later?

## Phase Plan

| Phase | Goal | Output |
|---|---|---|
| Phase 1 | Provenance Correlation MVP | ToolCallScope, raw telemetry correlation, runtime causality DAG, diff/blame, taint, promotion barrier, replay and trajectory manifests |
| Phase 2 | Evidence / Causality Hardening | stable explain JSON, content-addressed objects, object parent hashes, graph verification, bounded traversal, pagination, integrity metadata |
| Phase 3 | Zero-SDK Recorder Hardening | process-tree capture, delayed child process handling, cwd/time/file-diff inference, orphan lifecycle evidence, low-intrusion record mode |
| Phase 4 | Real Telemetry Integration | Falco/Tetragon/LoongCollector/auditd/eBPF receivers, cgroup/container/pid correlation, kernel-side filtering assumptions |
| Phase 5 | Risk / Policy / Control | configurable risk signals, behavior baseline checks, taint propagation, quarantine, promotion block, forensics export, Feishu/DingTalk notification hooks, isolation escalation hooks |
| Phase 6 | Scale / UI / Productization | async evidence writer, retention, content-addressed storage, snapshot GC, resource windows, high-concurrency ingest/query tests, usable UI/API |

## Phase 1 Definition Of Done

Phase 1 is done when the project can prove:

- A coding-agent best-of-N demo creates multiple attempts from one base
  snapshot.
- `agentprov record -- <command>` records a command without SDK integration and
  produces file diff, blame, sampled descendant process evidence, PID bindings,
  post-root outlived-process markers, and runtime file evidence.
- Runtime events can be ingested without raw `tool_call_id`.
- Events can be bound to execution context through process/container/cgroup/time
  evidence.
- The graph records `execution_context -> tool_call -> process ->
  runtime_event -> file_diff/artifact`.
- PID/PPID/TGID runtime evidence creates process-tree causality edges.
- Runtime file events create file nodes that can be explained with diff/blame.
- `graph diff` and `graph blame` explain state changes.
- `graph explain --json` can explain a file, event, process, tool call,
  attempt, artifact, or risk decision by combining causality and provenance
  evidence into an `agentprovenance.explain/v1` manifest with depth/limit/cursor
  controlled `causality_path` and query metadata.
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
agent execution state was produced, changed, branched, tainted, judged risky,
responded to, and made eligible or ineligible for promotion or further use.
