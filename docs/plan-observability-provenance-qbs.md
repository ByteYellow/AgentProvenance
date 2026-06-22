# Observability, Git-like Provenance, and QBS Plan

This document is the current product plan for AgentProvenance.

The direction is:

```text
Agent / Sandbox / Runtime Telemetry
  -> Execution Observability Core
  -> Git-like Provenance Core
  -> Evidence Query Surface
  -> Risk, Replay, Audit, Adapter Integrations
```

Branch-heavy fanout and RL-style rollout are demo and stress scenarios. They are
useful because they create branches, artifacts, risk, and competing
trajectories, but they are not the core product promise. For RL,
AgentProvenance should provide
observability, behavior evidence, expectation-deviation signals, and
security/risk context that downstream trainers can convert into reward,
penalty, filtering, or human-review signals.

## Final Positioning

AgentProvenance is an execution observability and Git-like provenance control
plane for sandboxed agents.

It correlates agent context with runtime telemetry, turns execution into a
causality graph, and materializes state changes, artifacts, risks, replay
evidence, and audit evidence as content-addressed provenance objects.

The project should answer:

- What happened inside the agent execution?
- Which tool call started which process?
- Which child process produced which runtime event?
- Which process changed which file?
- Which runtime event contributed to which artifact?
- Which evidence created a risk signal, baseline deviation, taint, or response
  action?
- Can the trajectory be queried, diffed, blamed, replayed, and audited later?

## What AgentProvenance Is Not

AgentProvenance is not:

- a generic sandbox runtime;
- a generic telemetry collector;
- a Kubernetes, Ray, or OpenSandbox replacement;
- a LangSmith/Langfuse-style LLM trace dashboard;
- an RL reward or winner selector;
- an eBPF agent implementation.

Those systems can be substrates or upstream/downstream integrations. The core
value of AgentProvenance is correlation, causality, Git-like evidence objects,
and auditability.

## Core Layers

### 1. Execution Observability Core

This is the first priority.

It connects application-side context with system-side telemetry:

```text
run_id / session_id / attempt_id / tool_call_id
  + process_id / pid / ppid / tgid / cgroup_id / container_id
  + file / network / exec / exit / resource events
  -> runtime causality graph
```

Required capabilities:

- explicit ToolCallScope in white-box mode;
- zero-SDK record mode for arbitrary agent commands;
- process tree capture, including child and delayed subprocesses;
- file, network, exec, exit, and resource event ingestion;
- raw runtime event schema that does not require `tool_call_id`;
- deterministic correlation through cgroup/container/pid/time evidence.

### 2. Git-like Provenance Core

This is the durable differentiator.

It turns execution evidence into Git-like objects and operations:

```text
refs       -> stable names for runs, attempts, snapshots, artifacts, decisions
log        -> chronological execution history
diff       -> file state delta from base
blame      -> attribution to attempt / tool_call / process
objects    -> content-addressed evidence objects
replay     -> reconstruction plan
audit      -> verifiable evidence manifest
```

Required capabilities:

- content-addressed object store;
- object parent hashes;
- schema versions;
- artifact lineage;
- diff and blame manifests as first-class objects;
- replay and audit manifests as first-class objects;
- `graph verify` to validate object hashes, parents, and causality invariants.

### 3. Evidence Query Surface

The evidence query surface is how users ask causal questions over execution
evidence. This is not QBS. It is the provenance graph's query interface.

Core query shapes:

```text
artifact -> upstream snapshot / attempt / tool_call / process / file diff
file     -> who changed it, when, through which process and tool call
process  -> owning tool_call / attempt / runtime events / artifacts
event    -> runtime identity / correlation result / impacted files or risk
attempt  -> state diff / events / artifacts / risk / replay eligibility
risk     -> signal source / affected descendants / response gate
```

Near-term commands:

```sh
agentprov graph explain --artifact <artifact>
agentprov graph explain --file <path> --run <run_id>
agentprov graph explain --process <process_id>
agentprov graph explain --event <event_id>
agentprov graph explain --tool-call <tool_call_id>
agentprov graph explain --artifact <artifact> --json
agentprov graph explain --process <process_id> --json
agentprov graph explain --event <event_id> --json
```

The first milestone is not a full query language. The first milestone is stable
JSON for upstream/downstream/evidence sections in `graph explain`.

### 4. QBS Impact

QBS is not the evidence query layer. It is an impact that must be accounted for
in the architecture.

Until the exact QBS contract is fixed, this plan treats QBS as an external
workload/evaluation influence. It can affect:

- how frequently agent executions are triggered;
- how bursty the runtime telemetry stream becomes;
- how many trajectories, artifacts, and diffs must be retained;
- how evidence is sampled, compacted, or materialized;
- what latency budget the query/explain path must satisfy;
- how adapter boundaries avoid coupling to one agent/evaluator runtime.

Design rule:

```text
QBS shapes workload and consumption assumptions.
It does not replace the core model:
observability -> provenance -> explain/replay/audit.
```

The QBS section should become more concrete once the exact QBS meaning,
interface, and workload assumptions are fixed.

### 5. Adapter Layer

The demo paths are not the final deployment model. AgentProvenance should become
adapter-driven.

Adapter families:

| Adapter | Examples | Role |
| --- | --- | --- |
| Agent adapter | Agentix, coding-agent harness, tool router, evaluator, RL trainer | Provides white-box execution context and tool call metadata |
| Sandbox adapter | Docker, OpenSandbox, gVisor, Firecracker, Kata | Provides sandbox lifecycle, identity, workspace/snapshot metadata |
| Telemetry adapter | wrapper events, auditd, Falco, Tetragon, LoongCollector, eBPF | Provides process/file/network/runtime events |
| Artifact adapter | local filesystem, S3, object store, CI artifacts | Provides durable artifact references and content hashes |
| Snapshot adapter | directory copy, reflink/COW, disk snapshot, memory snapshot | Provides state source and resume/fork semantics |

Adapter rule:

```text
Adapters provide facts and capabilities.
AgentProvenance owns correlation, provenance, query, replay, audit, and risk linkage.
```

Every adapter must expose capabilities honestly. For example, a Docker directory
snapshot must not pretend to support VM memory resume.

### 6. Risk / Response Layer

Risk is important, but it should sit on top of the observability and provenance
core.

Required capabilities:

- risk signals and baseline deviations become graph evidence;
- taint propagates through snapshot/artifact lineage;
- response gates block tainted, undrained, or policy-denied branches;
- response actions record audit, deny, kill, quarantine, taint, forensics,
  notification, or isolation-escalation intent;
- forensics bundle references provenance object IDs;
- policy and runtime enforcement use the same event/correlation model.

## Revised Phase Plan

| Phase | Goal | Primary output |
| --- | --- | --- |
| Phase 1 | Provenance Correlation MVP | ToolCallScope, raw telemetry correlation, runtime causality DAG, diff/blame, risk/deviation records, response-gate evidence, replay and trajectory manifests |
| Phase 2 | Evidence / Causality Hardening | stable explain JSON, content-addressed objects, object parent hashes, graph verification, bounded traversal, pagination, integrity metadata |
| Phase 3 | Zero-SDK Recorder Hardening | process-tree capture, delayed child process handling, cwd/time/file-diff inference, orphan lifecycle evidence, low-intrusion record mode |
| Phase 4 | Real Telemetry Integration | Falco/Tetragon/LoongCollector/auditd/eBPF receivers, cgroup/container/pid correlation, kernel-side filtering assumptions |
| Phase 5 | Risk / Policy / Control | configurable risk signals, behavior baselines, response adapters, taint propagation, quarantine, response blocking, forensics export, Feishu/DingTalk/webhook hooks, isolation escalation hooks |
| Phase 6 | Scale / UI / Productization | async evidence writer, retention, content-addressed storage, snapshot GC, resource windows, high-concurrency ingest/query tests, usable UI/API |

## Demo Repositioning

Branch-heavy coding-agent fanout remains useful, but its role is:

```text
a stress demo for branching sandboxed agent execution
```

It should prove that AgentProvenance can observe, trace, diff, blame, materialize,
query, replay, audit, and risk-gate multiple branches. It should not imply that
AgentProvenance owns reward selection or RL training policy. It should emit the
behavior and risk signals that an external RL system may score.

The stronger primary path should become:

```text
agentprov record -- <agent command>
  -> process tree
  -> runtime events
  -> file diffs
  -> artifact objects
  -> graph explain
  -> replay / audit manifest
```

That demo better represents the core product: execution observability plus
Git-like provenance.
