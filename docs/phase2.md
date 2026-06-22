# Phase 2: Provenance Core Hardening

Phase 2 turns the Phase 1 demo loop into a reliable observability and
provenance primitive.

The goal is not to expand into a generic sandbox platform. The goal is to make
AgentProvenance durable enough that an external agent harness, evaluator,
security workflow, or future adapter can trust the evidence graph.

Branch-heavy fanout is not the center of Phase 2. It is only a stress demo. The center is:

```text
Execution Observability Core
  -> Git-like Provenance Core
  -> Evidence Query Surface
```

## Completion Targets

| Target | Required behavior | Current status |
| --- | --- | --- |
| Content-addressed objects | Artifacts, replay manifests, trajectory manifests, per-file diff manifests, per-file blame manifests, telemetry batch manifests, and audit manifests are written into the provenance object store with schema versions, parent hashes, hash verification, and deduplication by content hash. | MVP done. `graph materialize` writes these object types, including telemetry-only runs, `graph objects` exposes object refs and hashes, and `graph verify` checks object hashes and parents. |
| Stronger zero-SDK record | `agentprov record -- <command>` captures process tree, child/async process evidence, cwd, exit event, env redaction, and file changes into one execution scope. | Improved. Current record captures command cwd, root process, sampled descendant processes, PID bindings for observed children, post-root grace window observations, outlived-root markers, observe-only orphan lifecycle audit decisions, exit status, redacted env summary/hash, changed files, and runtime file events. `graph verify` now rejects outlived process observations without orphan lifecycle evidence and linked policy decisions. Active orphan lifecycle actions still need hardening. |
| Bidirectional explain | `graph explain` can start from file, artifact, process, event, tool call, attempt, or risk and return upstream/downstream causality with stable JSON. | MVP done. These targets now emit v0.2-style `upstream`, `downstream`, depth/limit/cursor-controlled `causality_path`, `query`, `evidence`, `objects`, `risks`, `telemetry_batches`, `process_observations`, `runtime_events`, and `replay_refs` where applicable. Runtime events include telemetry receiver/source-format/schema/correlation details, and event explains can link back to the receiver batch manifest. Query metadata includes `result_set_id` and `page_hash`. |
| Telemetry raw event schema | Runtime events have a clear boundary between application context, runtime identity, raw payload, and correlation result. | Improved. Ingest now rejects application context inside raw telemetry payloads and validates minimum event-specific fields for exec, process, file, network, policy, abnormal process tree, and resource-pressure events. `telemetry ingest-jsonl` maps filtered Tetragon/Falco/LoongCollector JSONL into the normalized schema. `graph verify` revalidates stored telemetry-source payloads after unwrapping correlation metadata. |
| Evidence query shape | Evidence can be queried from artifact, file, process, event, tool call, attempt, and risk nodes through stable upstream/downstream/evidence JSON. | MVP done. All listed start points are covered with explicit `--depth`, `--limit`, and `--cursor` traversal controls. Policy-decision graph edges are persisted and verified. |
| QBS impact model | QBS is treated as a workload/evaluation influence that affects execution cadence, evidence volume, storage pressure, adapter boundaries, and downstream consumption. It is not the evidence query layer. | Direction corrected in docs. Concrete QBS assumptions still need to be specified once the exact QBS contract is fixed. |
| Adapter readiness | The provenance model clearly separates agent, sandbox, telemetry, artifact, and snapshot adapters from core correlation/query/provenance logic. | MVP done. `agentprov adapter list/inspect` exposes capability contracts for agent, sandbox, telemetry, artifact, and snapshot adapters, including identity keys, boundaries, and QBS impact. |
| Security evidence | Risk signals, baseline deviations, and response actions are first-class graph objects and queryable records rather than side effects hidden inside policy output. | MVP done for policy-derived risk/response records and baseline deviation records. `agentprov security risks/deviations/responses` exposes the evidence surface. |
| Demo evidence | The branch-heavy coding demo shows artifact lineage, content hash, diff/blame, taint, response-gate behavior, replay, trajectory, and audit evidence as a stress demo. | MVP done for CLI evidence. Acceptance now checks object refs for artifact, diff, blame, replay, trajectory, audit, record, and policy-decision objects. |
| README positioning | README explains why this is Git-like provenance rather than a trace dashboard or sandbox manager. | Partial. README has the positioning; Phase 2 object-store semantics are now called out. |

## Current Object Types

`graph materialize --run <run_id>` writes:

- `snapshot`
- `rollout`
- `attempt`
- `tool_call`
- `process`
- `artifact`
- `risk_signal`
- `baseline_deviation`
- `response_action`
- `promotion` (legacy stress-demo object)
- `evidence`
- `event`
- `policy_decision`
- `cost`
- `replay_manifest`
- `trajectory_manifest`
- `diff_manifest`
- `blame_manifest`
- `audit_manifest`
- `record_manifest`

Every object is stored under `.agentprov/provenance/objects/sha256/` and indexed
in SQLite through `provenance_objects`.
Use `graph objects --run <run_id>` or `graph objects --run <run_id> --json` to
inspect object type, source id, hash, parent hashes, path, size, and created
time. Add `--limit` and `--cursor <next_cursor>` to page large object sets.
Each page includes a stable `result_set_id` for the logical query and a
`page_hash` for the returned page content.

## Next Hardening Steps

1. Extend page integrity metadata into exported audit manifests so a bundle can
   prove exactly which paged evidence responses were used.
2. Define the QBS impact model once the exact QBS contract is clear: expected
   cadence, fanout/trajectory volume, query/consumption pattern, and evidence
   retention pressure.
3. Add explicit orphan lifecycle actions for zero-SDK record, such as
   observe-only, terminate, detach, or export-forensics.
4. Promote adapter contracts from static registry to plugin-loaded adapters with
   versioned manifests.
5. Add deeper object-level replay/materialization tests for longer-lived
   zero-SDK recordings and high-volume telemetry runs.
