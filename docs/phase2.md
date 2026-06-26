# Phase 2: Provenance Core Hardening

Phase 2 turns the Phase 1 demo loop into a reliable observability and
provenance primitive.

The goal is not to expand into a generic sandbox platform. The goal is to make
AgentProvenance durable enough that an external agent harness, evaluator,
security workflow, or future adapter can trust the evidence graph.

Branch-heavy fanout is not the center of Phase 2. It is only a stress demo. The center is:

```text
Execution Observability Core
  -> Execution Timeline
  -> Git-like Provenance Core
  -> Evidence Query Surface
```

## Completion Targets

| Target | Required behavior | Current status |
| --- | --- | --- |
| Content-addressed objects | Artifacts, replay manifests, trajectory manifests, per-file diff manifests, per-file blame manifests, telemetry batch manifests, record batch manifests, evidence manifests, and audit manifests are written into the provenance object store with schema versions, parent hashes, hash verification, and deduplication by content hash. | Improved. `graph materialize` writes the core object set, including `record_batch` and `record_batch_summary` objects for batch/evaluator pipelines. `evidence manifest --materialize` writes the run-level evidence index as a content-addressed object, `graph objects` exposes object refs and hashes, and `graph verify` checks object hashes and parents. |
| Stronger zero-SDK record | `agentprov record -- <command>` captures process tree, child/async process evidence, cwd, exit event, env redaction, and file changes into one execution scope. | Improved. Current record captures command cwd, root process, sampled descendant processes, configurable sampling/grace windows, PID bindings for observed children, raw/correlation/container/cgroup identity on `process_observed` telemetry, post-root grace window observations, outlived-root markers, observe-only orphan lifecycle audit decisions, exit status, redacted env summary/hash, changed files, and runtime file events. `scripts/accept_zero_sdk_realistic.sh` now exercises a realistic command that modifies, creates, and deletes files, observes a child process, ingests a delayed child runtime event without raw `tool_call_id`, then verifies diff/blame, timeline, evidence manifest, replay, and graph integrity. Active orphan lifecycle actions still need hardening. |
| Execution timeline | Users can inspect a time-ordered view of application context, runtime telemetry, evidence, policy decisions, risk signals, baseline deviations, response actions, and external effects. | Improved. `agentprov timeline --run <run_id>` emits a human table, `--view causality` emits a system-side lane view, and `--json` emits `agentprovenance.timeline/v1` with lane, correlation status, drill-down refs, tool-call/process/type filters, `result_set_id`, `page_hash`, `total_count`, `has_more`, and opaque `next_cursor` for UI/API integrity checks. |
| Observability query integrity | Run summary, coverage, tool-call scope, event detail, process detail, and event-flow views need stable machine-readable integrity metadata for UI caching, export, and audit. | Improved. `observe summary/coverage/scopes/event/process/flow --json` emit `result_set_id` and `page_hash`. `observe summary` now includes a telemetry window aggregate from `telemetry_event_windows` so summary queries can avoid repeated raw-event scans. Event, process, and flow views expose the same lane, correlation status, and drill-down semantics as `timeline --view causality`, so UI and audit consumers do not need to infer query shape differently per command. |
| Evidence manifest | A run needs one stable audit entry point that references observability, timeline, objects, risk, response, and next drill-down commands without forcing a consumer to call every surface first. | Improved. `agentprov evidence manifest --run --json` emits `agentprovenance.evidence_manifest/v1` with summary, timeline, object-list, risk-report, response-report hashes, object type counts, security counts, recommended drill-down queries, and `query_refs` carrying command, schema, result-set hash, page hash, and pagination metadata. `--materialize` stores the same manifest as an `evidence_manifest` provenance object with existing object hashes as parents. |
| Forensics bundle | A risky run or a recorded batch needs a portable evidence package that can be verified outside the live SQLite query path. | Improved. `forensics export <run_id> --json` emits `agentprovenance.forensics_export/v1` and writes a hashed `agentprovenance.forensics_bundle/v1` file with evidence manifest, telemetry batches, events, policy decisions, risk signals, response actions, graph edges, cost samples, sessions, processes, and snapshots. `forensics export-batch --json` emits `agentprovenance.batch_forensics_export/v1` and writes a sha256-verified batch audit bundle with batch summary, per-run bundle refs, optional EvalContext records, result/page hashes, and replay/query commands. `scripts/accept_forensics_bundle.sh` and `scripts/accept_batch_forensics.sh` verify these paths. |
| Daemon API boundary | The evidence path needs a long-lived control/query process so core flows are not limited to one-shot CLI commands. | Improved. `agentprov daemon serve` exposes ToolCallScope binding, paged telemetry event query, telemetry event window query, telemetry correlation explain, observability summary, timeline query, Falco ingest/spool, graph explain/verify, security risk/deviation/response query, evidence manifest materialization, run/batch forensics export, and evaluator context/import APIs. CLI daemon-client mode now covers `observe summary`, `timeline`, `telemetry correlations`, `graph explain`, `graph verify`, `security risks/deviations/responses`, `evidence manifest`, `forensics export`, `forensics export-batch`, and `signal`. `scripts/accept_daemon_evidence_api.sh` validates the risk/evidence/query/signal path through HTTP, including `GET /v1/telemetry/windows` and the summary window aggregate. |
| Telemetry spool / backpressure boundary | Data-plane receivers need a low-cost append path so raw telemetry does not synchronously monopolize the control/query process. | Improved. Daemon Falco ingest supports `queued` enqueue into `telemetry_spool_batches`, copies input into `.agentprov/spool`, records file hash/size/status, and a background worker consumes batches with `--spool-interval` / `--spool-limit`. `--spool-max-queued` applies a hard queue cap. `--spool-drop-policy=reject` returns structured HTTP 429 backpressure rejects; `--spool-drop-policy=drop_oldest` drops the oldest queued batch, records `drop_reason`, and removes the spooled file before accepting the new batch. `health` exposes `queued_spool`, `spool_max_queued`, and `spool_drop_policy`; acceptance covers queued control responsiveness and queue-full rejection. |
| High-volume telemetry pressure | Infra must prove that a large telemetry batch does not force control/query APIs into full scans or oversized responses. | Initial. `scripts/accept_telemetry_100k_pressure.sh` generates 100k Falco events, enqueues via daemon spool, checks `health` and paged query responsiveness while queued, drains the batch, and verifies `telemetry/events?limit=5` returns bounded output with `next_cursor`, `result_set_id`, and `page_hash`. Ingest summaries keep complete counts while row-level receiver details are capped with `row_results_truncated`. |
| Telemetry event windows | Runtime telemetry summaries need bounded aggregate tables so dashboards, risk scoring, and coverage checks do not repeatedly scan raw events. | Improved. JSONL/Falco ingest rebuilds `telemetry_event_windows` for 10s and 60s windows grouped by run/session/tool_call/source/event_type. `telemetry windows --run --window --json` and daemon `GET /v1/telemetry/windows` emit `agentprovenance.telemetry_event_windows/v1` with event, resolved, unresolved, high-risk counts, `result_set_id`, and `page_hash`. `observe summary` embeds the 60s aggregate. `scripts/accept_telemetry_event_windows.sh` and `scripts/accept_daemon_evidence_api.sh` validate this path. |
| Bidirectional explain | `graph explain` can start from file, artifact, process, event, tool call, attempt, or risk and return upstream/downstream causality with stable JSON. | Improved. These targets emit v0.2-style `upstream`, `downstream`, depth/limit/cursor-controlled `causality_path`, `query`, `evidence`, `objects`, `risks`, `responses`, `telemetry_batches`, `process_observations`, `runtime_events`, and `replay_refs` where applicable. Runtime events include telemetry receiver/source-format/schema/correlation details plus lane, correlation status, and drill-down refs aligned with `timeline` and `observe`. Risk explains now link raw runtime event -> policy decision -> response action. Event explains can link back to the receiver batch manifest. Query metadata includes `result_set_id` and `page_hash`. |
| Telemetry raw event schema | Runtime events have a clear boundary between application context, runtime identity, raw payload, and correlation result. | Improved. Ingest now rejects application context inside raw telemetry payloads and validates minimum event-specific fields for exec, process, file, network, policy, abnormal process tree, and resource-pressure events. `telemetry ingest-jsonl --json` maps filtered Tetragon/Falco/LoongCollector JSONL into the normalized schema and emits `receiver_summary` plus per-line `row_results` with detected format, event type, identity keys, correlation method, and skip/failure evidence. JSONL and Falco ingest run runtime-policy evaluation by default and return `policy_decisions` / `policy_decision_ids`; `--no-policy` keeps a pure receiver path. `scripts/accept_falco_risk_realistic.sh` verifies a Falco-style stream through telemetry correlation, risk/response creation, explain, timeline, object materialization, evidence manifest, and `graph verify`. `graph verify` revalidates stored telemetry-source payloads after unwrapping correlation metadata. |
| Telemetry/timeline pagination | High-volume runtime event and timeline queries must be page-bounded and machine-verifiable. | Improved. `telemetry list --json` returns `limit`, `cursor`, `next_cursor`, `has_more`, `total_count`, `result_set_id`, and `page_hash`; cursors are opaque keyset tokens over `created_at` and event id. `timeline --json` now exposes the same integrity shape with opaque cursor pagination over the merged causality timeline. Legacy internal list calls remain unbounded for compatibility, while CLI query surfaces default to bounded pages. |
| Raw telemetry retention | High-volume receivers need bounded raw-event growth without deleting evidence required by risk, response, or graph verification. | Initial. `telemetry prune` and daemon `POST /v1/telemetry/retention/prune` remove old unreferenced raw events, while protecting events referenced by telemetry batches, policy decisions, risk signals, or graph edges. `scripts/accept_daemon_evidence_api.sh` verifies daemon retention can delete an old unreferenced event and still pass `graph verify`. |
| Correlation explainability | Users need to know why a raw system event was attached to a given ToolCallScope. | Improved. `telemetry correlations --run/--event --json` emits `agentprovenance.telemetry_correlations/v1` with raw runtime identity, resolved application context, matched binding, matched keys, confidence, time window, and drill-down refs to event/process/timeline/explain views. `graph verify` now accepts runtime-identity bindings as external context anchors for telemetry-only runs while still flagging drift when local process/tool/session rows exist and disagree. |
| Evidence query shape | Evidence can be queried from artifact, file, process, event, tool call, attempt, and risk nodes through stable upstream/downstream/evidence JSON. | MVP done. All listed start points are covered with explicit `--depth`, `--limit`, and `--cursor` traversal controls. Policy-decision, risk-signal, and response-action graph edges are persisted and verified. |
| QBS impact model | QBS is treated as a workload/evaluation influence that affects execution cadence, evidence volume, storage pressure, adapter boundaries, and downstream consumption. It is not the evidence query layer. | Direction corrected in docs. Concrete QBS assumptions still need to be specified once the exact QBS contract is fixed. |
| Adapter readiness | The provenance model clearly separates agent, sandbox, telemetry, artifact, and snapshot adapters from core correlation/query/provenance logic. | MVP done. `agentprov adapter list/inspect` exposes capability contracts for agent, sandbox, telemetry, artifact, and snapshot adapters, including identity keys, boundaries, and QBS impact. |
| Security evidence | Risk signals, baseline deviations, and response actions are first-class graph objects and queryable records rather than side effects hidden inside policy output. | Improved. Policy-derived risk/response records are queryable, telemetry ingest can create them automatically, and baseline checks now compare process/file/network/risk/runtime feature vectors, persist deviation records, and create baseline-derived risk signals. `agentprov security risks/deviations/responses --json` now emits schema versions, result/page hashes, and drill-down refs back to event/process/timeline/explain views. `graph verify` now rejects non-allow policy decisions without risk signals or response actions, risk signals without policy/event linkage, responses with mismatched risk/policy references, missing risk->response graph edges, invalid action types, and missing response targets. Falco-style metadata-IP, private-CIDR, and secret-path rows are covered by `scripts/accept_falco_risk_realistic.sh`. |
| External evaluator protocol | Evaluator/RL/dataset consumers need programmable signals rather than YAML runtime policy decisions, but AgentProvenance should not own their reward policy. | Improved. `signal context --run` emits `agentprovenance.eval_context/v1`; `signal batch-context` emits EvalContext JSONL for batch/shard/run-list consumers; `signal run --external` passes one context to an external process over stdin; `signal import` validates returned `EvalSignal` records; `signal import-batch` validates JSONL `EvalReport` batches. Daemon mode supports `GET /v1/signal/context`, `POST /v1/signal/run`, and `POST /v1/signal/import`; it intentionally does not expose remote shell execution for external evaluators. Built-in signals remain available for smoke coverage. `python/agentprov_eval` and the `agentprov` import alias provide a thin SDK with `Registry`, `@rule`, `run_batch_pipeline`, `evaluate_batch`, `reports_jsonl`, and CLI-backed capture/query helpers. `run_batch_pipeline(...)` covers the Deploy 1 offline loop: record batch, export contexts, evaluate Python rules, import reports, export batch forensics, and return a summary. Acceptance verifies built-in output, decorator-registered Python evaluator execution, batch context export, imported signal validation, batch import validation, daemon API coverage, and the one-call Deploy 1 batch pipeline. |
| Demo evidence | The branch-heavy coding demo shows artifact lineage, content hash, diff/blame, taint, response-gate behavior, replay, trajectory, and audit evidence as a stress demo. | MVP done for CLI evidence. Acceptance now checks object refs for artifact, diff, blame, replay, trajectory, audit, record, and policy-decision objects. |
| README positioning | README explains why this is Git-like provenance rather than a trace dashboard or sandbox manager, and the repository layout separates core, substrate, stress-demo, and experimental code paths. | Done. README has the positioning, Phase 2 object-store semantics, timeline surface, and cleaned implementation layout. |

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
- `evidence_manifest`

Every object is stored under `.agentprov/provenance/objects/sha256/` and indexed
in SQLite through `provenance_objects`.
Use `graph objects --run <run_id>` or `graph objects --run <run_id> --json` to
inspect object type, source id, hash, parent hashes, path, size, and created
time. Add `--limit` and `--cursor <next_cursor>` to page large object sets.
Each page includes a stable `result_set_id` for the logical query and a
`page_hash` for the returned page content.

## Next Hardening Steps

1. Define the QBS impact model once the exact QBS contract is clear: expected
   cadence, fanout/trajectory volume, query/consumption pattern, and evidence
   retention pressure.
2. Add explicit orphan lifecycle actions for zero-SDK record, such as
   observe-only, terminate, detach, or export-forensics.
3. Promote adapter contracts from static registry to plugin-loaded adapters with
   versioned manifests.
4. Add deeper object-level replay/materialization tests for high-volume
   telemetry runs and longer-lived zero-SDK recordings with multiple overlapping
   child process windows.
