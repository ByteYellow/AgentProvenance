# Phase 1 Completion Audit

Phase 1 positions AgentProvenance as an immutable execution ledger, runtime
observability graph, and state-diff security audit engine for autonomous
agents, especially coding agents.

It does not try to be a generic scheduler, sandbox platform, LLM trace dashboard, or eBPF security product. The Phase 1 loop is:

```text
ToolCallScope
  -> Runtime Telemetry
  -> Provenance DAG
  -> State Diff / Blame
  -> Risk / Deviation
  -> Response / Taint
  -> Replay / Trajectory / Audit Manifest
```

## Acceptance Matrix

| Requirement | Current evidence |
| --- | --- |
| Product identity is AgentProvenance, not legacy runtime-management naming | `cmd/agentprov/main.go`, `README.md`, `docs/product.md`, `docs/mvp.md`; repository search for legacy CLI/project names has no hits outside excluded local experiment material. |
| Application context can be bound to runtime telemetry | `telemetry bind`, `execution_context_bindings`, correlation by `process_id`, `pid`, `container_id`, `cgroup_id`, and time window. Covered by `scripts/accept_phase1.sh`. |
| ToolCallID is not required inside raw runtime/security events | Acceptance script injects raw runtime payloads without `tool_call_id`; correlation attaches `run_id/session_id/tool_call_id` from bindings. |
| Delayed or asynchronous child process telemetry remains attributable | Runtime events with PID/PPID/TGID are linked into `runtime_process_parent`, `runtime_process_child_of`, `runtime_process_thread`, and process/tool-call event edges. |
| Runtime causality is a graph invariant, not only display output | `graph verify` now checks runtime event/process/file edges and fails on missing causality edges. Covered by `internal/provenance/verify_test.go`. |
| Runtime telemetry can be correlated into the graph | `scripts/demo_telemetry_jsonl.sh` binds ToolCallScope context, ingests Falco/Tetragon/LoongCollector-style events without `tool_call_id`, and explains the resulting graph. `scripts/accept_falco_risk_realistic.sh` covers a Falco-style stream where raw rows become correlated telemetry, policy decisions, risk signals, response actions, graph explanations, evidence manifests, and verified DAG state. |
| Runtime telemetry query is paged | `telemetry list --json` emits `result_set_id`, `page_hash`, `has_more`, and opaque `next_cursor`. `scripts/accept_phase1.sh` verifies paged telemetry output through CLI JSON. |
| State diff and blame are queryable | `agentprov graph diff`, `agentprov graph blame`, and `agentprov graph explain --file` show changed file state and attribution. JSON schemas are covered by provenance tests. |
| File mutations connect to runtime evidence | `file_write`/`file_open` events create `runtime_event_file`, `runtime_process_file`, `runtime_tool_call_file`, and `runtime_attempt_file`. |
| Risk can taint branches and block unsafe reuse | Risk events create risk signals, response action records, quarantine attempts, and taint snapshot lineage; the response gate verifies telemetry drain and refuses tainted branches. |
| Evidence can be replayed/audited | `agentprov graph replay`, `agentprov graph verify`, materialized provenance objects, and `forensics export --json` produce replay, audit, and hashed forensics manifests. `scripts/accept_forensics_bundle.sh` verifies bundle sha256 plus embedded evidence/risk/response/graph-edge content. |
| Zero-SDK capture exists | `agentprov record -- <command>` snapshots a working directory, executes a command, records changed files, emits runtime file events, and makes diff/blame/explain usable without an SDK. `scripts/accept_zero_sdk_realistic.sh` covers file modification, creation, deletion, child process observation, delayed child runtime-event correlation without raw `tool_call_id`, evidence materialization, replay, and graph verification. |
| Daemon API boundary exists | `agentprov daemon serve` exposes HTTP endpoints for ToolCallScope binding, paged telemetry event query, Falco ingest/spool, graph verification, evidence manifest materialization, and forensics export. `scripts/accept_daemon_evidence_api.sh` verifies the same risk/evidence path through daemon APIs. |
| Data-plane ingest has a spool/backpressure boundary | Daemon Falco ingest can enqueue into `telemetry_spool_batches`; a background worker processes queued batches and `health` reports `queued_spool` / `spool_max_queued` / `spool_drop_policy`. `--spool-drop-policy=reject` returns structured HTTP 429 rejects when the queue is full; `drop_oldest` records bounded data loss with `drop_reason`. `scripts/accept_daemon_evidence_api.sh` asserts control API responsiveness while a telemetry batch is queued, and `scripts/accept_telemetry_spool_backpressure.sh` verifies queue-full rejection without breaking health queries. |
| Old CLI code is removed | The legacy CLI entrypoint is deleted; only `cmd/agentprov/main.go` remains. |

## Verified Commands

These commands passed on the current working tree:

```sh
GOTOOLCHAIN=local go test ./...
./scripts/accept_phase1.sh
./scripts/accept_zero_sdk_realistic.sh
./scripts/accept_falco_risk_realistic.sh
./scripts/accept_forensics_bundle.sh
./scripts/accept_daemon_evidence_api.sh
./scripts/accept_telemetry_spool_backpressure.sh
./scripts/demo_telemetry_jsonl.sh
git diff --check
rg "<legacy CLI and project names>" . --glob '!test/**' --glob '!gpt55.md'
```

## Boundaries

Phase 1 intentionally does not implement:

- Memory snapshot / VM-level instant clone.
- Full eBPF collector implementation.
- Generic sandbox runtime replacement.
- RL reward or winner selection policy.
- Multi-tenant production control plane.

The next hardening pass should focus on higher-volume telemetry ingestion, durable content-addressed storage, stronger zero-SDK process-tree capture, and a real substrate collector path for Falco/Tetragon/LoongCollector-style events.
