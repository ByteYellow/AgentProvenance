# Phase 1 Completion Audit

Phase 1 positions AgentProvenance as an immutable execution ledger and state-diff audit engine for autonomous agents, especially coding agents.

It does not try to be a generic scheduler, sandbox platform, LLM trace dashboard, or eBPF security product. The Phase 1 loop is:

```text
ToolCallScope
  -> Runtime Telemetry
  -> Provenance DAG
  -> State Diff / Blame
  -> Taint
  -> Promotion Barrier
  -> Replay / Trajectory / Audit Manifest
```

## Acceptance Matrix

| Requirement | Current evidence |
| --- | --- |
| Product identity is AgentProvenance, not the legacy runtime-management naming | `cmd/agentprov/main.go`, `README.md`, `docs/product.md`, `docs/mvp.md`; repository search for legacy CLI/project names has no hits outside excluded local experiment material. |
| Application context can be bound to runtime telemetry | `telemetry bind`, `execution_context_bindings`, correlation by `process_id`, `pid`, `container_id`, `cgroup_id`, and time window. Covered by `scripts/accept_phase1.sh`. |
| ToolCallID is not required inside raw runtime/security events | Acceptance script injects raw runtime payloads without `tool_call_id`; correlation attaches `run_id/session_id/tool_call_id` from bindings. |
| Delayed or asynchronous child process telemetry remains attributable | Runtime events with PID/PPID/TGID are linked into `runtime_process_parent`, `runtime_process_child_of`, `runtime_process_thread`, and process/tool-call event edges. |
| Runtime causality is a graph invariant, not only display output | `graph verify` now checks runtime event/process/file edges and fails on missing causality edges. Covered by `internal/provenance/verify_test.go`. |
| Best-of-N coding-agent trajectory can be represented | `scripts/demo_coding_agent_best_of_n.sh` forks attempts, records strategies, emits artifacts, traces winning and risky branches, and demonstrates promotion explanation. |
| State diff and blame are queryable | `agentprov graph diff`, `agentprov graph blame`, and `agentprov graph explain --file` show changed file state and attribution. JSON schemas are covered by provenance tests. |
| File mutations connect to runtime evidence | `file_write`/`file_open` events create `runtime_event_file`, `runtime_process_file`, `runtime_tool_call_file`, and `runtime_attempt_file`. |
| Risk can taint branches and block promotion | Risk events can quarantine attempts and taint snapshot lineage; promotion verifies telemetry drain and refuses tainted winners. |
| Evidence can be replayed/audited | `agentprov graph replay`, `agentprov graph verify`, and materialized provenance objects produce replay and audit manifests. |
| Zero-SDK capture exists | `agentprov record -- <command>` snapshots a working directory, executes a command, records changed files, emits runtime file events, and makes diff/blame/explain usable without an SDK. |
| Old CLI code is removed | The legacy CLI entrypoint is deleted; only `cmd/agentprov/main.go` remains. |

## Verified Commands

These commands passed on the current working tree:

```sh
GOTOOLCHAIN=local go test ./...
./scripts/accept_phase1.sh
./scripts/demo_coding_agent_best_of_n.sh
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
