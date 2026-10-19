# Graph Commands

English | [简体中文](zh-CN/graph-commands.md)

The Git-like provenance surface over content-addressed evidence objects. The
README carries a short summary; this is the complete reference.

For browser-based investigation, see the [Agent session guide](agent-context.md)
for search, cross-Run comparison and selected replay export. The
[investigation demo](../demo/investigation-workflow/README.md) walks through all three
with a pair of signed captures.

```sh
./agentprov graph trace --run run-demo-bugfix
./agentprov graph refs --run run-demo-bugfix
./agentprov graph log --run run-demo-bugfix
./agentprov graph materialize --run run-demo-bugfix
./agentprov graph objects --run run-demo-bugfix
./agentprov graph objects --run run-demo-bugfix --limit 50 --json
./agentprov graph objects --run run-demo-bugfix --limit 50 --cursor <next_cursor> --json
./agentprov graph verify --run run-demo-bugfix
./agentprov graph verify --run run-demo-bugfix --json
./agentprov graph replay --run run-demo-bugfix
./agentprov graph replay --run run-demo-bugfix --json
./agentprov graph trajectories --run run-demo-bugfix --json
./agentprov graph lens --run run-demo-bugfix --lens default --json
./agentprov graph lens --run run-demo-bugfix --lens data-flow-taint --overlay risk --json
./agentprov graph lens --run run-demo-bugfix --lens data-flow-taint --detail expanded --json
./agentprov graph lens --run run-demo-bugfix --lens process --detail raw --focus runtime_event/<event_id> --json
./agentprov graph lens --run run-demo-bugfix --lens process --focus runtime_event/<event_id> --json
./agentprov graph diff --run run-demo-bugfix --file calculator.py
./agentprov graph diff --run run-demo-bugfix --file calculator.py --json
./agentprov graph blame --run run-demo-bugfix --file calculator.py
./agentprov graph blame --run run-demo-bugfix --file calculator.py --json
./agentprov graph explain --run run-demo-bugfix --file calculator.py
./agentprov graph explain --run run-demo-bugfix --file calculator.py --json
./agentprov graph explain --run run-demo-bugfix --file calculator.py --depth 4 --limit 200 --json
./agentprov graph explain --run run-demo-bugfix --file calculator.py --depth 4 --limit 200 --cursor <next_cursor> --json
./agentprov graph explain --tool-call <tool_call_id>
./agentprov graph explain --risk <policy_decision_id> --json
```

## Verification results

`graph verify --json` returns `agentprovenance.verify/v1` with three statuses:

- `ok`: verification completed without integrity errors.
- `failed`: verification completed and found integrity errors, including an unknown Run.
- `unavailable`: a database or other operational error prevented completion. The
  `error` field preserves its cause; issue counts cover only completed checks.

Both `failed` and `unavailable` return a nonzero CLI exit status. The read API
`GET /v1/graph/verify?run=...` returns HTTP 200 for completed checks and HTTP 503
with the same envelope for `unavailable`. Retry after the underlying failure is
resolved. Missing rows are reported as evidence issues; failed queries are not.

Dashboard overviews recheck current evidence on each request. Changing a
relationship or object file is detected even when event/object counts stay the
same. Imported bundle metadata does not replace this check. Runs with more than
5,000 objects show deferred verification; use `agentprov graph verify --run ...`
for their full check.

## Reanalysis and recovery

Transcript reanalysis validates all selected input streams before replacing
stored analysis. A malformed JSON row or assistant content record reports its
source line and retains the last graph. Complete final rows do not require a
trailing newline.

Each TLS, transcript or endpoint reanalysis replaces its own evidence layer in
one transaction. Endpoint replacement includes captured events and their policy
projections. An empty or missing dump directory, malformed metadata, or a missing
body file returns an error and preserves the previous graph. A request without
a recorded response remains a supported partial capture. Endpoint retries replace
counters owned by its policy decisions; unowned legacy counters stay unchanged.

Intent reanalysis commits diffs, graph edges, signals and any newly inferred
tool attribution together. Missing or corrupt model evidence aborts the pass.
Read, write and commit failures preserve the last successful analysis; after
resolving the reported error, rerun the same command. Retrying replaces the
relevant results without changing evidence from unrelated sources.

Policy replay also replaces decisions, risks, responses, signals and policy
counters in one transaction. A failed pass preserves both the prior results and
session state; it does not leave a partially rebuilt risk chain.

Content-addressed files are reused when unchanged and replaced through a
temporary file. A rolled-back pass can leave unreferenced objects on disk; they
are not part of the saved graph or its exports.

## Per-command purpose

| Command | Purpose |
|---|---|
| `trace` | Show execution context, runtime causality, provenance edges, risk, and response-gate evidence |
| `refs` | Emit stable Git-like references for execution scopes, artifact states, artifacts, and decisions |
| `log` | Show chronological execution history |
| `materialize` | Write content-addressed provenance objects |
| `materialize-llm` | Objectify captured LLM request/response bodies and build `llm_call` nodes with `llm_caused` edges for a run |
| `objects` | List content-addressed object refs, hashes, parent hashes, source IDs, paths, and sizes; supports `--limit` and `--cursor` |
| `verify` | Check graph integrity, risk/response evidence chains, taint/response barriers, object hashes, replay generation, drain watermarks, telemetry batch hashes, and orphan lifecycle evidence for outlived zero-SDK child processes |
| `replay` | Emit a plan-only reconstruction of the run |
| `trajectories --json` | Emit per-execution-scope behavior evidence, risk/deviation context, cost, artifacts, and runtime events for external evaluators or RL reward/penalty pipelines |
| `lens` | Project the canonical graph through a Graph Explorer lens. Emits `agentprovenance.graph_lens/v1` with canonical nodes/edges, derived edges, focus state, overlays, layout hints, raw event count, omitted counts, and `--detail summary\|expanded\|raw` |
| `diff` | Compare file state between a base state and execution scopes |
| `blame` | Attribute file state to execution scope, tool call, process, strategy, command, and local candidate status |
| `explain` | Explain a target by combining trace, runtime causality, diff/blame, telemetry receiver details, telemetry batch manifests, process observations, policy, object refs, risk signals, baseline deviations, and response evidence; `--json` emits `agentprovenance.explain/v1` with `upstream`, `downstream`, bounded `causality_path`, `query`, `evidence`, `objects`, `risks`, `telemetry_batches`, `process_observations`, and `replay_refs`; runtime events include receiver/source format, normalized event type, identity keys, schema status, and correlation status; use `--depth`, `--limit`, and `--cursor` to bound and page DAG traversal |
