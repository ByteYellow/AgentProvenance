# Changelog

## v0.4.1 - 2026-07-01

A consolidation-and-fix release on top of `v0.4.0`. No new surfaces — it makes the
compliance mapping defensible, unifies it across CLI and dashboard, and fixes two
display bugs.

### Changed

- Compliance mapping is now **rule-driven with four honest states** instead of
  "any evidence of class X exists":
  - `enforced` (a mapped detection rule fired and blocked),
    `detected` (fired but detect-only), `not_triggered` (rule maps here, did not
    fire), `no_rule` (no detector maps to this control — an honest coverage gap,
    not a fake pass).
  - The dashboard compliance card and the `compliance map` / `gaps` / `explain`
    CLI now share one model (`compliance.MapRunRules`) so they never drift.
  - Expanding a control shows **every individual rule hit** (time, decision,
    reason), each clickable back to its graph node.
- `security.Rule` gained `mode` (enforce | detect) and `controls:` so custom YAML
  detection rules map themselves onto framework controls; detect-mode rules are
  recorded but do not block. See `examples/policies/agentic-security.yaml`.

### Fixed

- Dashboard timeline "detail" and evidence "payload" cells no longer truncate at
  160 chars — the full record is shown, clamped by default and expandable.
- Graph lens no longer renders `tool_call` / `session` / `attempt` / `rollout` /
  `process` id endpoints as generic "unknown" nodes; they are typed by id prefix
  and counted correctly (e.g. the overview "Tool calls" count).

### Removed

- The legacy evidence-class compliance model (`MapRun`, `ResolveEvidence`, and the
  `internal/compliance/evidence.go` loaders) — superseded by the rule-based model.

## v0.4.0 - 2026-06-30

This release turns AgentProvenance from a CLI-first evidence prototype into a
local, replayable provenance dashboard for sandboxed agent execution.

Compared with `v0.3.0`, the main change is the new Graph Explorer and replayable
agent-in-sandbox demo: a signed supply-chain exfiltration capture can now be
imported directly and inspected offline without a Linux/eBPF VM.

### Added

- Added a portable signed demo bundle at `demo/snake-supply-chain/`.
  - Captured a real coding-agent run in a sandbox.
  - Shows a supply-chain install hook reading planted fake secrets and attempting
    metadata-IP egress.
  - Can be replayed with `forensics import` and inspected through the dashboard.
- Added Graph Explorer lenses for query-oriented provenance inspection:
  - Run overview
  - Security
  - Process
  - File/artifact
  - Network egress
  - Data-flow/taint
  - Agent intent
  - Trust/origin
  - Sandbox boundary
- Added bounded graph detail modes:
  - `summary` for grouped, high-signal views
  - `expanded` for selected high-value detail
  - `raw` for drilldown-oriented evidence, not default rendering
- Added focused evidence drilldown from graph nodes and risk signals.
- Added local graph expansion controls for upstream/downstream/children/raw
  evidence exploration.
- Added dashboard artifact preview support for bounded, redacted content preview.
- Added forensics import support for signed portable bundles.
- Added forensics round-trip tests.
- Added compliance rule mapping:
  - `examples/policies/agentic-security.yaml`
  - `internal/compliance` rule-to-control mapping
  - dashboard compliance API and panel
  - policy rule modes for enforcing vs detect-only mappings
- Added dashboard preview tests and graph lens tests.

### Changed

- Reworked the dashboard from a large canonical graph dump into a
  query-oriented evidence surface.
- Reworked README positioning around execution observability, Git-like
  provenance, dashboard replay, and signed evidence.
- Clarified that raw telemetry remains queryable, but the dashboard should not
  render every syscall/event as a graph node by default.
- Narrowed taint derivation so sensitive-data flow is gated by risky egress
  destinations instead of treating every network connection as exfiltration.
- Improved process naming from sampled process data so graph nodes are easier to
  inspect.
- Updated telemetry schema and eBPF sensor documentation to match the shipped
  native sensor surface.
- Updated roadmap/status documentation to reflect the actual implemented
  dashboard, MCP, native sensor, replay, and compliance surfaces.

### Fixed

- Fixed graph summary aggregation counts in dashboard lenses.
- Fixed risk signal clicks to focus the relevant graph path instead of only
  listing raw events.
- Fixed process burst drilldowns so grouped process/event summaries expand to
  the intended evidence set.
- Fixed dashboard labels that made Focused Evidence and Run Timeline look like
  the same surface.
- Fixed clean replay verification and populated Signals panel for the captured
  demo run.

### Demo

The release demo does not require re-running the agent or the eBPF sensor.
Import the signed bundle:

```sh
go build -o /tmp/agentprov ./cmd/agentprov

/tmp/agentprov --data-dir /tmp/snake-replay forensics import \
  demo/snake-supply-chain/run-snake-agent.forensics.json \
  --pub-key demo/snake-supply-chain/attestation.pub

/tmp/agentprov --data-dir /tmp/snake-replay dashboard serve --addr 127.0.0.1:7396
```

Then open `http://127.0.0.1:7396` and select `run-snake-agent`.

The capture scripts under `demo/snake-supply-chain/capture/` are only needed to
reproduce the original Linux/eBPF capture on a compatible VM. They are not
required for replaying the shipped demo.

### Verification

- `go test ./...`
- Dashboard JavaScript syntax check
- Signed forensics import/replay path
- Graph lens and dashboard preview tests

### Known Boundaries

- This is a technical preview, not a production HIDS.
- The project provides local integrity verification and signed evidence export.
  It does not yet provide off-host capture-time tamper-evidence against a
  malicious host root.
- Central evidence service, notification hooks, long-running multi-tenant
  deployment, and hardened production eBPF packaging remain future work.
