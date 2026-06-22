# Compliance Evidence Mapping

AgentProvenance provides evidence-backed self-assessment mappings for agent
security frameworks. It does not certify compliance, provide legal advice, or
replace a qualified third-party audit.

The mapping layer is intentionally downstream of the provenance model:

```text
runtime telemetry + execution context + provenance DAG + risk/response evidence
  -> framework control mapping
  -> covered / partial / missing / not_applicable
```

## Built-in Profiles

`agentprov compliance frameworks` lists the built-in mapping profiles:

- `owasp-asi`: OWASP Agentic Security style risk mapping.
- `nist-rfi-2026-00206`: NIST AI agent security assessment question mapping.

These are mapping profiles, not normative copies of the upstream documents.
They should be reviewed and customized before use in a formal assessment.

## Commands

```sh
agentprov compliance frameworks
agentprov compliance map --framework owasp-asi --run <run_id>
agentprov compliance map --framework nist-rfi-2026-00206 --run <run_id>
agentprov compliance report --framework owasp-asi --run <run_id> --json
```

`map` defaults to human output. `report` emits the same mapping as structured
JSON using schema `agentprovenance.compliance_mapping/v1`.

## Evidence Sources

The resolver reads current run evidence from:

- `timeline`-compatible events
- runtime telemetry events
- execution context bindings
- sessions and tool calls
- policy decisions
- risk signals
- baseline deviations
- response actions
- telemetry batch manifests
- forensics bundles
- content-addressed provenance objects
- graph edges
- snapshots and taint state

The output keeps concrete `evidence_refs` such as:

```text
runtime_event/evt-...
tool_call/tool-...
binding/bind-...
policy_decision/dec-...
risk_signal/risk-...
baseline_deviation/dev-...
response_action/action-...
telemetry_batch/telbatch-...
forensics_bundle/bundle-...
provenance_object/<sha256>
graph_edge/edge-...
```

These refs are intended to be followed with `timeline`, `graph explain`,
`security risks`, `security deviations`, `security responses`, `forensics
export`, or object inspection commands.

## Status Semantics

- `covered`: required evidence exists for the control.
- `partial`: related evidence exists, but at least one important evidence class
  is missing.
- `missing`: no matching run evidence was found.
- `not_applicable`: the run contains evidence that the control is not relevant
  for this execution, such as a single-agent run for inter-agent communication.

## Boundary

Compliance mapping is a reporting surface over evidence AgentProvenance already
has. It should not become a broad GRC workflow engine. The core product remains
execution observability, runtime causality, Git-like provenance, risk evidence,
and auditability for sandboxed agents.
