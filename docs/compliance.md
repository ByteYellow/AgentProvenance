# Compliance Evidence Mapping

English | [中文](zh-CN/compliance.md)

AgentProvenance maps detection rules and their results in a run to security
framework profiles, including OWASP Agentic Security and the NIST AI agent
security assessment questions. The result is an evidence-backed self-assessment,
not certification, legal advice, or a replacement for a qualified third-party
audit.

```sh
./agentprov compliance frameworks
./agentprov compliance frameworks --ruleset examples/compliance/custom-ruleset.yaml
./agentprov compliance validate --ruleset examples/compliance/custom-ruleset.yaml
./agentprov compliance map --framework owasp-asi --run <run_id>
./agentprov compliance map --framework owasp-asi --run <run_id> --only ASI05,ASI10,TRACE
./agentprov compliance explain --framework owasp-asi --run <run_id> --item ASI05
./agentprov compliance gaps --framework owasp-asi --run <run_id>
./agentprov compliance gaps --framework owasp-asi --run <run_id> --no-rule-only --json
./agentprov compliance map --framework enterprise-agent-review --ruleset examples/compliance/custom-ruleset.yaml --run <run_id>
./agentprov compliance report --framework nist-rfi-2026-00206 --run <run_id> --json
```

## Interpreting the result

Each control reports a status based on the detection rules mapped to it:

| Status | Meaning |
|---|---|
| `enforced` | A mapped rule fired and recorded a deny, quarantine, or kill decision. |
| `detected` | A mapped rule fired without one of those enforcing decisions. |
| `not_triggered` | Mapped rules exist, but none fired in this run. |
| `no_rule` | No detection rule maps to this control. This is a coverage gap. |

`not_triggered` is not a general claim that the control is satisfied. Merely
having a timeline, a risk record, or a graph object does not establish that a
particular threat was detected or prevented.

The `agentprovenance.compliance_rule_mapping/v1` report contains per-control
`rules`, their `hits`, concrete `evidence_refs`, a `gap`, a
`recommended_next_step`, and a `reason`. Hit records include the decision, time,
source event, and whether that hit recorded an enforcing decision. JSON identifies each
control with `control_id`; this report does not add an `item_id` alias.

`compliance gaps` lists `detected` and `no_rule` controls requiring attention.
Use `--no-rule-only` to select only controls without a mapped detector. The old
`--missing-only` option and `covered/partial/missing/not_applicable` statuses do
not describe the current rule-mapping commands.

## Custom frameworks and detection rules

`--ruleset` loads a YAML catalog with `rules`, `frameworks`, and `mappings`.
It extends the built-in catalog; mappings can reuse built-in controls such as
`ASI05`, `ASI10`, or `TRACE` in a local review profile.

A framework catalog and an executable detection rule set serve different
purposes. Pass `--rules` with the deployment's detection-rule YAML when mapping
custom detectors to controls. Adding a framework item alone does not make a
sensor emit the events needed to detect that threat. See
[the sample ruleset](../examples/compliance/custom-ruleset.yaml).

`enforced` is classified from stored policy decisions. It does not by itself
prove operating-system enforcement; inspect the execution path and response
evidence to determine what actually happened.
