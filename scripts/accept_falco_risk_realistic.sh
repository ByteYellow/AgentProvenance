#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DATA_DIR="${AGENTPROV_ACCEPT_FALCO_RISK_DATA_DIR:-.agentprov-falco-risk-accept}"
BIN="${AGENTPROV_ACCEPT_FALCO_RISK_BIN:-$(mktemp "${TMPDIR:-/tmp}/agentprov-falco-risk-bin.XXXXXX")}"
INGEST_JSON="/tmp/agentprov-falco-risk-ingest.json"

cleanup() {
  rm -rf "$DATA_DIR" "$BIN" "$INGEST_JSON"
}
trap cleanup EXIT

assert_contains() {
  local haystack="$1"
  local needle="$2"
  if [[ "$haystack" != *"$needle"* ]]; then
    echo "expected output to contain: $needle" >&2
    echo "$haystack" >&2
    exit 1
  fi
}

json_expr() {
  local expr="$1"
  python3 - "$expr" "$INGEST_JSON" <<'PY'
import json
import sys

expr, path = sys.argv[1], sys.argv[2]
with open(path) as f:
    data = json.load(f)
print(eval(expr, {"__builtins__": {}}, {"data": data}))
PY
}

echo "== build agentprov"
GOTOOLCHAIN="${GOTOOLCHAIN:-local}" go build -o "$BIN" ./cmd/agentprov

echo "== init"
"$BIN" --data-dir "$DATA_DIR" init

echo "== bind external ToolCallScope anchor"
"$BIN" --data-dir "$DATA_DIR" telemetry bind \
  --run run-falco-risk-realistic \
  --session session-falco-risk \
  --attempt attempt-falco-risk \
  --tool-call tool-falco-risk \
  --process process-falco-risk \
  --container-id container-falco-demo \
  --pid 4242 \
  --started-at 2000-01-01T00:00:00.000000000Z \
  --source external_telemetry >/tmp/agentprov-falco-risk-bind.txt

echo "== ingest Falco risk stream without raw tool_call_id"
"$BIN" --data-dir "$DATA_DIR" telemetry ingest-falco \
  --file examples/telemetry/falco-risk-events.jsonl \
  --json >"$INGEST_JSON"

INGEST_OUTPUT="$(cat "$INGEST_JSON")"
assert_contains "$INGEST_OUTPUT" '"schema_version": "agentprovenance.falco_ingest/v1"'
assert_contains "$INGEST_OUTPUT" '"receiver_summary"'
assert_contains "$INGEST_OUTPUT" '"row_results"'
assert_contains "$INGEST_OUTPUT" '"policy_decisions": 3'
assert_contains "$INGEST_OUTPUT" '"policy_decision_ids"'
assert_contains "$INGEST_OUTPUT" '"detected_format": "falco"'
assert_contains "$INGEST_OUTPUT" '"correlation_method": "container_time_window:container_id+time"'

FIRST_DECISION_ID="$(json_expr '((data.get("batch") or {}).get("policy_decision_ids") or [""])[0]')"
if [[ -z "$FIRST_DECISION_ID" ]]; then
  echo "missing policy decision id" >&2
  cat "$INGEST_JSON" >&2
  exit 1
fi

echo "== assert normalized telemetry and correlation evidence"
TELEMETRY_JSON="$("$BIN" --data-dir "$DATA_DIR" telemetry list --run run-falco-risk-realistic --json)"
assert_contains "$TELEMETRY_JSON" '"schema_version": "agentprovenance.telemetry_events/v1"'
assert_contains "$TELEMETRY_JSON" '"event_count": 4'
assert_contains "$TELEMETRY_JSON" '"event_type": "execve"'
assert_contains "$TELEMETRY_JSON" '"event_type": "metadata_ip"'
assert_contains "$TELEMETRY_JSON" '"event_type": "private_cidr"'
assert_contains "$TELEMETRY_JSON" '"event_type": "secret_path"'
assert_contains "$TELEMETRY_JSON" '"tool_call_id": "tool-falco-risk"'

CORRELATIONS_JSON="$("$BIN" --data-dir "$DATA_DIR" telemetry correlations --run run-falco-risk-realistic --json)"
assert_contains "$CORRELATIONS_JSON" '"schema_version": "agentprovenance.telemetry_correlations/v1"'
assert_contains "$CORRELATIONS_JSON" '"count": 4'
assert_contains "$CORRELATIONS_JSON" '"tool_call_id": "tool-falco-risk"'
assert_contains "$CORRELATIONS_JSON" '"matched_keys"'

METADATA_EVENT_ID="$("$BIN" --data-dir "$DATA_DIR" telemetry list --run run-falco-risk-realistic --type metadata_ip | awk 'NR == 2 {print $1}')"
if [[ -z "$METADATA_EVENT_ID" ]]; then
  echo "missing metadata_ip event" >&2
  exit 1
fi

echo "== assert risk and response evidence"
RISKS_JSON="$("$BIN" --data-dir "$DATA_DIR" security risks --run run-falco-risk-realistic --json)"
assert_contains "$RISKS_JSON" '"schema_version": "agentprovenance.security_risks/v1"'
assert_contains "$RISKS_JSON" '"count": 3'
assert_contains "$RISKS_JSON" '"severity": "high"'
assert_contains "$RISKS_JSON" '"recommended_action": "quarantine"'
assert_contains "$RISKS_JSON" '"recommended_action": "deny"'
assert_contains "$RISKS_JSON" '"recommended_action": "kill"'

RESPONSES_JSON="$("$BIN" --data-dir "$DATA_DIR" security responses --run run-falco-risk-realistic --json)"
assert_contains "$RESPONSES_JSON" '"schema_version": "agentprovenance.security_responses/v1"'
assert_contains "$RESPONSES_JSON" '"count": 3'
assert_contains "$RESPONSES_JSON" '"action_type": "quarantine"'
assert_contains "$RESPONSES_JSON" '"action_type": "deny"'
assert_contains "$RESPONSES_JSON" '"action_type": "kill"'

FLOW_JSON="$("$BIN" --data-dir "$DATA_DIR" observe flow --run run-falco-risk-realistic --json)"
assert_contains "$FLOW_JSON" '"schema_version": "agentprovenance.observability_flow/v1"'
assert_contains "$FLOW_JSON" '"event_type": "metadata_ip"'
assert_contains "$FLOW_JSON" '"policy_decisions"'
assert_contains "$FLOW_JSON" '"response_actions"'

echo "== assert explain and timeline surfaces"
EVENT_EXPLAIN_JSON="$("$BIN" --data-dir "$DATA_DIR" graph explain --event "$METADATA_EVENT_ID" --json)"
assert_contains "$EVENT_EXPLAIN_JSON" '"schema_version": "agentprovenance.explain/v1"'
assert_contains "$EVENT_EXPLAIN_JSON" '"type": "event"'
assert_contains "$EVENT_EXPLAIN_JSON" '"event_type": "metadata_ip"'
assert_contains "$EVENT_EXPLAIN_JSON" '"risks"'
assert_contains "$EVENT_EXPLAIN_JSON" '"responses"'

RISK_EXPLAIN_JSON="$("$BIN" --data-dir "$DATA_DIR" graph explain --risk "$FIRST_DECISION_ID" --json)"
assert_contains "$RISK_EXPLAIN_JSON" '"type": "risk"'
assert_contains "$RISK_EXPLAIN_JSON" '"runtime_events"'
assert_contains "$RISK_EXPLAIN_JSON" '"policy_decision_id"'
assert_contains "$RISK_EXPLAIN_JSON" '"responses"'

TIMELINE_JSON="$("$BIN" --data-dir "$DATA_DIR" timeline --run run-falco-risk-realistic --view causality --json)"
assert_contains "$TIMELINE_JSON" '"schema_version": "agentprovenance.timeline/v1"'
assert_contains "$TIMELINE_JSON" '"execve"'
assert_contains "$TIMELINE_JSON" '"metadata_ip"'
assert_contains "$TIMELINE_JSON" '"policy_decision"'
assert_contains "$TIMELINE_JSON" '"risk_signal"'
assert_contains "$TIMELINE_JSON" '"response_action"'

echo "== assert evidence materialization and verification"
"$BIN" --data-dir "$DATA_DIR" graph materialize --run run-falco-risk-realistic >/tmp/agentprov-falco-risk-materialize.txt
OBJECTS_JSON="$("$BIN" --data-dir "$DATA_DIR" graph objects --run run-falco-risk-realistic --json)"
assert_contains "$OBJECTS_JSON" '"type": "event"'
assert_contains "$OBJECTS_JSON" '"type": "policy_decision"'
assert_contains "$OBJECTS_JSON" '"type": "risk_signal"'
assert_contains "$OBJECTS_JSON" '"type": "response_action"'

EVIDENCE_JSON="$("$BIN" --data-dir "$DATA_DIR" evidence manifest --run run-falco-risk-realistic --materialize --json)"
assert_contains "$EVIDENCE_JSON" '"schema_version": "agentprovenance.evidence_manifest/v1"'
assert_contains "$EVIDENCE_JSON" '"risk_count": 3'
assert_contains "$EVIDENCE_JSON" '"response_count": 3'
assert_contains "$EVIDENCE_JSON" '"object_hash": "sha256:'

VERIFY_JSON="$("$BIN" --data-dir "$DATA_DIR" graph verify --run run-falco-risk-realistic --json)"
assert_contains "$VERIFY_JSON" '"schema_version": "agentprovenance.verify/v1"'
assert_contains "$VERIFY_JSON" '"status": "ok"'

echo "Falco realistic risk acceptance passed"
