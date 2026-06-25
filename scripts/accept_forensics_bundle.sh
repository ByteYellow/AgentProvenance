#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DATA_DIR="${AGENTPROV_ACCEPT_FORENSICS_DATA_DIR:-.agentprov-forensics-accept}"
BIN="${AGENTPROV_ACCEPT_FORENSICS_BIN:-$(mktemp "${TMPDIR:-/tmp}/agentprov-forensics-bin.XXXXXX")}"
INGEST_JSON="/tmp/agentprov-forensics-ingest.json"
BUNDLE_JSON="/tmp/agentprov-forensics-export.json"

cleanup() {
  rm -rf "$DATA_DIR" "$BIN" "$INGEST_JSON" "$BUNDLE_JSON"
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

echo "== build agentprov"
GOTOOLCHAIN="${GOTOOLCHAIN:-local}" go build -o "$BIN" ./cmd/agentprov

echo "== init"
"$BIN" --data-dir "$DATA_DIR" init

echo "== bind ToolCallScope for risky runtime stream"
"$BIN" --data-dir "$DATA_DIR" telemetry bind \
  --run run-forensics-accept \
  --session session-forensics-accept \
  --attempt attempt-forensics-accept \
  --tool-call tool-forensics-accept \
  --process process-forensics-accept \
  --container-id container-falco-demo \
  --pid 4242 \
  --started-at 2000-01-01T00:00:00.000000000Z \
  --source external_telemetry >/tmp/agentprov-forensics-bind.txt

echo "== ingest Falco risk stream"
"$BIN" --data-dir "$DATA_DIR" telemetry ingest-falco \
  --file examples/telemetry/falco-risk-events.jsonl \
  --json >"$INGEST_JSON"
INGEST_OUTPUT="$(cat "$INGEST_JSON")"
assert_contains "$INGEST_OUTPUT" '"policy_decisions": 3'

echo "== materialize provenance and export forensics bundle"
"$BIN" --data-dir "$DATA_DIR" graph materialize --run run-forensics-accept >/tmp/agentprov-forensics-materialize.txt
"$BIN" --data-dir "$DATA_DIR" evidence manifest --run run-forensics-accept --materialize --json >/tmp/agentprov-forensics-evidence.json
"$BIN" --data-dir "$DATA_DIR" forensics export run-forensics-accept --json >"$BUNDLE_JSON"

BUNDLE_OUTPUT="$(cat "$BUNDLE_JSON")"
assert_contains "$BUNDLE_OUTPUT" '"schema_version": "agentprovenance.forensics_export/v1"'
assert_contains "$BUNDLE_OUTPUT" '"sha256"'
assert_contains "$BUNDLE_OUTPUT" '"size_bytes"'

python3 - "$BUNDLE_JSON" <<'PY'
import hashlib
import json
import os
import sys

with open(sys.argv[1]) as f:
    exported = json.load(f)
path = exported["path"]
with open(path, "rb") as f:
    raw = f.read()
if hashlib.sha256(raw).hexdigest() != exported["sha256"]:
    raise SystemExit("bundle sha256 mismatch")
bundle = json.loads(raw)
assert bundle["schema_version"] == "agentprovenance.forensics_bundle/v1"
assert bundle["run_id"] == "run-forensics-accept"
assert len(bundle["events"]) == 4
assert len(bundle["policy_decisions"]) == 3
assert len(bundle["risk_signals"]) == 3
assert len(bundle["response_actions"]) == 3
assert len(bundle["graph_edges"]) >= 9
assert bundle["evidence_manifest"]["schema_version"] == "agentprovenance.evidence_manifest/v1"
assert bundle["evidence_manifest"]["security"]["risk_count"] == 3
assert bundle["evidence_manifest"]["security"]["response_count"] == 3
assert any(edge["edge_type"] == "runtime_event_policy_decision" for edge in bundle["graph_edges"])
assert any(edge["edge_type"] == "policy_decision_risk_signal" for edge in bundle["graph_edges"])
assert any(edge["edge_type"] == "risk_signal_response_action" for edge in bundle["graph_edges"])
assert os.path.getsize(path) == exported["size_bytes"]
PY

echo "== verify graph after bundle export"
VERIFY_JSON="$("$BIN" --data-dir "$DATA_DIR" graph verify --run run-forensics-accept --json)"
assert_contains "$VERIFY_JSON" '"schema_version": "agentprovenance.verify/v1"'
assert_contains "$VERIFY_JSON" '"status": "ok"'

echo "Forensics bundle acceptance passed"
