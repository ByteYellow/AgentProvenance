#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DATA_DIR="${AGENTPROV_ACCEPT_DAEMON_DATA_DIR:-.agentprov-daemon-accept}"
BIN="${AGENTPROV_ACCEPT_DAEMON_BIN:-$(mktemp "${TMPDIR:-/tmp}/agentprov-daemon-bin.XXXXXX")}"
LISTEN="${AGENTPROV_ACCEPT_DAEMON_LISTEN:-127.0.0.1:18574}"
DAEMON_URL="http://$LISTEN"

cleanup() {
  if [[ -n "${daemon_pid:-}" ]]; then
    kill "$daemon_pid" >/dev/null 2>&1 || true
    wait "$daemon_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$DATA_DIR" "$BIN"
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

post_json() {
  local path="$1"
  local body="$2"
  curl -fsS -X POST "$DAEMON_URL$path" -H 'Content-Type: application/json' -d "$body"
}

get_json() {
  local path="$1"
  curl -fsS "$DAEMON_URL$path"
}

echo "== build agentprov"
GOTOOLCHAIN="${GOTOOLCHAIN:-local}" go build -o "$BIN" ./cmd/agentprov

echo "== start daemon"
rm -rf "$DATA_DIR" "$DATA_DIR.daemon.log"
"$BIN" --data-dir "$DATA_DIR" daemon serve \
  --listen "$LISTEN" \
  --sample-interval 0 \
  --spool-interval 0 \
  --spool-limit 10 \
  --evidence-interval 0 \
  --gc-interval 0 >"$DATA_DIR.daemon.log" 2>&1 &
daemon_pid=$!

for _ in $(seq 1 80); do
  if get_json /v1/health >/tmp/agentprov-daemon-health.json 2>/dev/null; then
    break
  fi
  sleep 0.1
done
HEALTH="$(cat /tmp/agentprov-daemon-health.json 2>/dev/null || true)"
assert_contains "$HEALTH" '"status":"ok"'

echo "== bind ToolCallScope through daemon API"
BIND_JSON="$(post_json /v1/telemetry/bind '{
  "run_id":"run-daemon-api-accept",
  "session_id":"session-daemon-api-accept",
  "attempt_id":"attempt-daemon-api-accept",
  "tool_call_id":"tool-daemon-api-accept",
  "process_id":"process-daemon-api-accept",
  "container_id":"container-falco-demo",
  "pid":4242,
  "root_pid":4242,
  "started_at":"2000-01-01T00:00:00.000000000Z",
  "binding_source":"daemon_accept",
  "confidence":0.95
}')"
assert_contains "$BIND_JSON" '"schema_version":"agentprovenance.daemon_telemetry_binding/v1"'

echo "== ingest Falco risk stream through daemon API"
INGEST_JSON="$(post_json /v1/telemetry/ingest-falco '{
  "file":"examples/telemetry/falco-risk-events.jsonl",
  "run_id":"run-daemon-api-accept",
  "queued":true
}')"
assert_contains "$INGEST_JSON" '"schema_version":"agentprovenance.daemon_falco_spool/v1"'
assert_contains "$INGEST_JSON" '"status":"queued"'

echo "== assert control API responds while spool is queued"
HEALTH_AFTER_ENQUEUE="$(get_json /v1/health)"
assert_contains "$HEALTH_AFTER_ENQUEUE" '"status":"ok"'
assert_contains "$HEALTH_AFTER_ENQUEUE" '"queued_spool":1'

SPOOL_JSON="$(get_json '/v1/telemetry/spool?run=run-daemon-api-accept')"
assert_contains "$SPOOL_JSON" '"schema_version":"agentprovenance.telemetry_spool/v1"'
assert_contains "$SPOOL_JSON" '"status":"queued"'

echo "== drain telemetry spool explicitly"
SPOOL_PROCESS_JSON="$(post_json /v1/telemetry/spool/process '{"limit":10}')"
assert_contains "$SPOOL_PROCESS_JSON" '"schema_version":"agentprovenance.telemetry_spool_process/v1"'
assert_contains "$SPOOL_PROCESS_JSON" '"processed":1'

SPOOL_JSON="$(get_json '/v1/telemetry/spool?run=run-daemon-api-accept')"
assert_contains "$SPOOL_JSON" '"status":"processed"'
assert_contains "$SPOOL_JSON" '"ingested_count":4'

echo "== verify graph through daemon API"
VERIFY_JSON="$(get_json '/v1/graph/verify?run=run-daemon-api-accept')"
assert_contains "$VERIFY_JSON" '"schema_version":"agentprovenance.verify/v1"'
assert_contains "$VERIFY_JSON" '"status":"ok"'

echo "== materialize evidence manifest through daemon API"
EVIDENCE_JSON="$(get_json '/v1/evidence/manifest?run=run-daemon-api-accept&materialize=1')"
assert_contains "$EVIDENCE_JSON" '"manifest"'
assert_contains "$EVIDENCE_JSON" '"schema_version":"agentprovenance.evidence_manifest/v1"'
assert_contains "$EVIDENCE_JSON" '"risk_count":3'
assert_contains "$EVIDENCE_JSON" '"response_count":3'
assert_contains "$EVIDENCE_JSON" '"object_hash":"sha256:'

echo "== export forensics through daemon API"
FORENSICS_JSON="$(post_json /v1/forensics/export '{"run_id":"run-daemon-api-accept"}')"
assert_contains "$FORENSICS_JSON" '"schema_version":"agentprovenance.forensics_export/v1"'
assert_contains "$FORENSICS_JSON" '"sha256"'
assert_contains "$FORENSICS_JSON" '"size_bytes"'

python3 - <<'PY' "$FORENSICS_JSON"
import hashlib
import json
import os
import sys

exported = json.loads(sys.argv[1])
with open(exported["path"], "rb") as f:
    raw = f.read()
if hashlib.sha256(raw).hexdigest() != exported["sha256"]:
    raise SystemExit("forensics hash mismatch")
bundle = json.loads(raw)
assert bundle["schema_version"] == "agentprovenance.forensics_bundle/v1"
assert bundle["run_id"] == "run-daemon-api-accept"
assert len(bundle["policy_decisions"]) == 3
assert len(bundle["risk_signals"]) == 3
assert len(bundle["response_actions"]) == 3
assert os.path.getsize(exported["path"]) == exported["size_bytes"]
PY

echo "Daemon evidence API acceptance passed"
