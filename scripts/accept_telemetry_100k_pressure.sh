#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DATA_DIR="${AGENTPROV_ACCEPT_100K_DATA_DIR:-.agentprov-100k-accept}"
BIN="${AGENTPROV_ACCEPT_100K_BIN:-$(mktemp "${TMPDIR:-/tmp}/agentprov-100k-bin.XXXXXX")}"
LISTEN="${AGENTPROV_ACCEPT_100K_LISTEN:-127.0.0.1:18576}"
EVENT_COUNT="${AGENTPROV_ACCEPT_100K_EVENTS:-100000}"
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

echo "== generate $EVENT_COUNT Falco events"
rm -rf "$DATA_DIR" "$DATA_DIR.daemon.log"
mkdir -p "$DATA_DIR"
python3 - <<'PY' "$DATA_DIR/falco-100k.jsonl" "$EVENT_COUNT"
import json
import sys

path = sys.argv[1]
count = int(sys.argv[2])
with open(path, "w", encoding="utf-8") as f:
    for i in range(count):
        row = {
            "time": "2026-01-01T00:00:00Z",
            "rule": "Terminal shell in container",
            "priority": "Notice",
            "output_fields": {
                "evt.type": "execve",
                "proc.pid": 1000 + i,
                "proc.ppid": 1,
                "container.id": "container-pressure",
                "proc.cmdline": "true",
            },
        }
        f.write(json.dumps(row, separators=(",", ":")) + "\n")
PY

echo "== start daemon"
"$BIN" --data-dir "$DATA_DIR" daemon serve \
  --listen "$LISTEN" \
  --sample-interval 0 \
  --spool-interval 0 \
  --spool-limit 1 \
  --spool-max-queued 2 \
  --spool-drop-policy reject \
  --evidence-interval 0 \
  --gc-interval 0 >"$DATA_DIR.daemon.log" 2>&1 &
daemon_pid=$!

for _ in $(seq 1 80); do
  if get_json /v1/health >/tmp/agentprov-100k-health.json 2>/dev/null; then
    break
  fi
  sleep 0.1
done
HEALTH="$(cat /tmp/agentprov-100k-health.json 2>/dev/null || true)"
assert_contains "$HEALTH" '"status":"ok"'

echo "== enqueue high-volume telemetry batch"
ENQUEUE_JSON="$(post_json /v1/telemetry/ingest-falco '{"file":"'"$DATA_DIR"'/falco-100k.jsonl","run_id":"run-100k-pressure","queued":true,"no_policy":true}')"
assert_contains "$ENQUEUE_JSON" '"schema_version":"agentprovenance.daemon_falco_spool/v1"'
assert_contains "$ENQUEUE_JSON" '"status":"queued"'

echo "== control API remains responsive while high-volume batch is queued"
HEALTH_QUEUED="$(get_json /v1/health)"
assert_contains "$HEALTH_QUEUED" '"status":"ok"'
assert_contains "$HEALTH_QUEUED" '"queued_spool":1'
PRE_QUERY="$(get_json '/v1/telemetry/events?run=run-100k-pressure&limit=5')"
assert_contains "$PRE_QUERY" '"schema_version":"agentprovenance.telemetry_events/v1"'
assert_contains "$PRE_QUERY" '"event_count":0'

echo "== drain high-volume telemetry batch"
PROCESS_JSON="$(post_json /v1/telemetry/spool/process '{"limit":1}')"
assert_contains "$PROCESS_JSON" '"schema_version":"agentprovenance.telemetry_spool_process/v1"'
assert_contains "$PROCESS_JSON" '"processed":1'
if [[ "$EVENT_COUNT" -gt 1000 ]]; then
  assert_contains "$PROCESS_JSON" '"row_results_truncated":true'
fi

echo "== paged query remains bounded after high-volume ingest"
PAGE_JSON="$(get_json '/v1/telemetry/events?run=run-100k-pressure&limit=5')"
assert_contains "$PAGE_JSON" '"schema_version":"agentprovenance.telemetry_events/v1"'
assert_contains "$PAGE_JSON" '"event_count":5'
assert_contains "$PAGE_JSON" '"has_more":true'
assert_contains "$PAGE_JSON" '"next_cursor":"'
assert_contains "$PAGE_JSON" '"total_count":'"$EVENT_COUNT"
assert_contains "$PAGE_JSON" '"result_set_id":"sha256:'
assert_contains "$PAGE_JSON" '"page_hash":"sha256:'

echo "== health remains responsive after high-volume ingest"
HEALTH_DONE="$(get_json /v1/health)"
assert_contains "$HEALTH_DONE" '"status":"ok"'

echo "100k telemetry pressure acceptance passed"
