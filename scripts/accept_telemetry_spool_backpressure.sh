#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DATA_DIR="${AGENTPROV_ACCEPT_SPOOL_BP_DATA_DIR:-.agentprov-spool-backpressure-accept}"
BIN="${AGENTPROV_ACCEPT_SPOOL_BP_BIN:-$(mktemp "${TMPDIR:-/tmp}/agentprov-spool-bp-bin.XXXXXX")}"
LISTEN="${AGENTPROV_ACCEPT_SPOOL_BP_LISTEN:-127.0.0.1:18575}"
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

post_json_with_status() {
  local path="$1"
  local body="$2"
  local out="$3"
  curl -sS -o "$out" -w '%{http_code}' -X POST "$DAEMON_URL$path" -H 'Content-Type: application/json' -d "$body"
}

get_json() {
  local path="$1"
  curl -fsS "$DAEMON_URL$path"
}

echo "== build agentprov"
GOTOOLCHAIN="${GOTOOLCHAIN:-local}" go build -o "$BIN" ./cmd/agentprov

echo "== start daemon with bounded telemetry spool"
rm -rf "$DATA_DIR" "$DATA_DIR.daemon.log"
"$BIN" --data-dir "$DATA_DIR" daemon serve \
  --listen "$LISTEN" \
  --sample-interval 0 \
  --spool-interval 0 \
  --spool-limit 1 \
  --spool-max-queued 1 \
  --spool-drop-policy reject \
  --evidence-interval 0 \
  --gc-interval 0 >"$DATA_DIR.daemon.log" 2>&1 &
daemon_pid=$!

for _ in $(seq 1 80); do
  if get_json /v1/health >/tmp/agentprov-spool-bp-health.json 2>/dev/null; then
    break
  fi
  sleep 0.1
done
HEALTH="$(cat /tmp/agentprov-spool-bp-health.json 2>/dev/null || true)"
assert_contains "$HEALTH" '"status":"ok"'
assert_contains "$HEALTH" '"spool_max_queued":1'
assert_contains "$HEALTH" '"spool_drop_policy":"reject"'

BODY='{"file":"examples/telemetry/falco-risk-events.jsonl","run_id":"run-spool-backpressure","queued":true}'

echo "== enqueue first telemetry batch"
FIRST_STATUS="$(post_json_with_status /v1/telemetry/ingest-falco "$BODY" /tmp/agentprov-spool-bp-first.json)"
FIRST_JSON="$(cat /tmp/agentprov-spool-bp-first.json)"
if [[ "$FIRST_STATUS" != "200" ]]; then
  echo "expected first ingest status 200, got $FIRST_STATUS" >&2
  echo "$FIRST_JSON" >&2
  exit 1
fi
assert_contains "$FIRST_JSON" '"schema_version":"agentprovenance.daemon_falco_spool/v1"'
assert_contains "$FIRST_JSON" '"status":"queued"'

echo "== second telemetry batch is rejected by backpressure"
SECOND_STATUS="$(post_json_with_status /v1/telemetry/ingest-falco "$BODY" /tmp/agentprov-spool-bp-second.json)"
SECOND_JSON="$(cat /tmp/agentprov-spool-bp-second.json)"
if [[ "$SECOND_STATUS" != "429" ]]; then
  echo "expected second ingest status 429, got $SECOND_STATUS" >&2
  echo "$SECOND_JSON" >&2
  exit 1
fi
assert_contains "$SECOND_JSON" '"schema_version":"agentprovenance.daemon_falco_spool/v1"'
assert_contains "$SECOND_JSON" '"reject_reason":"telemetry_spool_queue_full"'
assert_contains "$SECOND_JSON" '"queued":1'
assert_contains "$SECOND_JSON" '"max_queued":1'

echo "== control API remains responsive under spool backpressure"
HEALTH_AFTER_REJECT="$(get_json /v1/health)"
assert_contains "$HEALTH_AFTER_REJECT" '"status":"ok"'
assert_contains "$HEALTH_AFTER_REJECT" '"queued_spool":1'

echo "Telemetry spool backpressure acceptance passed"
