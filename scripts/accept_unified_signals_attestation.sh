#!/usr/bin/env bash
set -euo pipefail

# Acceptance for the Unified Signal + Attestation merge. Proves the full closed
# loop:
#   Falco/telemetry -> policy risk -> security signal auto-enters unified signals
#   evaluator/import signal -> quality signal
#   cost sample/backfill -> cost signal
#   agentprov signals list --json -> agentprovenance.signals/v1
#   daemon GET /v1/signals -> same schema (CLI and daemon agree)
#   forensics bundle signed; tampered bundle fails verification

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DATA_DIR="${AGENTPROV_ACCEPT_UNIFIED_DATA_DIR:-.agentprov-unified-signals-accept}"
BIN="${AGENTPROV_ACCEPT_UNIFIED_BIN:-$(mktemp "${TMPDIR:-/tmp}/agentprov-unified-bin.XXXXXX")}"
LISTEN="${AGENTPROV_ACCEPT_UNIFIED_LISTEN:-127.0.0.1:18599}"
DAEMON_URL="http://$LISTEN"
RUN="run-unified-signals-accept"
KEYDIR="$(mktemp -d "${TMPDIR:-/tmp}/agentprov-unified-keys.XXXXXX")"
daemon_pid=""

cleanup() {
  if [[ -n "$daemon_pid" ]]; then
    kill "$daemon_pid" >/dev/null 2>&1 || true
    wait "$daemon_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$DATA_DIR" "$BIN" "$KEYDIR" "$DATA_DIR.daemon.log"
}
trap cleanup EXIT

assert_contains() {
  if [[ "$1" != *"$2"* ]]; then
    echo "FAIL: expected output to contain: $2" >&2
    echo "$1" >&2
    exit 1
  fi
}

count_dim() {
  python3 - "$1" "$2" <<'PY'
import json, sys
data = json.loads(sys.argv[1])
print(data.get("counts", {}).get(sys.argv[2], 0))
PY
}

echo "== build agentprov"
GOTOOLCHAIN="${GOTOOLCHAIN:-local}" go build -o "$BIN" ./cmd/agentprov

echo "== init"
"$BIN" --data-dir "$DATA_DIR" init >/dev/null

echo "== bind external ToolCallScope anchor"
"$BIN" --data-dir "$DATA_DIR" telemetry bind \
  --run "$RUN" --session sess --attempt att --tool-call tool-unified --process proc-unified \
  --container-id container-falco-demo --pid 4242 \
  --started-at 2000-01-01T00:00:00.000000000Z --source external_telemetry >/dev/null

echo "== Falco/telemetry -> policy risk -> security signal (live)"
INGEST="$("$BIN" --data-dir "$DATA_DIR" telemetry ingest-falco --file examples/telemetry/falco-risk-events.jsonl --json)"
assert_contains "$INGEST" '"policy_decisions": 3'

SIGNALS="$("$BIN" --data-dir "$DATA_DIR" signals list --run "$RUN" --json)"
assert_contains "$SIGNALS" '"schema_version": "agentprovenance.signals/v1"'
if [[ "$(count_dim "$SIGNALS" security)" -lt 1 ]]; then
  echo "FAIL: no security signals after Falco ingest" >&2
  echo "$SIGNALS" >&2
  exit 1
fi
echo "   security signals: $(count_dim "$SIGNALS" security)"

echo "== evaluator/import signal -> quality signal"
echo '{"signals":[{"name":"task_success","kind":"reward_feature","score":0.9,"reason":"tests pass","tool_call_id":"tool-unified"}]}' \
  | "$BIN" --data-dir "$DATA_DIR" signal import --run "$RUN" --file - --json >/dev/null
SIGNALS="$("$BIN" --data-dir "$DATA_DIR" signals list --run "$RUN" --json)"
if [[ "$(count_dim "$SIGNALS" quality)" -lt 1 ]]; then
  echo "FAIL: no quality signal after import" >&2
  echo "$SIGNALS" >&2
  exit 1
fi
echo "   quality signals: $(count_dim "$SIGNALS" quality)"

echo "== cost sample/backfill -> cost signal"
"$BIN" --data-dir "$DATA_DIR" signals backfill >/dev/null
SIGNALS="$("$BIN" --data-dir "$DATA_DIR" signals list --run "$RUN" --json)"
if [[ "$(count_dim "$SIGNALS" cost)" -lt 1 ]]; then
  echo "FAIL: no cost signal after backfill" >&2
  echo "$SIGNALS" >&2
  exit 1
fi
echo "   cost signals: $(count_dim "$SIGNALS" cost)"

echo "== signals validate (conformance against the contract)"
VALIDATE="$(printf '%s' "$SIGNALS" | "$BIN" signals validate --file -)"
assert_contains "$VALIDATE" "ok schema=agentprovenance.signals/v1"

echo "== graph verify includes unified signals (clean)"
VERIFY="$("$BIN" --data-dir "$DATA_DIR" graph verify --run "$RUN" --json)"
assert_contains "$VERIFY" '"status": "ok"'
assert_contains "$VERIFY" '"error_count": 0'

echo "== dimension filter + 400s"
QUALITY_ONLY="$("$BIN" --data-dir "$DATA_DIR" signals list --run "$RUN" --dimension quality --json)"
assert_contains "$QUALITY_ONLY" '"dimension": "quality"'

echo "== daemon GET /v1/signals matches CLI schema"
"$BIN" --data-dir "$DATA_DIR" daemon serve \
  --listen "$LISTEN" --sample-interval 0 --spool-interval 0 --evidence-interval 0 --gc-interval 0 \
  >"$DATA_DIR.daemon.log" 2>&1 &
daemon_pid=$!
for _ in $(seq 1 80); do
  if curl -fsS "$DAEMON_URL/v1/health" >/dev/null 2>&1; then break; fi
  sleep 0.1
done
DAEMON_SIGNALS="$(curl -fsS "$DAEMON_URL/v1/signals?run=$RUN")"
# Daemon emits compact JSON; CLI --json is indented. Same schema, different
# whitespace, so assert on the compact form here (count_dim parses either).
assert_contains "$DAEMON_SIGNALS" '"schema_version":"agentprovenance.signals/v1"'
for dim in security quality cost; do
  if [[ "$(count_dim "$DAEMON_SIGNALS" "$dim")" != "$(count_dim "$SIGNALS" "$dim")" ]]; then
    echo "FAIL: daemon/CLI $dim count mismatch" >&2
    exit 1
  fi
done
echo "   daemon and CLI agree on all dimensions"

echo "== daemon dimension filter + error codes"
DAEMON_Q="$(curl -fsS "$DAEMON_URL/v1/signals?run=$RUN&dimension=quality")"
assert_contains "$DAEMON_Q" '"signals"'
MISSING_RUN_CODE="$(curl -s -o /dev/null -w '%{http_code}' "$DAEMON_URL/v1/signals")"
[[ "$MISSING_RUN_CODE" == "400" ]] || { echo "FAIL: missing run want 400 got $MISSING_RUN_CODE" >&2; exit 1; }
BAD_DIM_CODE="$(curl -s -o /dev/null -w '%{http_code}' "$DAEMON_URL/v1/signals?run=$RUN&dimension=bogus")"
[[ "$BAD_DIM_CODE" == "400" ]] || { echo "FAIL: bad dimension want 400 got $BAD_DIM_CODE" >&2; exit 1; }
echo "   missing run -> 400, bad dimension -> 400"

echo "== forensics bundle signing + tamper detection"
"$BIN" --data-dir "$DATA_DIR" forensics keygen --priv "$KEYDIR/priv.hex" --pub "$KEYDIR/pub.hex" >/dev/null
EXPORT_JSON="$("$BIN" --data-dir "$DATA_DIR" forensics export "$RUN" --sign-key "$KEYDIR/priv.hex" --json)"
# Parse via JSON: bundle/attestation paths can contain spaces.
IFS=$'\t' read -r BUNDLE ATT SIGNED < <(python3 - "$EXPORT_JSON" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
print("\t".join([d["path"], d.get("attestation_path", ""), str(d.get("signed", False))]))
PY
)
[[ "$SIGNED" == "True" ]] || { echo "FAIL: bundle not signed" >&2; exit 1; }
VERIFY_ATT="$("$BIN" forensics verify-attestation "$BUNDLE" "$ATT" --pub-key "$KEYDIR/pub.hex")"
assert_contains "$VERIFY_ATT" "ok attestation verifies"

echo '{"tampered":true}' > "$BUNDLE"
if "$BIN" forensics verify-attestation "$BUNDLE" "$ATT" --pub-key "$KEYDIR/pub.hex" >/dev/null 2>&1; then
  echo "FAIL: tampered bundle passed verification" >&2
  exit 1
fi
echo "   signed bundle verifies; tampered bundle rejected"

echo ""
echo "PASS accept_unified_signals_attestation"
