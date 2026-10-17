#!/usr/bin/env bash
set -euo pipefail

# Portable acceptance of normalized synthetic TLS evidence: pair one HTTP
# exchange by connection identity, correlate its declared command with one exec,
# retain egress as a separate observation, then materialize and verify the graph.
# This fixture tests ingestion and analysis; it does not execute its commands.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agentprov-llm-accept.XXXXXX")"
DATA_DIR="${AGENTPROV_ACCEPT_LLM_DATA_DIR:-$WORK_DIR/data}"
BIN="${AGENTPROV_ACCEPT_LLM_BIN:-$WORK_DIR/agentprov}"
INGEST_JSON="$WORK_DIR/ingest.json"

cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

assert_contains() {
  if [[ "$1" != *"$2"* ]]; then
    echo "expected output to contain: $2" >&2
    echo "$1" >&2
    exit 1
  fi
}

echo "== build agentprov"
GOTOOLCHAIN="${GOTOOLCHAIN:-local}" go build -o "$BIN" ./cmd/agentprov

echo "== initialize a local evidence store"
"$BIN" --data-dir "$DATA_DIR" init >/dev/null
mkdir -p "$WORK_DIR/workspace"
"$BIN" --data-dir "$DATA_DIR" record --run run-llm-causal \
  --workdir "$WORK_DIR/workspace" --post-root-grace-ms 1 -- true >/dev/null
# Bind only the synthetic container scope, not the unrelated setup tool call.
"$BIN" --data-dir "$DATA_DIR" telemetry bind --run run-llm-causal \
  --tool-call '' --container-id container-llm-demo \
  --started-at 2000-01-01T00:00:00Z --source external_telemetry >/dev/null

echo "== ingest synthetic TLS + runtime evidence with full-body opt-in"
AGENTPROV_TLS_CAPTURE_BODY=1 "$BIN" --data-dir "$DATA_DIR" telemetry ingest-jsonl \
  --file examples/telemetry/llm-causal-events.jsonl \
  --run run-llm-causal \
  --json >"$INGEST_JSON"
INGEST="$(cat "$INGEST_JSON")"
assert_contains "$INGEST" '"detected_format": "native"'
assert_contains "$INGEST" '"ingested": 4'

echo "== the LLM response keeps its hash alongside the opted-in body"
TLS_JSON="$("$BIN" --data-dir "$DATA_DIR" telemetry list --run run-llm-causal --type tls_read --json)"
assert_contains "$TLS_JSON" '"event_type": "tls_read"'
assert_contains "$TLS_JSON" 'preview_sha256'

echo "== ingestion does not fabricate response-to-syscall causality"
EDGE_COUNT="$(sqlite3 "$DATA_DIR/agentprov.db" "SELECT COUNT(*) FROM graph_edges WHERE edge_type='llm_intent_caused' AND run_id='run-llm-causal'")"
if [[ "$EDGE_COUNT" -ne 0 ]]; then
  echo "expected no temporal llm_intent_caused edges, got $EDGE_COUNT" >&2
  exit 1
fi
echo "== materialize one identity-based exchange and one command match"
"$BIN" --data-dir "$DATA_DIR" graph materialize-llm --run run-llm-causal >/dev/null
PAIR_COUNT="$(sqlite3 "$DATA_DIR/agentprov.db" "SELECT COUNT(*) FROM graph_edges WHERE edge_type='llm_call' AND id LIKE 'tls-pair-v1-%' AND run_id='run-llm-causal'")"
COMMAND_COUNT="$(sqlite3 "$DATA_DIR/agentprov.db" "SELECT COUNT(*) FROM graph_edges WHERE edge_type='llm_caused' AND run_id='run-llm-causal'")"
if [[ "$PAIR_COUNT" -ne 1 || "$COMMAND_COUNT" -ne 1 ]]; then
  echo "expected one pair and one command match, got $PAIR_COUNT / $COMMAND_COUNT" >&2
  exit 1
fi

echo "== the separately observed metadata-IP egress fired a security signal"
RISKS_JSON="$("$BIN" --data-dir "$DATA_DIR" security risks --run run-llm-causal --json)"
assert_contains "$RISKS_JSON" '"reason": "metadata IP access"'

echo "== materialize + verify content-addressed evidence"
"$BIN" --data-dir "$DATA_DIR" graph materialize --run run-llm-causal >/dev/null
if ! VERIFY_JSON="$("$BIN" --data-dir "$DATA_DIR" graph verify --run run-llm-causal --json)"; then
  echo "$VERIFY_JSON" >&2
  exit 1
fi
assert_contains "$VERIFY_JSON" '"status": "ok"'

echo "LLM intent-to-action causality acceptance passed"
