#!/usr/bin/env bash
set -euo pipefail

# End-to-end proof of the project's throughline: a captured LLM response (the
# model's decision, via the SSL_read uprobe -> tls_read) is linked in the
# verifiable DAG to the syscalls it caused (exec + egress), through the same
# correlation primitive, and the whole chain materializes + graph-verifies. This
# is "model intent -> system action -> verifiable causal chain" on one graph.
#
# The fixture mirrors the agentprov sensor's normalized output (verified live on
# the Linux lab VM); this acceptance runs the macOS-codeable ingest/DAG half.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DATA_DIR="${AGENTPROV_ACCEPT_LLM_DATA_DIR:-.agentprov-llm-causal-accept}"
BIN="${AGENTPROV_ACCEPT_LLM_BIN:-$(mktemp "${TMPDIR:-/tmp}/agentprov-llm-bin.XXXXXX")}"
INGEST_JSON="/tmp/agentprov-llm-ingest.json"

cleanup() { rm -rf "$DATA_DIR" "$BIN" "$INGEST_JSON"; }
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

echo "== init + bind the agent's ToolCallScope (container+time)"
"$BIN" --data-dir "$DATA_DIR" init >/dev/null
"$BIN" --data-dir "$DATA_DIR" telemetry bind \
  --run run-llm-causal --session s-llm --attempt a-llm \
  --tool-call tool-llm --process proc-llm \
  --container-id container-llm-demo \
  --started-at 2000-01-01T00:00:00.000000000Z \
  --source external_telemetry >/dev/null

echo "== ingest the captured LLM call + the syscalls it caused"
"$BIN" --data-dir "$DATA_DIR" telemetry ingest-jsonl \
  --file examples/telemetry/llm-causal-events.jsonl \
  --json >"$INGEST_JSON"
INGEST="$(cat "$INGEST_JSON")"
assert_contains "$INGEST" '"detected_format": "native"'
assert_contains "$INGEST" '"ingested": 4'

echo "== the LLM response is stored as a hashed preview, not full plaintext"
TLS_JSON="$("$BIN" --data-dir "$DATA_DIR" telemetry list --run run-llm-causal --type tls_read --json)"
assert_contains "$TLS_JSON" '"event_type": "tls_read"'
assert_contains "$TLS_JSON" 'preview_sha256'

echo "== the causal edges: LLM intent -> the exec + egress it caused"
# Two action events (execve + metadata_ip) follow the tls_read in-scope, so two
# llm_intent_caused edges must exist.
EDGE_COUNT="$(sqlite3 "$DATA_DIR/agentprov.db" "SELECT COUNT(*) FROM graph_edges WHERE edge_type='llm_intent_caused' AND run_id='run-llm-causal'")"
if [[ "$EDGE_COUNT" -lt 2 ]]; then
  echo "expected >=2 llm_intent_caused edges, got $EDGE_COUNT" >&2
  exit 1
fi
echo "llm_intent_caused edges = $EDGE_COUNT"

echo "== the metadata-IP egress the model requested also fired a security signal"
RISKS_JSON="$("$BIN" --data-dir "$DATA_DIR" security risks --run run-llm-causal --json)"
assert_contains "$RISKS_JSON" '"reason": "metadata IP access"'

echo "== materialize + verify the chain (signed, tamper-evident objects)"
"$BIN" --data-dir "$DATA_DIR" graph materialize --run run-llm-causal >/dev/null
VERIFY_JSON="$("$BIN" --data-dir "$DATA_DIR" graph verify --run run-llm-causal --json)"
assert_contains "$VERIFY_JSON" '"status": "ok"'

echo "LLM intent-to-action causality acceptance passed"
