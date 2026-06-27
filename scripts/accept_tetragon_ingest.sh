#!/usr/bin/env bash
set -euo pipefail

# Parity acceptance for the Tetragon JSONL receiver (falco and native already
# have dedicated accept scripts; Tetragon only had unit + demo coverage). Binds
# an external ToolCallScope anchor, ingests Tetragon process_exec JSONL via
# `ingest-jsonl --format tetragon`, and asserts it is detected, mapped to an
# execve event, and correlated by container+time.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DATA_DIR="${AGENTPROV_ACCEPT_TETRAGON_DATA_DIR:-.agentprov-tetragon-accept}"
BIN="${AGENTPROV_ACCEPT_TETRAGON_BIN:-$(mktemp "${TMPDIR:-/tmp}/agentprov-tetragon-bin.XXXXXX")}"
INGEST_JSON="/tmp/agentprov-tetragon-ingest.json"

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

echo "== init"
"$BIN" --data-dir "$DATA_DIR" init >/dev/null

echo "== bind external ToolCallScope anchor (container+time)"
"$BIN" --data-dir "$DATA_DIR" telemetry bind \
  --run run-tetragon --session s-tetragon --attempt a-tetragon \
  --tool-call tool-tetragon --process proc-tetragon \
  --container-id agentprov-demo-container \
  --started-at 2000-01-01T00:00:00.000000000Z \
  --source external_telemetry >/dev/null

echo "== ingest Tetragon JSONL (explicit --format tetragon)"
"$BIN" --data-dir "$DATA_DIR" telemetry ingest-jsonl \
  --format tetragon \
  --file examples/telemetry/tetragon-process-exec.jsonl \
  --json >"$INGEST_JSON"

INGEST_OUTPUT="$(cat "$INGEST_JSON")"
assert_contains "$INGEST_OUTPUT" '"detected_format": "tetragon"'
assert_contains "$INGEST_OUTPUT" '"read": 1'
assert_contains "$INGEST_OUTPUT" '"ingested": 1'
assert_contains "$INGEST_OUTPUT" '"correlation_method": "container_time_window:container_id+time"'

echo "== assert normalized + correlated telemetry"
TELEMETRY_JSON="$("$BIN" --data-dir "$DATA_DIR" telemetry list --run run-tetragon --json)"
assert_contains "$TELEMETRY_JSON" '"event_type": "execve"'
assert_contains "$TELEMETRY_JSON" '"source": "tetragon_jsonl"'
assert_contains "$TELEMETRY_JSON" '"tool_call_id": "tool-tetragon"'
assert_contains "$TELEMETRY_JSON" '"correlation_class": "kernel_correlated"'

echo "Tetragon ingest acceptance passed"
