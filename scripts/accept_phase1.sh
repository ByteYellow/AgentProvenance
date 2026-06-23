#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DATA_DIR="${AGENTPROV_ACCEPT_DATA_DIR:-.agentprov-phase1-accept}"
BIN="./agentprov"

cleanup() {
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

echo "== build agentprov"
GOTOOLCHAIN="${GOTOOLCHAIN:-local}" go build ./cmd/agentprov

echo "== init"
"$BIN" --data-dir "$DATA_DIR" init

STARTED_AT="2000-01-01T00:00:00.000000000Z"

echo "== bind ToolCallScope"
"$BIN" --data-dir "$DATA_DIR" telemetry bind \
  --run run-phase1-accept \
  --session session-phase1-accept \
  --attempt attempt-phase1-accept \
  --tool-call tool-phase1-accept \
  --process process-phase1-accept \
  --container-id agentprov-phase1-container \
  --cgroup-id agentprov-phase1-cgroup \
  --pid 4242 \
  --started-at "$STARTED_AT" \
  --source phase1_accept

echo "== ingest raw telemetry without tool_call_id"
"$BIN" --data-dir "$DATA_DIR" telemetry ingest-jsonl --format tetragon --file examples/telemetry/tetragon-process-exec.jsonl --json >/tmp/agentprov-accept-tetragon.json
"$BIN" --data-dir "$DATA_DIR" telemetry ingest-jsonl --format falco --file examples/telemetry/falco-network-connect.jsonl --json >/tmp/agentprov-accept-falco.json
"$BIN" --data-dir "$DATA_DIR" telemetry ingest-jsonl --format loongcollector --file examples/telemetry/loongcollector-file-write.jsonl --json >/tmp/agentprov-accept-loongcollector.json

echo "== assert normalized telemetry"
TELEMETRY_OUTPUT="$("$BIN" --data-dir "$DATA_DIR" telemetry list --run run-phase1-accept)"
assert_contains "$TELEMETRY_OUTPUT" "execve"
assert_contains "$TELEMETRY_OUTPUT" "network_connect"
assert_contains "$TELEMETRY_OUTPUT" "file_write"
assert_contains "$TELEMETRY_OUTPUT" "tool-phase1-accept"
TELEMETRY_JSON="$("$BIN" --data-dir "$DATA_DIR" telemetry list --run run-phase1-accept --json)"
assert_contains "$TELEMETRY_JSON" '"schema_version": "agentprovenance.telemetry_events/v1"'
assert_contains "$TELEMETRY_JSON" '"event_count": 3'
assert_contains "$TELEMETRY_JSON" '"tool_call_id": "tool-phase1-accept"'
assert_contains "$TELEMETRY_JSON" '"correlation_method": "pid_time_window:pid+time"'

EVENT_ID="$("$BIN" --data-dir "$DATA_DIR" telemetry list --run run-phase1-accept --type execve | awk 'NR == 2 {print $1}')"
if [[ -z "$EVENT_ID" ]]; then
  echo "missing execve event" >&2
  exit 1
fi

echo "== assert graph explain JSON"
EXPLAIN_JSON="$("$BIN" --data-dir "$DATA_DIR" graph explain --event "$EVENT_ID" --json)"
assert_contains "$EXPLAIN_JSON" '"schema_version": "agentprovenance.explain/v1"'
assert_contains "$EXPLAIN_JSON" '"target"'
assert_contains "$EXPLAIN_JSON" '"type": "event"'
assert_contains "$EXPLAIN_JSON" '"upstream"'
assert_contains "$EXPLAIN_JSON" '"evidence"'
assert_contains "$EXPLAIN_JSON" '"runtime_edges"'
assert_contains "$EXPLAIN_JSON" '"replay_refs"'
assert_contains "$EXPLAIN_JSON" '"tool_call_id": "tool-phase1-accept"'
assert_contains "$EXPLAIN_JSON" '"process_id": "process-phase1-accept"'

echo "== assert graph explain ToolCallScope JSON"
TOOL_EXPLAIN_JSON="$("$BIN" --data-dir "$DATA_DIR" graph explain --tool-call tool-phase1-accept --json)"
assert_contains "$TOOL_EXPLAIN_JSON" '"schema_version": "agentprovenance.explain/v1"'
assert_contains "$TOOL_EXPLAIN_JSON" '"type": "tool_call"'
assert_contains "$TOOL_EXPLAIN_JSON" '"id": "tool-phase1-accept"'
assert_contains "$TOOL_EXPLAIN_JSON" '"runtime_events"'
assert_contains "$TOOL_EXPLAIN_JSON" '"event_type": "execve"'
assert_contains "$TOOL_EXPLAIN_JSON" '"event_type": "network_connect"'
assert_contains "$TOOL_EXPLAIN_JSON" '"event_type": "file_write"'

echo "== assert graph explain process JSON"
PROCESS_EXPLAIN_JSON="$("$BIN" --data-dir "$DATA_DIR" graph explain --process process-phase1-accept --json)"
assert_contains "$PROCESS_EXPLAIN_JSON" '"schema_version": "agentprovenance.explain/v1"'
assert_contains "$PROCESS_EXPLAIN_JSON" '"type": "process"'
assert_contains "$PROCESS_EXPLAIN_JSON" '"id": "process-phase1-accept"'
assert_contains "$PROCESS_EXPLAIN_JSON" '"tool_call_id": "tool-phase1-accept"'
assert_contains "$PROCESS_EXPLAIN_JSON" '"runtime_edges"'

echo "== assert observability flow JSON"
FLOW_JSON="$("$BIN" --data-dir "$DATA_DIR" observe flow --run run-phase1-accept --json)"
assert_contains "$FLOW_JSON" '"schema_version": "agentprovenance.observability_flow/v1"'
assert_contains "$FLOW_JSON" '"tool_call_id": "tool-phase1-accept"'
assert_contains "$FLOW_JSON" '"event_type": "execve"'

echo "Phase 1 observability/provenance acceptance passed"
