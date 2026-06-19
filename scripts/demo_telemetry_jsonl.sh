#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DATA_DIR="${AGENTPROV_DEMO_DATA_DIR:-.agentprov-demo-telemetry-jsonl}"
BIN="./agentprov"

cleanup() {
  rm -rf "$DATA_DIR" "$BIN"
}
trap cleanup EXIT

echo "== build agentprov"
GOTOOLCHAIN="${GOTOOLCHAIN:-local}" go build ./cmd/agentprov

echo "== init"
"$BIN" --data-dir "$DATA_DIR" init

STARTED_AT="2000-01-01T00:00:00.000000000Z"

echo "== bind ToolCallScope"
"$BIN" --data-dir "$DATA_DIR" telemetry bind \
  --run run-telemetry-jsonl-demo \
  --session session-jsonl-demo \
  --attempt attempt-jsonl-demo \
  --tool-call tool-jsonl-demo \
  --process process-jsonl-demo \
  --container-id agentprov-demo-container \
  --cgroup-id agentprov-demo-cgroup \
  --pid 4242 \
  --started-at "$STARTED_AT" \
  --source demo_tool_call_scope

echo "== ingest Tetragon/Falco/LoongCollector JSONL"
"$BIN" --data-dir "$DATA_DIR" telemetry ingest-jsonl --format tetragon --file examples/telemetry/tetragon-process-exec.jsonl --json
"$BIN" --data-dir "$DATA_DIR" telemetry ingest-jsonl --format falco --file examples/telemetry/falco-network-connect.jsonl --json
"$BIN" --data-dir "$DATA_DIR" telemetry ingest-jsonl --format loongcollector --file examples/telemetry/loongcollector-file-write.jsonl --json

echo "== list normalized telemetry"
"$BIN" --data-dir "$DATA_DIR" telemetry list --run run-telemetry-jsonl-demo

echo "== list telemetry batch manifests"
"$BIN" --data-dir "$DATA_DIR" telemetry batches --run run-telemetry-jsonl-demo

EVENT_ID="$("$BIN" --data-dir "$DATA_DIR" telemetry list --run run-telemetry-jsonl-demo --type execve | awk 'NR == 2 {print $1}')"
if [[ -z "$EVENT_ID" ]]; then
  echo "missing normalized execve event" >&2
  exit 1
fi

echo "== explain substrate event"
"$BIN" --data-dir "$DATA_DIR" graph explain --event "$EVENT_ID" --json
