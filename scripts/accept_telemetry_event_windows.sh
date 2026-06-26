#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DATA_DIR="${AGENTPROV_ACCEPT_TELEMETRY_WINDOWS_DATA_DIR:-.agentprov-telemetry-windows-accept}"
BIN="${AGENTPROV_ACCEPT_TELEMETRY_WINDOWS_BIN:-$(mktemp "${TMPDIR:-/tmp}/agentprov-telemetry-windows-bin.XXXXXX")}"
WINDOWS_JSON="/tmp/agentprov-telemetry-windows.json"

cleanup() {
  rm -rf "$DATA_DIR" "$BIN" "$WINDOWS_JSON"
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

echo "== bind runtime identity"
"$BIN" --data-dir "$DATA_DIR" telemetry bind \
  --run run-telemetry-windows \
  --session session-telemetry-windows \
  --tool-call tool-telemetry-windows \
  --process process-telemetry-windows \
  --container-id container-falco-demo \
  --pid 4242 \
  --started-at 2000-01-01T00:00:00.000000000Z \
  >/tmp/agentprov-telemetry-windows-bind.txt

echo "== ingest Falco stream"
"$BIN" --data-dir "$DATA_DIR" telemetry ingest-falco \
  --run run-telemetry-windows \
  --file examples/telemetry/falco-risk-events.jsonl \
  --json >/tmp/agentprov-telemetry-windows-ingest.json

echo "== query telemetry event windows"
"$BIN" --data-dir "$DATA_DIR" telemetry windows --run run-telemetry-windows --window 60 --json >"$WINDOWS_JSON"
WINDOWS_OUTPUT="$(cat "$WINDOWS_JSON")"
assert_contains "$WINDOWS_OUTPUT" '"schema_version": "agentprovenance.telemetry_event_windows/v1"'
assert_contains "$WINDOWS_OUTPUT" '"result_set_id": "sha256:'
assert_contains "$WINDOWS_OUTPUT" '"page_hash": "sha256:'

python3 - "$WINDOWS_JSON" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)

assert data["schema_version"] == "agentprovenance.telemetry_event_windows/v1"
assert data["filter"]["run_id"] == "run-telemetry-windows"
assert data["filter"]["window_seconds"] == 60
windows = data["windows"]
assert len(windows) == 4, windows
by_type = {row["event_type"]: row for row in windows}
for event_type in ("execve", "metadata_ip", "private_cidr", "secret_path"):
    assert event_type in by_type, by_type
    assert by_type[event_type]["event_count"] == 1, by_type[event_type]
    assert by_type[event_type]["resolved_count"] == 1, by_type[event_type]
assert by_type["execve"]["high_risk_count"] == 0
assert by_type["metadata_ip"]["high_risk_count"] == 1
assert by_type["private_cidr"]["high_risk_count"] == 1
assert by_type["secret_path"]["high_risk_count"] == 1
print("telemetry window assertions ok")
PY

echo "== assert human table"
HUMAN_OUTPUT="$("$BIN" --data-dir "$DATA_DIR" telemetry windows --run run-telemetry-windows --window 60)"
assert_contains "$HUMAN_OUTPUT" 'RUN'
assert_contains "$HUMAN_OUTPUT" 'metadata_ip'
assert_contains "$HUMAN_OUTPUT" 'secret_path'

echo "Telemetry event window acceptance passed"
