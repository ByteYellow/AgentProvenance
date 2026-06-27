#!/usr/bin/env bash
set -euo pipefail

# End-to-end proof that telemetry from the self-owned agentprov eBPF sensor
# (internal/sensor, source="agentprov_ebpf") flows through the SAME pipeline as
# third-party Falco/Tetragon: native JSONL -> ingest -> correlation -> risk ->
# unified security signal. The sensor's live output was verified on the Linux
# lab VM (kernel 6.8); this acceptance runs the macOS-codeable ingest half using
# a fixture identical in shape to what cmd/agentprov-sensor emits.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DATA_DIR="${AGENTPROV_ACCEPT_NATIVE_DATA_DIR:-.agentprov-native-sensor-accept}"
BIN="${AGENTPROV_ACCEPT_NATIVE_BIN:-$(mktemp "${TMPDIR:-/tmp}/agentprov-native-bin.XXXXXX")}"
INGEST_JSON="/tmp/agentprov-native-ingest.json"

cleanup() {
  rm -rf "$DATA_DIR" "$BIN" "$INGEST_JSON"
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

echo "== bind external ToolCallScope anchor (container+time key)"
"$BIN" --data-dir "$DATA_DIR" telemetry bind \
  --run run-native-sensor \
  --session session-native \
  --attempt attempt-native \
  --tool-call tool-native \
  --process process-native \
  --container-id container-native-demo \
  --pid 4242 \
  --started-at 2000-01-01T00:00:00.000000000Z \
  --source external_telemetry >/dev/null

echo "== pipe the sensor stream directly into ingest (--file -, the VM E2E shape)"
# On the Linux VM this is: agentprov-sensor | agentprov telemetry ingest-jsonl --file -
cat examples/telemetry/native-ebpf-events.jsonl \
  | "$BIN" --data-dir "$DATA_DIR" telemetry ingest-jsonl \
    --file - \
    --json >"$INGEST_JSON"

INGEST_OUTPUT="$(cat "$INGEST_JSON")"
assert_contains "$INGEST_OUTPUT" '"detected_format": "native"'
assert_contains "$INGEST_OUTPUT" '"read": 4'
assert_contains "$INGEST_OUTPUT" '"ingested": 4'
assert_contains "$INGEST_OUTPUT" '"policy_decisions": 3'
assert_contains "$INGEST_OUTPUT" '"correlation_method": "container_time_window:container_id+time"'

echo "== assert normalized telemetry carries the self-owned sensor provenance"
TELEMETRY_JSON="$("$BIN" --data-dir "$DATA_DIR" telemetry list --run run-native-sensor --json)"
assert_contains "$TELEMETRY_JSON" '"event_count": 4'
assert_contains "$TELEMETRY_JSON" '"source": "agentprov_ebpf"'
assert_contains "$TELEMETRY_JSON" '"event_type": "execve"'
assert_contains "$TELEMETRY_JSON" '"event_type": "metadata_ip"'
assert_contains "$TELEMETRY_JSON" '"event_type": "private_cidr"'
assert_contains "$TELEMETRY_JSON" '"event_type": "file_write"'
assert_contains "$TELEMETRY_JSON" '"tool_call_id": "tool-native"'

echo "== assert automatic risk signals from own kernel telemetry"
RISKS_JSON="$("$BIN" --data-dir "$DATA_DIR" security risks --run run-native-sensor --json)"
assert_contains "$RISKS_JSON" '"schema_version": "agentprovenance.security_risks/v1"'
assert_contains "$RISKS_JSON" '"count": 3'
assert_contains "$RISKS_JSON" '"recommended_action": "quarantine"'
assert_contains "$RISKS_JSON" '"recommended_action": "deny"'
assert_contains "$RISKS_JSON" '"recommended_action": "kill"'

echo "== assert the loop closes on the unified signal model (security dimension)"
SIGNALS_JSON="$("$BIN" --data-dir "$DATA_DIR" signals list --run run-native-sensor --json)"
assert_contains "$SIGNALS_JSON" '"schema_version": "agentprovenance.signals/v1"'
assert_contains "$SIGNALS_JSON" '"dimension": "security"'

echo "Native sensor risk acceptance passed"
