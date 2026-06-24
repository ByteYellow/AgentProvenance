#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DATA_DIR="${AGENTPROV_ACCEPT_ZERO_SDK_DATA_DIR:-.agentprov-zero-sdk-accept}"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/agentprov-zero-sdk-workdir.XXXXXX")"
BIN="${AGENTPROV_ACCEPT_ZERO_SDK_BIN:-$(mktemp "${TMPDIR:-/tmp}/agentprov-zero-sdk-bin.XXXXXX")}"
RECORD_JSON="/tmp/agentprov-zero-sdk-record.json"

cleanup() {
  rm -rf "$DATA_DIR" "$BIN" "$WORKDIR" "$RECORD_JSON"
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

json_field() {
  local field="$1"
  python3 - "$field" "$RECORD_JSON" <<'PY'
import json
import sys

field, path = sys.argv[1], sys.argv[2]
with open(path) as f:
    data = json.load(f)
value = data
for part in field.split("."):
    if isinstance(value, list):
        value = value[int(part)]
    else:
        value = value.get(part, "")
print(value if value is not None else "")
PY
}

echo "== build agentprov"
GOTOOLCHAIN="${GOTOOLCHAIN:-local}" go build -o "$BIN" ./cmd/agentprov

echo "== init"
"$BIN" --data-dir "$DATA_DIR" init

cat >"$WORKDIR/app.py" <<'PY'
VALUE = 1
PY
cat >"$WORKDIR/old.txt" <<'EOF_OLD'
remove me
EOF_OLD
cat >"$WORKDIR/agent_task.py" <<'PY'
import os
import subprocess
import sys
import time

child = subprocess.Popen([
    sys.executable,
    "-c",
    "import pathlib, time; pathlib.Path('child.log').write_text('child-started\\n'); time.sleep(0.35)",
])
pathlib = __import__("pathlib")
pathlib.Path("app.py").write_text("VALUE = 2\n")
pathlib.Path("generated.txt").write_text("artifact=ok\n")
os.remove("old.txt")
time.sleep(0.08)
child.wait()
PY

echo "== record realistic zero-SDK agent command"
"$BIN" --data-dir "$DATA_DIR" record \
  --run run-zero-sdk-realistic \
  --name zero-sdk-realistic \
  --workdir "$WORKDIR" \
  --sample-interval-ms 10 \
  --post-root-grace-ms 250 \
  --json \
  -- python3 agent_task.py >"$RECORD_JSON"

RECORD_OUTPUT="$(cat "$RECORD_JSON")"
assert_contains "$RECORD_OUTPUT" '"schema_version": "agentprovenance.record/v1"'
assert_contains "$RECORD_OUTPUT" '"context_mode": "zero_sdk"'
assert_contains "$RECORD_OUTPUT" '"boundary": "root_pid_descendants+cwd+time_window+file_diff"'
assert_contains "$RECORD_OUTPUT" '"app.py"'
assert_contains "$RECORD_OUTPUT" '"generated.txt"'
assert_contains "$RECORD_OUTPUT" '"old.txt"'

TOOL_CALL_ID="$(json_field tool_call_id)"
PROCESS_ID="$(json_field process_id)"
CONTAINER_ID="$(json_field session_id | sed 's/^record-/agentprov-record-/')"
CHILD_PID="$(python3 - "$RECORD_JSON" <<'PY'
import json
import sys
with open(sys.argv[1]) as f:
    data = json.load(f)
children = data.get("observed_processes") or []
print(children[0]["pid"] if children else "")
PY
)"
CHILD_LAST_SEEN="$(python3 - "$RECORD_JSON" <<'PY'
import json
import sys
with open(sys.argv[1]) as f:
    data = json.load(f)
children = data.get("observed_processes") or []
print(children[0]["last_seen"] if children else "")
PY
)"

if [[ -z "$TOOL_CALL_ID" || -z "$PROCESS_ID" || -z "$CHILD_PID" || -z "$CHILD_LAST_SEEN" ]]; then
  echo "record output missing scope/process identity" >&2
  cat "$RECORD_JSON" >&2
  exit 1
fi

echo "== ingest delayed child runtime event without tool_call_id"
"$BIN" --data-dir "$DATA_DIR" telemetry ingest \
  --run run-zero-sdk-realistic \
  --raw-event raw-zero-sdk-child-exec \
  --container-id "$CONTAINER_ID" \
  --pid "$CHILD_PID" \
  --tgid "$CHILD_PID" \
  --timestamp "$CHILD_LAST_SEEN" \
  --source filtered_telemetry \
  --type execve \
  --payload '{"argv":["python3","child-work"]}' >/tmp/agentprov-zero-sdk-child-ingest.txt

echo "== assert diff and blame"
DIFF_JSON="$("$BIN" --data-dir "$DATA_DIR" graph diff --run run-zero-sdk-realistic --file app.py --json)"
assert_contains "$DIFF_JSON" '"schema_version": "agentprovenance.diff/v1"'
assert_contains "$DIFF_JSON" '"changed": true'
assert_contains "$DIFF_JSON" '+VALUE = 2'

CREATED_BLAME_JSON="$("$BIN" --data-dir "$DATA_DIR" graph blame --run run-zero-sdk-realistic --file generated.txt --json)"
assert_contains "$CREATED_BLAME_JSON" '"schema_version": "agentprovenance.blame/v1"'
assert_contains "$CREATED_BLAME_JSON" '"reason": "created_by_attempt"'

DELETED_BLAME_JSON="$("$BIN" --data-dir "$DATA_DIR" graph blame --run run-zero-sdk-realistic --file old.txt --json)"
assert_contains "$DELETED_BLAME_JSON" '"reason": "deleted_by_attempt"'

echo "== assert causality timeline and child correlation"
TIMELINE_JSON="$("$BIN" --data-dir "$DATA_DIR" timeline --run run-zero-sdk-realistic --view causality --json)"
assert_contains "$TIMELINE_JSON" '"schema_version": "agentprovenance.timeline/v1"'
assert_contains "$TIMELINE_JSON" '"process_observed"'
assert_contains "$TIMELINE_JSON" '"file_write"'
assert_contains "$TIMELINE_JSON" '"execve"'
assert_contains "$TIMELINE_JSON" "\"tool_call_id\": \"$TOOL_CALL_ID\""

CORRELATIONS_JSON="$("$BIN" --data-dir "$DATA_DIR" telemetry correlations --run run-zero-sdk-realistic --event "$(awk '{print $1}' /tmp/agentprov-zero-sdk-child-ingest.txt | sed 's/event_id=//')" --json)"
assert_contains "$CORRELATIONS_JSON" '"schema_version": "agentprovenance.telemetry_correlations/v1"'
assert_contains "$CORRELATIONS_JSON" "\"tool_call_id\": \"$TOOL_CALL_ID\""
assert_contains "$CORRELATIONS_JSON" '"matched_keys"'

PROCESS_JSON="$("$BIN" --data-dir "$DATA_DIR" observe process --run run-zero-sdk-realistic --process "$PROCESS_ID" --json)"
assert_contains "$PROCESS_JSON" '"schema_version": "agentprovenance.observability_process/v1"'
assert_contains "$PROCESS_JSON" "\"tool_call_id\": \"$TOOL_CALL_ID\""
assert_contains "$PROCESS_JSON" '"process_observed"'

echo "== assert evidence and graph verification"
"$BIN" --data-dir "$DATA_DIR" graph materialize --run run-zero-sdk-realistic >/tmp/agentprov-zero-sdk-materialize.txt
VERIFY_JSON="$("$BIN" --data-dir "$DATA_DIR" graph verify --run run-zero-sdk-realistic --json)"
assert_contains "$VERIFY_JSON" '"schema_version": "agentprovenance.verify/v1"'
assert_contains "$VERIFY_JSON" '"status": "ok"'

EVIDENCE_JSON="$("$BIN" --data-dir "$DATA_DIR" evidence manifest --run run-zero-sdk-realistic --materialize --json)"
assert_contains "$EVIDENCE_JSON" '"schema_version": "agentprovenance.evidence_manifest/v1"'
assert_contains "$EVIDENCE_JSON" '"object_hash": "sha256:'
assert_contains "$EVIDENCE_JSON" '"timeline"'
assert_contains "$EVIDENCE_JSON" '"objects"'

REPLAY_JSON="$("$BIN" --data-dir "$DATA_DIR" graph replay --run run-zero-sdk-realistic --json)"
assert_contains "$REPLAY_JSON" '"schema_version": "agentprovenance.replay/v1"'
assert_contains "$REPLAY_JSON" "\"tool_call_id\": \"$TOOL_CALL_ID\""

echo "Zero-SDK realistic observability acceptance passed"
