#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DATA_DIR="${AGENTPROV_ACCEPT_SIGNAL_DATA_DIR:-.agentprov-signal-accept}"
BIN="${AGENTPROV_ACCEPT_SIGNAL_BIN:-$(mktemp "${TMPDIR:-/tmp}/agentprov-signal-bin.XXXXXX")}"

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
GOTOOLCHAIN="${GOTOOLCHAIN:-local}" go build -o "$BIN" ./cmd/agentprov

echo "== init signal fixture"
rm -rf "$DATA_DIR"
"$BIN" --data-dir "$DATA_DIR" init >/tmp/agentprov-signal-init.txt
mkdir -p "$DATA_DIR/signal-base" "$DATA_DIR/signal-workspace" "$DATA_DIR/artifacts"
printf "print('old')\n" > "$DATA_DIR/signal-base/app.py"
printf "print('new')\n" > "$DATA_DIR/signal-workspace/app.py"
printf "patch\n" > "$DATA_DIR/artifacts/result.patch"

DB="$DATA_DIR/agentprov.db"
BASE_PATH="$(cd "$DATA_DIR/signal-base" && pwd)"
WORKSPACE_PATH="$(cd "$DATA_DIR/signal-workspace" && pwd)"
ARTIFACT_PATH="$(cd "$DATA_DIR/artifacts" && pwd)/result.patch"
NOW="2026-01-01T00:00:00.000000000Z"

sqlite3 "$DB" <<SQL
INSERT INTO snapshots (id, name, kind, source, path, manifest_hash, file_count, bytes, status, created_at)
VALUES ('snap-signal-accept', 'ready', 'ready', 'test', '$BASE_PATH', 'hash', 1, 32, 'ready', '$NOW');
INSERT INTO rollouts (id, run_id, base_snapshot_id, status, fanout, winner_attempt_id, promotion_id, risk_status, created_at, updated_at)
VALUES ('rollout-signal-accept', 'run-signal-accept', 'snap-signal-accept', 'completed', 1, 'attempt-signal-accept', '', 'clean', '$NOW', '$NOW');
INSERT INTO fork_attempts (id, rollout_id, tool_call_id, snapshot_id, workspace_path, fork_ms, strategy, command, status, risk_status, is_winner, artifact_result, score, cost_estimate, created_at)
VALUES ('attempt-signal-accept', 'rollout-signal-accept', 'tool-signal-accept', 'snap-signal-accept', '$WORKSPACE_PATH', 1, 'fix', 'pytest -q', 'passed', 'clean', 1, '$ARTIFACT_PATH', 5, 0.01, '$NOW');
INSERT INTO leases (id, run_id, task_path, task_yaml, status, created_at, updated_at)
VALUES ('lease-signal-accept', 'run-signal-accept', 'task.yaml', '{}', 'allocated', '$NOW', '$NOW');
INSERT INTO sessions (id, lease_id, run_id, workspace_host_path, status, created_at, updated_at)
VALUES ('session-signal-accept', 'lease-signal-accept', 'run-signal-accept', '$WORKSPACE_PATH', 'stopped', '$NOW', '$NOW');
INSERT INTO tool_calls (id, run_id, rollout_id, attempt_id, session_id, command, status, exit_code, result_ref, created_at, started_at, ended_at)
VALUES ('tool-signal-accept', 'run-signal-accept', 'rollout-signal-accept', 'attempt-signal-accept', 'session-signal-accept', 'pytest -q', 'passed', 0, '$ARTIFACT_PATH', '$NOW', '$NOW', '$NOW');
INSERT INTO processes (id, session_id, tool_call_id, command, status, exit_code, started_at, ended_at)
VALUES ('process-signal-accept', 'session-signal-accept', 'tool-signal-accept', 'pytest -q', 'exited', 0, '$NOW', '$NOW');
INSERT INTO events (id, run_id, session_id, tool_call_id, process_id, source, event_type, payload, created_at, correlation_method, correlation_confidence)
VALUES ('evt-signal-accept', 'run-signal-accept', 'session-signal-accept', 'tool-signal-accept', 'process-signal-accept', 'native_runtime', 'execve', '{"argv":["pytest","-q"]}', '$NOW', 'provided_context', 1);
SQL

echo "== run code signal engine"
SIGNAL_JSON="$("$BIN" --data-dir "$DATA_DIR" signal run --run run-signal-accept --json)"
assert_contains "$SIGNAL_JSON" '"schema_version": "agentprovenance.eval_signals/v1"'
assert_contains "$SIGNAL_JSON" '"engine": "builtin-code-signal-engine"'
assert_contains "$SIGNAL_JSON" '"decision_owner": "external_evaluator"'
assert_contains "$SIGNAL_JSON" '"name": "state.file_change_volume"'
assert_contains "$SIGNAL_JSON" '"name": "artifact.presence"'
assert_contains "$SIGNAL_JSON" '"name": "dataset.filter_label"'
assert_contains "$SIGNAL_JSON" '"label": "candidate"'
assert_contains "$SIGNAL_JSON" '"result_set_id": "sha256:'
assert_contains "$SIGNAL_JSON" '"page_hash": "sha256:'

python3 - <<'PY' "$SIGNAL_JSON"
import json
import sys

report = json.loads(sys.argv[1])
signals = {item["name"]: item for item in report["signals"]}
assert signals["state.file_change_volume"]["score"] == 1
assert signals["artifact.presence"]["label"] == "artifact_present"
assert signals["dataset.filter_label"]["kind"] == "dataset_label"
PY

echo "Signal engine acceptance passed"
