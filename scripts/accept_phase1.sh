#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DATA_DIR="${AGENTPROV_ACCEPT_DATA_DIR:-.agentprov-accept-phase1}"
BIN="./agentprov"
PYTHON_BIN="${PYTHON_BIN:-python3}"
SESSION_ID=""

cleanup() {
  if [[ -n "$SESSION_ID" ]]; then
    "$BIN" --data-dir "$DATA_DIR" session rm "$SESSION_ID" >/dev/null 2>&1 || true
  fi
  rm -rf "$DATA_DIR" "$BIN"
}
trap cleanup EXIT

assert_contains() {
  local haystack="$1"
  local needle="$2"
  if ! grep -Fq "$needle" <<<"$haystack"; then
    echo "assertion failed: expected output to contain: $needle" >&2
    echo "$haystack" >&2
    exit 1
  fi
}

echo "== build"
GOTOOLCHAIN="${GOTOOLCHAIN:-local}" go build ./cmd/agentprov

echo "== init"
rm -rf "$DATA_DIR"
"$BIN" --data-dir "$DATA_DIR" init >/dev/null

echo "== adapter contracts"
ADAPTERS_JSON="$DATA_DIR/adapters.json"
DOCKER_ADAPTER_JSON="$DATA_DIR/docker-adapter.json"
TELEMETRY_ADAPTER_JSON="$DATA_DIR/telemetry-adapter.json"
"$BIN" --data-dir "$DATA_DIR" adapter list --json > "$ADAPTERS_JSON"
"$BIN" --data-dir "$DATA_DIR" adapter inspect docker --json > "$DOCKER_ADAPTER_JSON"
"$BIN" --data-dir "$DATA_DIR" adapter inspect filtered-jsonl --json > "$TELEMETRY_ADAPTER_JSON"
"$PYTHON_BIN" - "$ADAPTERS_JSON" "$DOCKER_ADAPTER_JSON" "$TELEMETRY_ADAPTER_JSON" <<'PY'
import json
import sys

adapters_path, docker_path, telemetry_path = sys.argv[1:]
with open(adapters_path, "r", encoding="utf-8") as f:
    adapters = json.load(f)
with open(docker_path, "r", encoding="utf-8") as f:
    docker = json.load(f)
with open(telemetry_path, "r", encoding="utf-8") as f:
    telemetry = json.load(f)

kinds = {a["kind"] for a in adapters}
assert {"agent", "sandbox", "telemetry", "artifact", "snapshot"}.issubset(kinds), kinds
assert docker["kind"] == "sandbox", docker
docker_caps = {c["name"]: c for c in docker["capabilities"]}
assert docker_caps["create_session"]["supported"] is True, docker_caps
assert docker_caps["memory_snapshot"]["supported"] is False, docker_caps
telemetry_caps = {c["name"]: c for c in telemetry["capabilities"]}
assert telemetry_caps["exec_events"]["supported"] is True, telemetry_caps
assert telemetry_caps["kernel_capture"]["supported"] is False, telemetry_caps
assert telemetry["identity_keys"], telemetry
assert telemetry["qbs_impact"], telemetry
PY

echo "== seed coding workspace"
LEASE_ID="$("$BIN" --data-dir "$DATA_DIR" lease create --task examples/tasks/bugfix.yaml)"
SESSION_ID="$("$BIN" --data-dir "$DATA_DIR" session create --lease "$LEASE_ID")"
"$BIN" --data-dir "$DATA_DIR" exec "$SESSION_ID" --stream -- sh -lc 'cat > calculator.py <<'"'"'PY'"'"'
def add(a, b):
    return a - b

def multiply(a, b):
    return a * b
PY
cp calculator.py calculator.py.bug
cat > test_calculator.sh <<'"'"'SH'"'"'
set -eu
grep -q "return a + b" calculator.py
grep -q "return a \* b" calculator.py
echo passed
SH
chmod +x test_calculator.sh' >/dev/null

echo "== snapshot"
"$BIN" --data-dir "$DATA_DIR" snapshot create "$SESSION_ID" --type directory --path /workspace --name ready >/dev/null

echo "== rollout"
ROLLOUT_OUTPUT="$("$BIN" --data-dir "$DATA_DIR" rollout start \
  --run run-phase1-accept \
  --task examples/tasks/bugfix.yaml \
  --snapshot ready \
  --runtime local \
  --fanout 5 \
  --strategy "noop::echo no fix > fix.patch; ./test_calculator.sh::score=contains:passed::artifact=fix.patch" \
  --strategy "wrong-constant::sed 's/return a - b/return 42/' calculator.py > calculator.py.new && mv calculator.py.new calculator.py; diff -u calculator.py.bug calculator.py > fix.patch || true; ./test_calculator.sh::score=contains:passed::artifact=fix.patch" \
  --strategy "syntax-error::printf 'def add(a, b):\n    return a +\n' > calculator.py; diff -u calculator.py.bug calculator.py > fix.patch || true; ./test_calculator.sh::score=contains:passed::artifact=fix.patch" \
  --strategy "partial-comment::printf '\n# TODO fix add later\n' >> calculator.py; diff -u calculator.py.bug calculator.py > fix.patch || true; ./test_calculator.sh::score=contains:passed::artifact=fix.patch" \
  --strategy "correct-add::sed 's/return a - b/return a + b/' calculator.py > calculator.py.new && mv calculator.py.new calculator.py; diff -u calculator.py.bug calculator.py > fix.patch || true; echo fixed > fix-notes.txt; rm calculator.py.bug; ./test_calculator.sh::score=contains:passed::artifact=fix.patch")"
echo "$ROLLOUT_OUTPUT"

ROLLOUT_ID="$(echo "$ROLLOUT_OUTPUT" | sed -n 's/^rollout_id=\([^ ]*\).*/\1/p')"
CORRECT_ATTEMPT="$(echo "$ROLLOUT_OUTPUT" | awk '$5 == "correct-add" {print $1; exit}')"
CORRECT_TOOL_CALL="$(echo "$ROLLOUT_OUTPUT" | awk '$5 == "correct-add" {print $2; exit}')"
CORRECT_SESSION="$(echo "$ROLLOUT_OUTPUT" | awk '$5 == "correct-add" {print $3; exit}')"
CORRECT_PROCESS="$(echo "$ROLLOUT_OUTPUT" | awk '$5 == "correct-add" {print $4; exit}')"
RISKY_ATTEMPT="$(echo "$ROLLOUT_OUTPUT" | awk '$5 == "wrong-constant" {print $1; exit}')"

if [[ -z "$ROLLOUT_ID" || -z "$CORRECT_ATTEMPT" || -z "$CORRECT_TOOL_CALL" || -z "$CORRECT_SESSION" || -z "$CORRECT_PROCESS" || -z "$RISKY_ATTEMPT" ]]; then
  echo "failed to parse rollout ids" >&2
  exit 1
fi
CORRECT_PROCESS_STARTED="$("$BIN" --data-dir "$DATA_DIR" process inspect "$CORRECT_PROCESS" | sed -n 's/^started_at=//p')"
if [[ -z "$CORRECT_PROCESS_STARTED" ]]; then
  echo "failed to parse process started_at" >&2
  exit 1
fi

echo "== telemetry correlation"
"$BIN" --data-dir "$DATA_DIR" telemetry bind \
  --run run-phase1-accept \
  --session "$CORRECT_SESSION" \
  --attempt "$CORRECT_ATTEMPT" \
  --tool-call "$CORRECT_TOOL_CALL" \
  --process "$CORRECT_PROCESS" \
  --container-id "agentprov-local-$CORRECT_ATTEMPT" \
  --cgroup-id "agentprov-cgroup-$CORRECT_ATTEMPT" \
  --pid 424242 \
  --started-at "$CORRECT_PROCESS_STARTED" \
  --source harness_tool_call_scope >/dev/null
"$BIN" --data-dir "$DATA_DIR" telemetry ingest \
  --raw-event raw-execve-correct-add \
  --process "$CORRECT_PROCESS" \
  --source wrapper_runtime \
  --type execve \
  --payload '{"argv":["./test_calculator.sh"]}' >/dev/null
"$BIN" --data-dir "$DATA_DIR" telemetry ingest \
  --raw-event raw-execve-cgroup-correct-add \
  --cgroup-id "agentprov-cgroup-$CORRECT_ATTEMPT" \
  --timestamp "$CORRECT_PROCESS_STARTED" \
  --source tetragon_jsonl \
  --type execve \
  --payload '{"argv":["./delayed_child.sh"],"note":"no tool_call_id in raw event"}' >/dev/null
"$BIN" --data-dir "$DATA_DIR" telemetry ingest \
  --raw-event raw-execve-pid-child-correct-add \
  --pid 424242 \
  --tgid 424242 \
  --ppid 424200 \
  --timestamp "$CORRECT_PROCESS_STARTED" \
  --source tetragon_jsonl \
  --type execve \
  --payload '{"argv":["./async_child.sh"],"note":"pid scoped event without tool_call_id"}' >/dev/null
"$BIN" --data-dir "$DATA_DIR" telemetry ingest \
  --raw-event raw-file-write-correct-add \
  --pid 424242 \
  --tgid 424242 \
  --ppid 424200 \
  --timestamp "$CORRECT_PROCESS_STARTED" \
  --source native_runtime \
  --type file_write \
  --payload '{"path":"calculator.py","op":"write","note":"runtime-observed file mutation"}' >/dev/null
"$BIN" --data-dir "$DATA_DIR" telemetry ingest \
  --raw-event raw-network-container-correct-add \
  --container-id "agentprov-local-$CORRECT_ATTEMPT" \
  --timestamp "$CORRECT_PROCESS_STARTED" \
  --source falco_jsonl \
  --type network_connect \
  --payload '{"dst":"api.example.com:443","note":"container scoped event"}' >/dev/null
TELEMETRY_JSONL="$DATA_DIR/substrate-events.jsonl"
cat > "$TELEMETRY_JSONL" <<JSONL
{"process_exec":{"process":{"pid":424242,"binary":"/bin/sh","arguments":"-lc pytest -q","docker":"agentprov-local-$CORRECT_ATTEMPT"}}}
{"output_fields":{"evt.type":"connect","proc.pid":424242,"proc.ppid":424200,"container.id":"agentprov-local-$CORRECT_ATTEMPT","fd.rip":"api.example.com:443"}}
JSONL
JSONL_OUTPUT="$("$BIN" --data-dir "$DATA_DIR" telemetry ingest-jsonl --format auto --file "$TELEMETRY_JSONL" --json)"
assert_contains "$JSONL_OUTPUT" '"ingested": 2'
assert_contains "$JSONL_OUTPUT" '"failed": 0'
TELEMETRY_OUTPUT="$("$BIN" --data-dir "$DATA_DIR" telemetry list --run run-phase1-accept --type execve)"
assert_contains "$TELEMETRY_OUTPUT" "process_id:process_id"
assert_contains "$TELEMETRY_OUTPUT" "cgroup_time_window:cgroup_id+time"
assert_contains "$TELEMETRY_OUTPUT" "pid_time_window:pid+time"
assert_contains "$TELEMETRY_OUTPUT" "$CORRECT_TOOL_CALL"
FILE_OUTPUT="$("$BIN" --data-dir "$DATA_DIR" telemetry list --run run-phase1-accept --type file_write)"
assert_contains "$FILE_OUTPUT" "file_write"
assert_contains "$FILE_OUTPUT" "$CORRECT_TOOL_CALL"
BINDINGS_OUTPUT="$("$BIN" --data-dir "$DATA_DIR" telemetry bindings --run run-phase1-accept --tool-call "$CORRECT_TOOL_CALL")"
assert_contains "$BINDINGS_OUTPUT" "harness_tool_call_scope"
assert_contains "$BINDINGS_OUTPUT" "424242"
NETWORK_OUTPUT="$("$BIN" --data-dir "$DATA_DIR" telemetry list --run run-phase1-accept --type network_connect)"
assert_contains "$NETWORK_OUTPUT" "container_time_window:container_id+time"
assert_contains "$NETWORK_OUTPUT" "$CORRECT_TOOL_CALL"

echo "== external effect"
"$BIN" --data-dir "$DATA_DIR" effect record \
  --run run-phase1-accept \
  --attempt "$CORRECT_ATTEMPT" \
  --tool-call "$CORRECT_TOOL_CALL" \
  --process "$CORRECT_PROCESS" \
  --type api_call \
  --target api.example.com/v1/tickets \
  --mode dry-run \
  --decision audit \
  --compensation ticket-compensate \
  --payload '{"redacted":true}' >/dev/null
EFFECT_OUTPUT="$("$BIN" --data-dir "$DATA_DIR" effect list --run run-phase1-accept)"
assert_contains "$EFFECT_OUTPUT" "mode=dry-run"
assert_contains "$EFFECT_OUTPUT" "decision=audit"

echo "== quarantine risky branch"
"$BIN" --data-dir "$DATA_DIR" rollout taint "$RISKY_ATTEMPT" --reason "phase1 acceptance risky branch" >/dev/null
ATTEMPTS_OUTPUT="$("$BIN" --data-dir "$DATA_DIR" rollout attempts "$ROLLOUT_ID")"
assert_contains "$ATTEMPTS_OUTPUT" "$RISKY_ATTEMPT"
assert_contains "$ATTEMPTS_OUTPUT" "quarantined"
assert_contains "$ATTEMPTS_OUTPUT" "tainted"

echo "== promotion"
WINNER_OUTPUT="$("$BIN" --data-dir "$DATA_DIR" rollout winner run-phase1-accept)"
assert_contains "$WINNER_OUTPUT" "$CORRECT_ATTEMPT"
assert_contains "$WINNER_OUTPUT" "promotion_status=promoted"
assert_contains "$WINNER_OUTPUT" "risk=clean"
assert_contains "$WINNER_OUTPUT" "watermark="
assert_contains "$WINNER_OUTPUT" "drain_started_at="
assert_contains "$WINNER_OUTPUT" "drain_completed_at="
assert_contains "$WINNER_OUTPUT" "drain_queued_before=1"
assert_contains "$WINNER_OUTPUT" "drain_processed="
assert_contains "$WINNER_OUTPUT" "drain_pending_after=0"

echo "== provenance graph"
"$BIN" --data-dir "$DATA_DIR" graph materialize --run run-phase1-accept >/dev/null
VERIFY_OUTPUT="$("$BIN" --data-dir "$DATA_DIR" graph verify --run run-phase1-accept)"
assert_contains "$VERIFY_OUTPUT" "status=ok"

TRACE_OUTPUT="$("$BIN" --data-dir "$DATA_DIR" graph trace --run run-phase1-accept)"
assert_contains "$TRACE_OUTPUT" "execution_context_bindings:"
assert_contains "$TRACE_OUTPUT" "runtime_causality:"
assert_contains "$TRACE_OUTPUT" "runtime_tool_call_event"
assert_contains "$TRACE_OUTPUT" "runtime_process_event"
assert_contains "$TRACE_OUTPUT" "runtime_process_parent"
assert_contains "$TRACE_OUTPUT" "runtime_event_file"
assert_contains "$TRACE_OUTPUT" "workspace_file/calculator.py"
assert_contains "$TRACE_OUTPUT" "external_effects:"
assert_contains "$TRACE_OUTPUT" "attempt_quarantined"
assert_contains "$TRACE_OUTPUT" "winner_promoted"
assert_contains "$TRACE_OUTPUT" "drain_processed"

EXPLAIN_FILE_OUTPUT="$("$BIN" --data-dir "$DATA_DIR" graph explain --run run-phase1-accept --file calculator.py)"
assert_contains "$EXPLAIN_FILE_OUTPUT" "target=file"
assert_contains "$EXPLAIN_FILE_OUTPUT" "state_diff:"
assert_contains "$EXPLAIN_FILE_OUTPUT" "state_blame:"
assert_contains "$EXPLAIN_FILE_OUTPUT" "runtime_file_events:"
assert_contains "$EXPLAIN_FILE_OUTPUT" "modified_by_attempt"
assert_contains "$EXPLAIN_FILE_OUTPUT" "file_write"
assert_contains "$EXPLAIN_FILE_OUTPUT" "ppid=424200"

echo "== zero-sdk record"
RECORD_WORKDIR="$DATA_DIR/record-workspace"
mkdir -p "$RECORD_WORKDIR"
cat > "$RECORD_WORKDIR/app.py" <<'PY'
value = 1
PY
RECORD_JSON="$DATA_DIR/record.json"
"$BIN" --data-dir "$DATA_DIR" record --json --run run-record-accept --name zero-sdk --workdir "$RECORD_WORKDIR" -- "$PYTHON_BIN" -c 'import subprocess, time; subprocess.Popen(["sleep", "0.8"]); time.sleep(0.08); open("app.py", "w").write("value = 2\n"); open("artifact.txt", "w").write("artifact\n")' > "$RECORD_JSON"
"$BIN" --data-dir "$DATA_DIR" graph materialize --run run-record-accept >/dev/null
RECORD_TRACE="$("$BIN" --data-dir "$DATA_DIR" graph trace --run run-record-accept)"
assert_contains "$RECORD_TRACE" "zero-sdk-record"
assert_contains "$RECORD_TRACE" "runtime_process_parent"
assert_contains "$RECORD_TRACE" "runtime_event_file"
assert_contains "$RECORD_TRACE" "workspace_file/app.py"
RECORD_EXPLAIN="$("$BIN" --data-dir "$DATA_DIR" graph explain --run run-record-accept --file app.py)"
assert_contains "$RECORD_EXPLAIN" "target=file"
assert_contains "$RECORD_EXPLAIN" "modified_by_attempt"
assert_contains "$RECORD_EXPLAIN" "file_write"
RECORD_VERIFY_OUTPUT="$("$BIN" --data-dir "$DATA_DIR" graph verify --run run-record-accept)"
assert_contains "$RECORD_VERIFY_OUTPUT" "status=ok"
RECORD_EXPLAIN_JSON="$DATA_DIR/explain.json"
"$BIN" --data-dir "$DATA_DIR" graph explain --run run-record-accept --file app.py --json > "$RECORD_EXPLAIN_JSON"

VERIFY_JSON="$DATA_DIR/verify.json"
REPLAY_JSON="$DATA_DIR/replay.json"
TRAJECTORIES_JSON="$DATA_DIR/trajectories.json"
DIFF_JSON="$DATA_DIR/diff.json"
BLAME_JSON="$DATA_DIR/blame.json"
CREATED_DIFF_JSON="$DATA_DIR/created-diff.json"
CREATED_BLAME_JSON="$DATA_DIR/created-blame.json"
DELETED_BLAME_JSON="$DATA_DIR/deleted-blame.json"
TOOL_EXPLAIN_JSON="$DATA_DIR/tool-explain.json"
PROCESS_EXPLAIN_JSON="$DATA_DIR/process-explain.json"
EVENT_EXPLAIN_JSON="$DATA_DIR/event-explain.json"
SUBSTRATE_EVENT_EXPLAIN_JSON="$DATA_DIR/substrate-event-explain.json"
RISK_EXPLAIN_JSON="$DATA_DIR/risk-explain.json"
ARTIFACT_EXPLAIN_JSON="$DATA_DIR/artifact-explain.json"
PHASE1_OBJECTS_JSON="$DATA_DIR/phase1-objects.json"
RECORD_OBJECTS_JSON="$DATA_DIR/record-objects.json"
LIMITED_EXPLAIN_JSON="$DATA_DIR/limited-explain.json"
OBJECTS_PAGE1_JSON="$DATA_DIR/objects-page1.json"
OBJECTS_PAGE2_JSON="$DATA_DIR/objects-page2.json"
EXPLAIN_PAGE2_JSON="$DATA_DIR/explain-page2.json"
"$BIN" --data-dir "$DATA_DIR" graph verify --run run-phase1-accept --json > "$VERIFY_JSON"
"$BIN" --data-dir "$DATA_DIR" graph replay --run run-phase1-accept --json > "$REPLAY_JSON"
"$BIN" --data-dir "$DATA_DIR" graph trajectories --run run-phase1-accept --json > "$TRAJECTORIES_JSON"
"$BIN" --data-dir "$DATA_DIR" graph diff --run run-phase1-accept --file calculator.py --json > "$DIFF_JSON"
"$BIN" --data-dir "$DATA_DIR" graph blame --run run-phase1-accept --file calculator.py --json > "$BLAME_JSON"
"$BIN" --data-dir "$DATA_DIR" graph diff --run run-phase1-accept --file fix-notes.txt --json > "$CREATED_DIFF_JSON"
"$BIN" --data-dir "$DATA_DIR" graph blame --run run-phase1-accept --file fix-notes.txt --json > "$CREATED_BLAME_JSON"
"$BIN" --data-dir "$DATA_DIR" graph blame --run run-phase1-accept --file calculator.py.bug --json > "$DELETED_BLAME_JSON"
CORRECT_EVENT="$("$PYTHON_BIN" - "$DATA_DIR/agentprov.db" "$CORRECT_TOOL_CALL" <<'PY'
import sqlite3
import sys
db_path, tool_call = sys.argv[1:]
with sqlite3.connect(db_path) as conn:
    row = conn.execute("SELECT id FROM events WHERE tool_call_id = ? AND event_type = 'file_write' ORDER BY created_at ASC LIMIT 1", (tool_call,)).fetchone()
if row is None:
    raise SystemExit("missing file_write event for correct tool call")
print(row[0])
PY
)"
SUBSTRATE_EVENT="$("$PYTHON_BIN" - "$DATA_DIR/agentprov.db" "$CORRECT_TOOL_CALL" <<'PY'
import sqlite3
import sys
db_path, tool_call = sys.argv[1:]
with sqlite3.connect(db_path) as conn:
    row = conn.execute("SELECT id FROM events WHERE tool_call_id = ? AND source = 'tetragon_jsonl' AND raw_event_id = 'tetragon:1' ORDER BY created_at ASC LIMIT 1", (tool_call,)).fetchone()
if row is None:
    raise SystemExit("missing tetragon jsonl event for correct tool call")
print(row[0])
PY
)"
"$PYTHON_BIN" - "$DATA_DIR/agentprov.db" "$CORRECT_EVENT" <<'PY'
import datetime
import sqlite3
import sys
db_path, event_id = sys.argv[1:]
now = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
with sqlite3.connect(db_path) as conn:
    row = conn.execute("SELECT run_id, session_id FROM events WHERE id = ?", (event_id,)).fetchone()
    if row is None:
        raise SystemExit("missing event for policy decision")
    run_id, session_id = row
    conn.execute(
        "INSERT OR REPLACE INTO policy_decisions (id, event_id, run_id, session_id, rule_id, decision, reason, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("policy-correct-event-accept", event_id, run_id, session_id, "accept-runtime-file-write", "audit", "acceptance risk link", now),
    )
    conn.execute(
        "INSERT OR REPLACE INTO graph_edges (id, run_id, from_id, to_id, edge_type, source_event_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("edge-policy-correct-event-accept", run_id, "runtime_event/" + event_id, "policy_decision/policy-correct-event-accept", "runtime_event_policy_decision", event_id, now),
    )
    conn.execute(
        "INSERT OR REPLACE INTO graph_edges (id, run_id, from_id, to_id, edge_type, source_event_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("edge-policy-correct-session-accept", run_id, "policy_decision/policy-correct-event-accept", session_id, "policy_decision_session", event_id, now),
    )
    conn.commit()
PY
"$BIN" --data-dir "$DATA_DIR" graph materialize --run run-phase1-accept >/dev/null
POST_POLICY_VERIFY_OUTPUT="$("$BIN" --data-dir "$DATA_DIR" graph verify --run run-phase1-accept)"
assert_contains "$POST_POLICY_VERIFY_OUTPUT" "status=ok"
CORRECT_ARTIFACT="$("$PYTHON_BIN" - "$DATA_DIR/agentprov.db" "$CORRECT_ATTEMPT" <<'PY'
import sqlite3
import sys
db_path, attempt = sys.argv[1:]
with sqlite3.connect(db_path) as conn:
    row = conn.execute("SELECT artifact_result FROM fork_attempts WHERE id = ?", (attempt,)).fetchone()
if row is None or not row[0]:
    raise SystemExit("missing artifact result for correct attempt")
print(row[0])
PY
)"
"$BIN" --data-dir "$DATA_DIR" graph explain --tool-call "$CORRECT_TOOL_CALL" --json > "$TOOL_EXPLAIN_JSON"
"$BIN" --data-dir "$DATA_DIR" graph explain --process "$CORRECT_PROCESS" --json > "$PROCESS_EXPLAIN_JSON"
"$BIN" --data-dir "$DATA_DIR" graph explain --event "$CORRECT_EVENT" --json > "$EVENT_EXPLAIN_JSON"
"$BIN" --data-dir "$DATA_DIR" graph explain --event "$SUBSTRATE_EVENT" --json > "$SUBSTRATE_EVENT_EXPLAIN_JSON"
"$BIN" --data-dir "$DATA_DIR" graph explain --risk policy-correct-event-accept --json > "$RISK_EXPLAIN_JSON"
"$BIN" --data-dir "$DATA_DIR" graph explain --artifact "$CORRECT_ARTIFACT" --json > "$ARTIFACT_EXPLAIN_JSON"
"$BIN" --data-dir "$DATA_DIR" graph objects --run run-phase1-accept --json > "$PHASE1_OBJECTS_JSON"
"$BIN" --data-dir "$DATA_DIR" graph objects --run run-record-accept --json > "$RECORD_OBJECTS_JSON"
"$BIN" --data-dir "$DATA_DIR" graph explain --run run-phase1-accept --file calculator.py --depth 4 --limit 2 --json > "$LIMITED_EXPLAIN_JSON"
 "$BIN" --data-dir "$DATA_DIR" graph objects --run run-phase1-accept --limit 2 --json > "$OBJECTS_PAGE1_JSON"
OBJECTS_PAGE1_CURSOR="$("$PYTHON_BIN" - "$OBJECTS_PAGE1_JSON" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)
print(data["next_cursor"])
PY
)"
"$BIN" --data-dir "$DATA_DIR" graph objects --run run-phase1-accept --limit 2 --cursor "$OBJECTS_PAGE1_CURSOR" --json > "$OBJECTS_PAGE2_JSON"
EXPLAIN_PAGE1_CURSOR="$("$PYTHON_BIN" - "$LIMITED_EXPLAIN_JSON" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)
print(data["query"]["next_cursor"])
PY
)"
"$BIN" --data-dir "$DATA_DIR" graph explain --run run-phase1-accept --file calculator.py --depth 4 --limit 2 --cursor "$EXPLAIN_PAGE1_CURSOR" --json > "$EXPLAIN_PAGE2_JSON"

"$PYTHON_BIN" - "$VERIFY_JSON" "$REPLAY_JSON" "$TRAJECTORIES_JSON" "$DIFF_JSON" "$BLAME_JSON" "$CREATED_DIFF_JSON" "$CREATED_BLAME_JSON" "$DELETED_BLAME_JSON" "$RECORD_EXPLAIN_JSON" "$RECORD_JSON" "$TOOL_EXPLAIN_JSON" "$PROCESS_EXPLAIN_JSON" "$EVENT_EXPLAIN_JSON" "$SUBSTRATE_EVENT_EXPLAIN_JSON" "$RISK_EXPLAIN_JSON" "$ARTIFACT_EXPLAIN_JSON" "$PHASE1_OBJECTS_JSON" "$RECORD_OBJECTS_JSON" "$LIMITED_EXPLAIN_JSON" "$OBJECTS_PAGE1_JSON" "$OBJECTS_PAGE2_JSON" "$EXPLAIN_PAGE2_JSON" "$DATA_DIR" "$CORRECT_ATTEMPT" "$RISKY_ATTEMPT" <<'PY'
import json
import os
import sys

verify_path, replay_path, trajectories_path, diff_path, blame_path, created_diff_path, created_blame_path, deleted_blame_path, explain_path, record_path, tool_explain_path, process_explain_path, event_explain_path, substrate_event_explain_path, risk_explain_path, artifact_explain_path, phase1_objects_path, record_objects_path, limited_explain_path, objects_page1_path, objects_page2_path, explain_page2_path, data_dir, correct_attempt, risky_attempt = sys.argv[1:]

with open(verify_path, "r", encoding="utf-8") as f:
    verify = json.load(f)
with open(replay_path, "r", encoding="utf-8") as f:
    replay = json.load(f)
with open(trajectories_path, "r", encoding="utf-8") as f:
    trajectories = json.load(f)
with open(diff_path, "r", encoding="utf-8") as f:
    diff = json.load(f)
with open(blame_path, "r", encoding="utf-8") as f:
    blame = json.load(f)
with open(created_diff_path, "r", encoding="utf-8") as f:
    created_diff = json.load(f)
with open(created_blame_path, "r", encoding="utf-8") as f:
    created_blame = json.load(f)
with open(deleted_blame_path, "r", encoding="utf-8") as f:
    deleted_blame = json.load(f)
with open(explain_path, "r", encoding="utf-8") as f:
    explain = json.load(f)
with open(record_path, "r", encoding="utf-8") as f:
    record = json.load(f)
with open(tool_explain_path, "r", encoding="utf-8") as f:
    tool_explain = json.load(f)
with open(process_explain_path, "r", encoding="utf-8") as f:
    process_explain = json.load(f)
with open(event_explain_path, "r", encoding="utf-8") as f:
    event_explain = json.load(f)
with open(substrate_event_explain_path, "r", encoding="utf-8") as f:
    substrate_event_explain = json.load(f)
with open(risk_explain_path, "r", encoding="utf-8") as f:
    risk_explain = json.load(f)
with open(artifact_explain_path, "r", encoding="utf-8") as f:
    artifact_explain = json.load(f)
with open(phase1_objects_path, "r", encoding="utf-8") as f:
    phase1_objects = json.load(f)
with open(record_objects_path, "r", encoding="utf-8") as f:
    record_objects = json.load(f)
with open(limited_explain_path, "r", encoding="utf-8") as f:
    limited_explain = json.load(f)
with open(objects_page1_path, "r", encoding="utf-8") as f:
    objects_page1 = json.load(f)
with open(objects_page2_path, "r", encoding="utf-8") as f:
    objects_page2 = json.load(f)
with open(explain_page2_path, "r", encoding="utf-8") as f:
    explain_page2 = json.load(f)

assert verify["schema_version"] == "agentprovenance.verify/v1", verify
assert verify["status"] == "ok", verify
assert verify["error_count"] == 0, verify

assert replay["schema_version"] == "agentprovenance.replay/v1", replay
assert replay["mode"] == "plan_only", replay
attempts = replay["rollouts"][0]["attempts"]
by_id = {a["id"]: a for a in attempts}
assert correct_attempt in by_id, by_id.keys()
assert risky_attempt in by_id, by_id.keys()
winner = by_id[correct_attempt]
assert winner["is_winner"] is True, winner
assert winner["replay_blocked"] is False, winner
assert winner["tool_call"]["status"] == "passed", winner
assert any(e["event_type"] == "execve" and e["correlation_method"] == "process_id:process_id" for e in winner["events"]), winner.get("events")
assert any(e["event_type"] == "execve" and e["correlation_method"] == "cgroup_time_window:cgroup_id+time" for e in winner["events"]), winner.get("events")
assert any(e["event_type"] == "execve" and e["correlation_method"] == "pid_time_window:pid+time" for e in winner["events"]), winner.get("events")
assert any(e["event_type"] == "file_write" and e["correlation_method"] == "pid_time_window:pid+time" for e in winner["events"]), winner.get("events")
assert any(e["event_type"] == "network_connect" and e["correlation_method"] == "container_time_window:container_id+time" for e in winner["events"]), winner.get("events")
assert winner["external_effects"][0]["mode"] == "dry-run", winner.get("external_effects")
risky = by_id[risky_attempt]
assert risky["replay_blocked"] is True, risky
assert "risk_tainted" in risky["block_reasons"], risky

assert trajectories["schema_version"] == "agentprovenance.trajectories/v1", trajectories
assert trajectories["decision_owner"] == "external_evaluator", trajectories
trajectory_by_id = {t["attempt_id"]: t for t in trajectories["trajectories"]}
assert correct_attempt in trajectory_by_id, trajectory_by_id.keys()
correct_trajectory = trajectory_by_id[correct_attempt]
assert correct_trajectory["local_candidate_eligible"] is True, correct_trajectory
assert correct_trajectory["tool_call"]["status"] == "passed", correct_trajectory
assert any(e.get("correlation_method") == "cgroup_time_window:cgroup_id+time" for e in correct_trajectory["runtime_events"]), correct_trajectory["runtime_events"]
assert any(e.get("correlation_method") == "pid_time_window:pid+time" for e in correct_trajectory["runtime_events"]), correct_trajectory["runtime_events"]
assert any(e.get("event_type") == "file_write" for e in correct_trajectory["runtime_events"]), correct_trajectory["runtime_events"]
assert any(e.get("correlation_method") == "container_time_window:container_id+time" for e in correct_trajectory["runtime_events"]), correct_trajectory["runtime_events"]
assert correct_trajectory["external_effects"][0]["mode"] == "dry-run", correct_trajectory["external_effects"]
change_types = {c["path"]: c["change_type"] for c in correct_trajectory["file_changes"]}
assert change_types["calculator.py"] == "modified", change_types
assert change_types["fix-notes.txt"] == "created", change_types
assert change_types["calculator.py.bug"] == "deleted", change_types

assert diff["schema_version"] == "agentprovenance.diff/v1", diff
assert diff["file"] == "calculator.py", diff
diff_by_id = {a["attempt_id"]: a for a in diff["attempts"]}
assert diff_by_id[correct_attempt]["changed"] is True, diff_by_id[correct_attempt]
assert any("+    return a + b" in line for line in diff_by_id[correct_attempt]["unified_diff"]), diff_by_id[correct_attempt]

assert blame["schema_version"] == "agentprovenance.blame/v1", blame
blame_by_id = {e["attempt_id"]: e for e in blame["entries"]}
assert blame_by_id[correct_attempt]["reason"] == "modified_by_attempt", blame_by_id[correct_attempt]
assert blame_by_id[correct_attempt]["is_winner"] is True, blame_by_id[correct_attempt]

created_diff_by_id = {a["attempt_id"]: a for a in created_diff["attempts"]}
assert created_diff_by_id[correct_attempt]["changed"] is True, created_diff_by_id[correct_attempt]
assert created_diff_by_id[correct_attempt]["file_exists"] is True, created_diff_by_id[correct_attempt]
assert any(not entry["changed"] for entry in created_diff["attempts"] if entry["attempt_id"] != correct_attempt), created_diff

created_blame_by_id = {e["attempt_id"]: e for e in created_blame["entries"]}
assert created_blame_by_id[correct_attempt]["reason"] == "created_by_attempt", created_blame_by_id[correct_attempt]

deleted_blame_by_id = {e["attempt_id"]: e for e in deleted_blame["entries"]}
assert deleted_blame_by_id[correct_attempt]["reason"] == "deleted_by_attempt", deleted_blame_by_id[correct_attempt]

assert explain["schema_version"] == "agentprovenance.explain/v1", explain
assert explain["target"]["type"] == "file", explain
assert explain["target"]["file"] == "app.py", explain
assert explain["query"]["depth"] == 2, explain["query"]
assert explain["query"]["limit"] == 100, explain["query"]
assert explain["query"]["edge_count"] == len(explain["causality_path"]), explain["query"]
assert explain["file_diff"]["schema_version"] == "agentprovenance.diff/v1", explain
assert explain["file_blame"]["schema_version"] == "agentprovenance.blame/v1", explain
assert any(e["event_type"] == "file_write" for e in explain["runtime_events"]), explain
edge_types = {e["edge_type"] for e in explain["runtime_edges"]}
assert "runtime_event_file" in edge_types, edge_types
assert "runtime_tool_call_file" in edge_types, edge_types
assert explain["upstream"], explain
assert explain["evidence"], explain
assert explain["objects"], explain
assert any(o["type"] == "record_manifest" for o in explain["objects"]), explain["objects"]
assert explain["replay_refs"], explain
ref_kinds = {r["kind"] for r in explain["replay_refs"]}
assert {"attempt", "tool_call", "process", "event", "snapshot"}.issubset(ref_kinds), ref_kinds
assert explain["process_observations"], explain
outlived = [p for p in explain["process_observations"] if p["outlived_root"]]
assert outlived, explain["process_observations"]
assert all(p["boundary"] == "root_pid_descendants+cwd+time_window" for p in explain["process_observations"]), explain["process_observations"]
assert all(p["orphan_policy"] == "observe_only" for p in explain["process_observations"]), explain["process_observations"]
assert any(p.get("evidence_ids") and p.get("policy_decision_ids") for p in outlived), outlived

for target_explain, expected_type in [
    (tool_explain, "tool_call"),
    (process_explain, "process"),
    (event_explain, "event"),
    (risk_explain, "risk"),
    (artifact_explain, "artifact"),
]:
    assert target_explain["schema_version"] == "agentprovenance.explain/v1", target_explain
    assert target_explain["target"]["type"] == expected_type, target_explain
    assert target_explain["target"]["run_id"] == "run-phase1-accept", target_explain
    assert target_explain["runtime_events"], target_explain
    assert target_explain["evidence"], target_explain
    assert target_explain["objects"], target_explain
    assert target_explain["replay_refs"], target_explain
    assert target_explain["causality_path"], target_explain
    kinds = {r["kind"] for r in target_explain["replay_refs"]}
    assert "attempt" in kinds and "tool_call" in kinds and "process" in kinds, (expected_type, kinds)

assert artifact_explain["upstream"], artifact_explain
assert any(e["edge_type"] in {"attempt_artifact", "tool_call_artifact"} for e in artifact_explain["upstream"]), artifact_explain["upstream"]
assert event_explain["risks"], event_explain
assert substrate_event_explain["target"]["type"] == "event", substrate_event_explain
assert substrate_event_explain["runtime_events"], substrate_event_explain
substrate_event = substrate_event_explain["runtime_events"][0]
assert substrate_event["source"] == "tetragon_jsonl", substrate_event
assert substrate_event["event_type"] == "execve", substrate_event
assert substrate_event["telemetry"]["receiver"] == "tetragon", substrate_event
assert substrate_event["telemetry"]["source_format"] == "jsonl", substrate_event
assert substrate_event["telemetry"]["normalized_event_type"] == "execve", substrate_event
assert substrate_event["telemetry"]["schema_status"] == "valid", substrate_event
assert substrate_event["telemetry"]["correlation_status"] == "resolved", substrate_event
assert "pid" in substrate_event["telemetry"]["identity_keys"], substrate_event
assert risk_explain["risks"][0]["id"] == "policy-correct-event-accept", risk_explain
assert any(o["type"] == "policy_decision" and o["source_id"] == "policy-correct-event-accept" for o in risk_explain["objects"]), risk_explain["objects"]

assert limited_explain["schema_version"] == "agentprovenance.explain/v1", limited_explain
assert limited_explain["query"]["depth"] == 4, limited_explain["query"]
assert limited_explain["query"]["limit"] == 2, limited_explain["query"]
assert limited_explain["query"]["truncated"] is True, limited_explain["query"]
assert limited_explain["query"]["next_cursor"], limited_explain["query"]
assert limited_explain["query"]["edge_count"] == 2, limited_explain["query"]
assert len(limited_explain["causality_path"]) == 2, limited_explain["causality_path"]
assert objects_page1["limit"] == 2, objects_page1
assert objects_page1["has_more"] is True, objects_page1
assert objects_page1["next_cursor"], objects_page1
assert objects_page1["result_set_id"].startswith("sha256:"), objects_page1
assert objects_page1["page_hash"].startswith("sha256:"), objects_page1
assert objects_page2["cursor"] == objects_page1["next_cursor"], (objects_page1, objects_page2)
assert objects_page2["result_set_id"] == objects_page1["result_set_id"], (objects_page1, objects_page2)
assert objects_page2["page_hash"].startswith("sha256:"), objects_page2
assert objects_page2["page_hash"] != objects_page1["page_hash"], (objects_page1, objects_page2)
assert objects_page2["object_count"] > 0, objects_page2
page1_hashes = {o["hash"] for o in objects_page1["objects"]}
page2_hashes = {o["hash"] for o in objects_page2["objects"]}
assert page1_hashes.isdisjoint(page2_hashes), (objects_page1, objects_page2)
assert explain_page2["query"]["cursor"] == limited_explain["query"]["next_cursor"], explain_page2["query"]
assert limited_explain["query"]["result_set_id"].startswith("sha256:"), limited_explain["query"]
assert limited_explain["query"]["page_hash"].startswith("sha256:"), limited_explain["query"]
assert explain_page2["query"]["result_set_id"] == limited_explain["query"]["result_set_id"], (limited_explain["query"], explain_page2["query"])
assert explain_page2["query"]["page_hash"].startswith("sha256:"), explain_page2["query"]
assert explain_page2["query"]["page_hash"] != limited_explain["query"]["page_hash"], (limited_explain["query"], explain_page2["query"])
assert explain_page2["query"]["edge_count"] > 0, explain_page2["query"]
page1_edges = {(e["from_id"], e["to_id"], e["edge_type"], e["source_event_id"]) for e in limited_explain["causality_path"]}
page2_edges = {(e["from_id"], e["to_id"], e["edge_type"], e["source_event_id"]) for e in explain_page2["causality_path"]}
assert page1_edges.isdisjoint(page2_edges), (limited_explain["causality_path"], explain_page2["causality_path"])

assert phase1_objects["schema_version"] == "agentprovenance.objects/v1", phase1_objects
assert phase1_objects["run_id"] == "run-phase1-accept", phase1_objects
phase1_object_types = {o["type"] for o in phase1_objects["objects"]}
for required_type in {
    "artifact",
    "diff_manifest",
    "blame_manifest",
    "replay_manifest",
    "trajectory_manifest",
    "audit_manifest",
    "policy_decision",
}:
    assert required_type in phase1_object_types, (required_type, phase1_object_types)
for obj in phase1_objects["objects"]:
    assert obj["hash"].startswith("sha256:"), obj
    assert obj["path"], obj
    assert obj["size_bytes"] > 0, obj
assert any(obj["source_id"] == "policy-correct-event-accept" for obj in phase1_objects["objects"]), phase1_objects["objects"]

assert record_objects["schema_version"] == "agentprovenance.objects/v1", record_objects
assert record_objects["run_id"] == "run-record-accept", record_objects
assert any(o["type"] == "record_manifest" for o in record_objects["objects"]), record_objects["objects"]

assert record["schema_version"] == "agentprovenance.record/v1", record
assert record["run_id"] == "run-record-accept", record
assert record["context_mode"] == "zero_sdk", record
assert record["status"] == "passed", record
assert record["root_pid"] > 0, record
assert record["process_tree_count"] >= 1, record
assert record["orphan_policy"] == "observe_only", record
assert record["post_root_grace_ms"] >= 200, record
assert record["scope_inference"]["boundary"] == "root_pid_descendants+cwd+time_window+file_diff", record
assert record["scope_inference"]["orphan_policy"] == "observe_only", record
assert record["scope_inference"]["post_root_grace_ms"] >= 200, record
assert record["cwd"], record
assert record["time_window"]["started_at"], record
assert record["time_window"]["ended_at"], record
assert record["scope_inference"]["method"] == "zero_sdk_root_process+cwd+time_window+file_diff", record
assert record["changed_file_count"] == 2, record
assert set(record["changed_files"]) == {"app.py", "artifact.txt"}, record

db_path = os.path.join(data_dir, "agentprov.db")
import sqlite3
with sqlite3.connect(db_path) as conn:
    row = conn.execute(
        "SELECT path, parent_hashes FROM provenance_objects WHERE run_id = ? AND object_type = 'record_manifest'",
        ("run-record-accept",),
    ).fetchone()
assert row is not None, "missing record_manifest object"
manifest_path, parent_hashes = row
assert parent_hashes, "record_manifest parent_hashes is empty"
with open(manifest_path, "r", encoding="utf-8") as f:
    record_object = json.load(f)
assert record_object["type"] == "record_manifest", record_object
manifest = record_object["payload"]["manifest"]
assert manifest["schema_version"] == "agentprovenance.record/v1", manifest
assert manifest["run_id"] == "run-record-accept", manifest
assert manifest["root_pid"] == record["root_pid"], (manifest, record)
assert manifest["process_tree_count"] == record["process_tree_count"], (manifest, record)
assert manifest["orphan_policy"] == "observe_only", manifest
assert manifest["post_root_grace_ms"] >= 200, manifest
assert set(manifest["changed_files"]).issuperset({"app.py", "artifact.txt"}), manifest

if any(p.get("outlived_root") for p in manifest.get("observed_processes", [])):
    decision = conn.execute(
        "SELECT COUNT(*) FROM policy_decisions WHERE run_id = ? AND rule_id = 'zero_sdk_orphan_observe_only' AND decision = 'audit'",
        ("run-record-accept",),
    ).fetchone()[0]
    evidence = conn.execute(
        "SELECT COUNT(*) FROM evidence_events WHERE run_id = ? AND event_type = 'orphan_lifecycle_decision'",
        ("run-record-accept",),
    ).fetchone()[0]
    assert decision > 0, "missing orphan lifecycle policy decision"
    assert evidence > 0, "missing orphan lifecycle evidence"
PY

echo "phase1 acceptance: ok"

echo "== cleanup"
"$BIN" --data-dir "$DATA_DIR" session rm "$SESSION_ID" >/dev/null
SESSION_ID=""
