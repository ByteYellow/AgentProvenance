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
  --timestamp "$CORRECT_PROCESS_STARTED" \
  --source tetragon_jsonl \
  --type execve \
  --payload '{"argv":["./async_child.sh"],"note":"pid scoped event without tool_call_id"}' >/dev/null
"$BIN" --data-dir "$DATA_DIR" telemetry ingest \
  --raw-event raw-network-container-correct-add \
  --container-id "agentprov-local-$CORRECT_ATTEMPT" \
  --timestamp "$CORRECT_PROCESS_STARTED" \
  --source falco_jsonl \
  --type network_connect \
  --payload '{"dst":"api.example.com:443","note":"container scoped event"}' >/dev/null
TELEMETRY_OUTPUT="$("$BIN" --data-dir "$DATA_DIR" telemetry list --run run-phase1-accept --type execve)"
assert_contains "$TELEMETRY_OUTPUT" "process_id:process_id"
assert_contains "$TELEMETRY_OUTPUT" "cgroup_time_window:cgroup_id+time"
assert_contains "$TELEMETRY_OUTPUT" "pid_time_window:pid+time"
assert_contains "$TELEMETRY_OUTPUT" "$CORRECT_TOOL_CALL"
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

echo "== provenance graph"
"$BIN" --data-dir "$DATA_DIR" graph materialize --run run-phase1-accept >/dev/null
VERIFY_OUTPUT="$("$BIN" --data-dir "$DATA_DIR" graph verify --run run-phase1-accept)"
assert_contains "$VERIFY_OUTPUT" "status=ok"

TRACE_OUTPUT="$("$BIN" --data-dir "$DATA_DIR" graph trace --run run-phase1-accept)"
assert_contains "$TRACE_OUTPUT" "execution_context_bindings:"
assert_contains "$TRACE_OUTPUT" "external_effects:"
assert_contains "$TRACE_OUTPUT" "attempt_quarantined"
assert_contains "$TRACE_OUTPUT" "winner_promoted"

VERIFY_JSON="$DATA_DIR/verify.json"
REPLAY_JSON="$DATA_DIR/replay.json"
TRAJECTORIES_JSON="$DATA_DIR/trajectories.json"
DIFF_JSON="$DATA_DIR/diff.json"
BLAME_JSON="$DATA_DIR/blame.json"
CREATED_DIFF_JSON="$DATA_DIR/created-diff.json"
CREATED_BLAME_JSON="$DATA_DIR/created-blame.json"
DELETED_BLAME_JSON="$DATA_DIR/deleted-blame.json"
"$BIN" --data-dir "$DATA_DIR" graph verify --run run-phase1-accept --json > "$VERIFY_JSON"
"$BIN" --data-dir "$DATA_DIR" graph replay --run run-phase1-accept --json > "$REPLAY_JSON"
"$BIN" --data-dir "$DATA_DIR" graph trajectories --run run-phase1-accept --json > "$TRAJECTORIES_JSON"
"$BIN" --data-dir "$DATA_DIR" graph diff --run run-phase1-accept --file calculator.py --json > "$DIFF_JSON"
"$BIN" --data-dir "$DATA_DIR" graph blame --run run-phase1-accept --file calculator.py --json > "$BLAME_JSON"
"$BIN" --data-dir "$DATA_DIR" graph diff --run run-phase1-accept --file fix-notes.txt --json > "$CREATED_DIFF_JSON"
"$BIN" --data-dir "$DATA_DIR" graph blame --run run-phase1-accept --file fix-notes.txt --json > "$CREATED_BLAME_JSON"
"$BIN" --data-dir "$DATA_DIR" graph blame --run run-phase1-accept --file calculator.py.bug --json > "$DELETED_BLAME_JSON"

"$PYTHON_BIN" - "$VERIFY_JSON" "$REPLAY_JSON" "$TRAJECTORIES_JSON" "$DIFF_JSON" "$BLAME_JSON" "$CREATED_DIFF_JSON" "$CREATED_BLAME_JSON" "$DELETED_BLAME_JSON" "$CORRECT_ATTEMPT" "$RISKY_ATTEMPT" <<'PY'
import json
import sys

verify_path, replay_path, trajectories_path, diff_path, blame_path, created_diff_path, created_blame_path, deleted_blame_path, correct_attempt, risky_attempt = sys.argv[1:]

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
PY

echo "phase1 acceptance: ok"

echo "== cleanup"
"$BIN" --data-dir "$DATA_DIR" session rm "$SESSION_ID" >/dev/null
SESSION_ID=""
