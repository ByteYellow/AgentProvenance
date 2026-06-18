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
  --strategy "correct-add::sed 's/return a - b/return a + b/' calculator.py > calculator.py.new && mv calculator.py.new calculator.py; diff -u calculator.py.bug calculator.py > fix.patch || true; ./test_calculator.sh::score=contains:passed::artifact=fix.patch")"
echo "$ROLLOUT_OUTPUT"

ROLLOUT_ID="$(echo "$ROLLOUT_OUTPUT" | sed -n 's/^rollout_id=\([^ ]*\).*/\1/p')"
CORRECT_ATTEMPT="$(echo "$ROLLOUT_OUTPUT" | awk '$5 == "correct-add" {print $1; exit}')"
CORRECT_TOOL_CALL="$(echo "$ROLLOUT_OUTPUT" | awk '$5 == "correct-add" {print $2; exit}')"
CORRECT_PROCESS="$(echo "$ROLLOUT_OUTPUT" | awk '$5 == "correct-add" {print $4; exit}')"
RISKY_ATTEMPT="$(echo "$ROLLOUT_OUTPUT" | awk '$5 == "wrong-constant" {print $1; exit}')"

if [[ -z "$ROLLOUT_ID" || -z "$CORRECT_ATTEMPT" || -z "$CORRECT_TOOL_CALL" || -z "$CORRECT_PROCESS" || -z "$RISKY_ATTEMPT" ]]; then
  echo "failed to parse rollout ids" >&2
  exit 1
fi

echo "== telemetry correlation"
"$BIN" --data-dir "$DATA_DIR" telemetry ingest \
  --raw-event raw-execve-correct-add \
  --process "$CORRECT_PROCESS" \
  --source wrapper_runtime \
  --type execve \
  --payload '{"argv":["./test_calculator.sh"]}' >/dev/null
TELEMETRY_OUTPUT="$("$BIN" --data-dir "$DATA_DIR" telemetry list --run run-phase1-accept --type execve)"
assert_contains "$TELEMETRY_OUTPUT" "process_id:process_id"
assert_contains "$TELEMETRY_OUTPUT" "$CORRECT_TOOL_CALL"

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

REPLAY_JSON="$DATA_DIR/replay.json"
DIFF_JSON="$DATA_DIR/diff.json"
BLAME_JSON="$DATA_DIR/blame.json"
"$BIN" --data-dir "$DATA_DIR" graph replay --run run-phase1-accept --json > "$REPLAY_JSON"
"$BIN" --data-dir "$DATA_DIR" graph diff --run run-phase1-accept --file calculator.py --json > "$DIFF_JSON"
"$BIN" --data-dir "$DATA_DIR" graph blame --run run-phase1-accept --file calculator.py --json > "$BLAME_JSON"

"$PYTHON_BIN" - "$REPLAY_JSON" "$DIFF_JSON" "$BLAME_JSON" "$CORRECT_ATTEMPT" "$RISKY_ATTEMPT" <<'PY'
import json
import sys

replay_path, diff_path, blame_path, correct_attempt, risky_attempt = sys.argv[1:]

with open(replay_path, "r", encoding="utf-8") as f:
    replay = json.load(f)
with open(diff_path, "r", encoding="utf-8") as f:
    diff = json.load(f)
with open(blame_path, "r", encoding="utf-8") as f:
    blame = json.load(f)

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
assert winner["external_effects"][0]["mode"] == "dry-run", winner.get("external_effects")
risky = by_id[risky_attempt]
assert risky["replay_blocked"] is True, risky
assert "risk_tainted" in risky["block_reasons"], risky

assert diff["schema_version"] == "agentprovenance.diff/v1", diff
assert diff["file"] == "calculator.py", diff
diff_by_id = {a["attempt_id"]: a for a in diff["attempts"]}
assert diff_by_id[correct_attempt]["changed"] is True, diff_by_id[correct_attempt]
assert any("+    return a + b" in line for line in diff_by_id[correct_attempt]["unified_diff"]), diff_by_id[correct_attempt]

assert blame["schema_version"] == "agentprovenance.blame/v1", blame
blame_by_id = {e["attempt_id"]: e for e in blame["entries"]}
assert blame_by_id[correct_attempt]["reason"] == "modified_by_attempt", blame_by_id[correct_attempt]
assert blame_by_id[correct_attempt]["is_winner"] is True, blame_by_id[correct_attempt]
PY

echo "phase1 acceptance: ok"

echo "== cleanup"
"$BIN" --data-dir "$DATA_DIR" session rm "$SESSION_ID" >/dev/null
SESSION_ID=""
