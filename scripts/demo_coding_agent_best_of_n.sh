#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DATA_DIR="${AGENTPROV_DEMO_DATA_DIR:-.agentprov-demo-coding-bestof}"
BIN="./agentprov"
SESSION_ID=""

cleanup() {
  if [[ -n "$SESSION_ID" ]]; then
    "$BIN" --data-dir "$DATA_DIR" session rm "$SESSION_ID" >/dev/null 2>&1 || true
  fi
  rm -rf "$DATA_DIR" "$BIN"
}
trap cleanup EXIT

echo "== build agentprov"
GOTOOLCHAIN="${GOTOOLCHAIN:-local}" go build ./cmd/agentprov

echo "== init"
"$BIN" --data-dir "$DATA_DIR" init

echo "== create clean coding workspace"
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
chmod +x test_calculator.sh'

echo "== snapshot clean state"
"$BIN" --data-dir "$DATA_DIR" snapshot create "$SESSION_ID" --type directory --path /workspace --name ready

echo "== fan out 5 coding-agent attempts"
ROLLOUT_OUTPUT="$("$BIN" --data-dir "$DATA_DIR" rollout start \
  --run run-demo-bugfix \
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

CORRECT_PROCESS="$(echo "$ROLLOUT_OUTPUT" | awk '$5 == "correct-add" {print $4; exit}')"
if [[ -z "$CORRECT_PROCESS" ]]; then
  echo "failed to find correct-add process" >&2
  exit 1
fi
CORRECT_ATTEMPT="$(echo "$ROLLOUT_OUTPUT" | awk '$5 == "correct-add" {print $1; exit}')"
CORRECT_TOOL_CALL="$(echo "$ROLLOUT_OUTPUT" | awk '$5 == "correct-add" {print $2; exit}')"
if [[ -z "$CORRECT_ATTEMPT" || -z "$CORRECT_TOOL_CALL" ]]; then
  echo "failed to find correct-add attempt/tool call" >&2
  exit 1
fi
CORRECT_PROCESS_STARTED="$("$BIN" --data-dir "$DATA_DIR" process inspect "$CORRECT_PROCESS" | sed -n 's/^started_at=//p')"

echo "== ingest raw runtime telemetry without tool_call_id"
"$BIN" --data-dir "$DATA_DIR" telemetry ingest \
  --raw-event raw-execve-correct-add \
  --process "$CORRECT_PROCESS" \
  --source wrapper_runtime \
  --type execve \
  --payload '{"argv":["./test_calculator.sh"]}'
"$BIN" --data-dir "$DATA_DIR" telemetry ingest \
  --raw-event raw-execve-cgroup-correct-add \
  --cgroup-id "agentprov-cgroup-$CORRECT_ATTEMPT" \
  --timestamp "$CORRECT_PROCESS_STARTED" \
  --source tetragon_jsonl \
  --type execve \
  --payload '{"argv":["./delayed_child.sh"],"note":"no tool_call_id in raw event"}'
"$BIN" --data-dir "$DATA_DIR" telemetry ingest \
  --raw-event raw-network-container-correct-add \
  --container-id "agentprov-local-$CORRECT_ATTEMPT" \
  --timestamp "$CORRECT_PROCESS_STARTED" \
  --source falco_jsonl \
  --type network_connect \
  --payload '{"dst":"api.example.com:443","note":"container scoped event"}'
"$BIN" --data-dir "$DATA_DIR" telemetry list --run run-demo-bugfix --type execve
"$BIN" --data-dir "$DATA_DIR" telemetry list --run run-demo-bugfix --type network_connect

echo "== record external side-effect gate"
"$BIN" --data-dir "$DATA_DIR" effect record \
  --run run-demo-bugfix \
  --attempt "$CORRECT_ATTEMPT" \
  --tool-call "$CORRECT_TOOL_CALL" \
  --process "$CORRECT_PROCESS" \
  --type api_call \
  --target api.example.com/v1/tickets \
  --mode dry-run \
  --decision audit \
  --compensation ticket-compensate \
  --payload '{"redacted":true,"note":"external side effect recorded, not rolled back"}'
"$BIN" --data-dir "$DATA_DIR" effect list --run run-demo-bugfix

RISKY_ATTEMPT="$(echo "$ROLLOUT_OUTPUT" | awk '$5 == "wrong-constant" {print $1; exit}')"
if [[ -z "$RISKY_ATTEMPT" ]]; then
  echo "failed to find wrong-constant attempt" >&2
  exit 1
fi

echo "== quarantine risky branch"
"$BIN" --data-dir "$DATA_DIR" rollout taint "$RISKY_ATTEMPT" --reason "risky branch: incorrect arithmetic patch failed tests"
"$BIN" --data-dir "$DATA_DIR" rollout attempts "$(echo "$ROLLOUT_OUTPUT" | sed -n 's/^rollout_id=\([^ ]*\).*/\1/p')"

echo "== explain promotion"
"$BIN" --data-dir "$DATA_DIR" rollout winner run-demo-bugfix

echo "== trace rollout provenance"
"$BIN" --data-dir "$DATA_DIR" graph trace --run run-demo-bugfix

echo "== refs/log/materialize"
"$BIN" --data-dir "$DATA_DIR" graph refs --run run-demo-bugfix
"$BIN" --data-dir "$DATA_DIR" graph log --run run-demo-bugfix
"$BIN" --data-dir "$DATA_DIR" graph materialize --run run-demo-bugfix
"$BIN" --data-dir "$DATA_DIR" graph verify --run run-demo-bugfix
"$BIN" --data-dir "$DATA_DIR" graph replay --run run-demo-bugfix
"$BIN" --data-dir "$DATA_DIR" graph trajectories --run run-demo-bugfix

echo "== diff attempts for calculator.py"
"$BIN" --data-dir "$DATA_DIR" graph diff --run run-demo-bugfix --file calculator.py

echo "== blame calculator.py"
"$BIN" --data-dir "$DATA_DIR" graph blame --run run-demo-bugfix --file calculator.py

echo "== blame created and deleted files"
"$BIN" --data-dir "$DATA_DIR" graph blame --run run-demo-bugfix --file fix-notes.txt
"$BIN" --data-dir "$DATA_DIR" graph blame --run run-demo-bugfix --file calculator.py.bug

echo "== trace winning patch artifacts"
"$BIN" --data-dir "$DATA_DIR" graph trace --run run-demo-bugfix | sed -n '1,220p'

echo "== cleanup"
"$BIN" --data-dir "$DATA_DIR" session rm "$SESSION_ID"
SESSION_ID=""
