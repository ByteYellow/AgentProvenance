#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DATA_DIR="${ACF_DEMO_DATA_DIR:-.acf-demo-coding-bestof}"
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
"$BIN" --data-dir "$DATA_DIR" rollout start \
  --run run-demo-bugfix \
  --task examples/tasks/bugfix.yaml \
  --snapshot ready \
  --runtime local \
  --fanout 5 \
  --strategy "noop::echo no fix > fix.patch; ./test_calculator.sh::score=contains:passed::artifact=fix.patch" \
  --strategy "wrong-constant::sed 's/return a - b/return 42/' calculator.py > calculator.py.new && mv calculator.py.new calculator.py; diff -u calculator.py.bug calculator.py > fix.patch || true; ./test_calculator.sh::score=contains:passed::artifact=fix.patch" \
  --strategy "syntax-error::printf 'def add(a, b):\n    return a +\n' > calculator.py; diff -u calculator.py.bug calculator.py > fix.patch || true; ./test_calculator.sh::score=contains:passed::artifact=fix.patch" \
  --strategy "partial-comment::printf '\n# TODO fix add later\n' >> calculator.py; diff -u calculator.py.bug calculator.py > fix.patch || true; ./test_calculator.sh::score=contains:passed::artifact=fix.patch" \
  --strategy "correct-add::sed 's/return a - b/return a + b/' calculator.py > calculator.py.new && mv calculator.py.new calculator.py; diff -u calculator.py.bug calculator.py > fix.patch || true; ./test_calculator.sh::score=contains:passed::artifact=fix.patch"

echo "== explain promotion"
"$BIN" --data-dir "$DATA_DIR" rollout winner run-demo-bugfix

echo "== trace rollout provenance"
"$BIN" --data-dir "$DATA_DIR" graph trace --run run-demo-bugfix

echo "== refs/log/materialize"
"$BIN" --data-dir "$DATA_DIR" graph refs --run run-demo-bugfix
"$BIN" --data-dir "$DATA_DIR" graph log --run run-demo-bugfix
"$BIN" --data-dir "$DATA_DIR" graph materialize --run run-demo-bugfix

echo "== diff attempts for calculator.py"
"$BIN" --data-dir "$DATA_DIR" graph diff --run run-demo-bugfix --file calculator.py

echo "== blame calculator.py"
"$BIN" --data-dir "$DATA_DIR" graph blame --run run-demo-bugfix --file calculator.py

echo "== trace winning patch artifacts"
"$BIN" --data-dir "$DATA_DIR" graph trace --run run-demo-bugfix | sed -n '1,220p'

echo "== cleanup"
"$BIN" --data-dir "$DATA_DIR" session rm "$SESSION_ID"
SESSION_ID=""
