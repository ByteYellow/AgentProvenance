#!/usr/bin/env bash
set -euo pipefail
umask 077

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
bin=$(command -v "${AGENTPROV_BIN:-agentprov}")
dsh=$(command -v "${DSH_BIN:-dsh}")
: "${DSH_HOME:?Set DSH_HOME to the configured Harness home; credentials stay outside this demo.}"
out=${1:-$(mktemp -d "${TMPDIR:-/tmp}/agentprov-deepseek.XXXXXX")}
mkdir -p -- "$out"
out=$(cd -- "$out" && pwd)
if [[ -e "$out/workspace" || -e "$out/store" || -e "$out/signing.key" ]]; then
  printf '%s\n' 'Refusing to replace an existing capture. Choose a fresh output directory.' >&2
  exit 1
fi

mkdir -- "$out/workspace"
cp -- "$here"/workspace/*.py "$here/workspace/orders.csv" "$out/workspace/"
"$dsh" --version > "$out/harness-version.txt"
python3 -m unittest discover -s "$out/workspace" -v > "$out/baseline-tests.log" 2>&1
"$bin" forensics keygen --priv "$out/signing.key" --pub "$out/signing.pub" > "$out/keygen.log"
task=$(<"$here/TASK.md")

set +e
"$bin" --data-dir "$out/store" launch --no-dashboard --file-diff --json \
  --workdir "$out/workspace" --context-dir "$DSH_HOME" \
  --context-harness deepseek --sign-key "$out/signing.key" \
  -- "$dsh" headless --json "$task" > "$out/launch.json" 2> "$out/launch.log"
status=$?
set -e
printf 'capture_directory=%s\nlaunch_exit=%s\n' "$out" "$status"
if [[ "$status" != 0 ]]; then
  printf '%s\n' 'Capture did not finish successfully; retain its logs for diagnosis.' >&2
  exit "$status"
fi

python3 -m unittest discover -s "$out/workspace" -v > "$out/final-tests.log" 2>&1
python3 "$out/workspace/report.py" "$out/workspace/orders.csv" > "$out/total.txt"
python3 "$out/workspace/report.py" "$out/workspace/orders.csv" --daily > "$out/daily.txt"
printf '%s\n' 'Capture and task checks finished. Inspect coverage and verify the signed bundle before sharing.'
