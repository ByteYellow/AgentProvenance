#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="${AGENTPROV_ACCEPT_PYTHON_HELPER_DATA_DIR:-.agentprov-python-helper-accept}"
BIN="${AGENTPROV_ACCEPT_PYTHON_HELPER_BIN:-$(mktemp "${TMPDIR:-/tmp}/agentprov-python-helper-bin.XXXXXX")}"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/agentprov-python-helper-work.XXXXXX")"

cleanup() {
  rm -rf "$WORKDIR"
  if [[ "${AGENTPROV_ACCEPT_KEEP_BIN:-0}" != "1" ]]; then
    rm -f "$BIN"
  fi
}
trap cleanup EXIT

echo "== build agentprov"
go build -o "$BIN" ./cmd/agentprov

echo "== init python helper fixture"
rm -rf "$DATA_DIR"
printf 'value = 1\n' >"$WORKDIR/app.py"

echo "== record through thin Python helper"
PYTHONPATH=python AGENTPROV_BIN="$BIN" AGENTPROV_DATA_DIR="$DATA_DIR" AGENTPROV_WORKDIR="$WORKDIR" python3 - <<'PY'
import os
from agentprov_eval import Client, Signal

client = Client(binary=os.environ["AGENTPROV_BIN"], data_dir=os.environ["AGENTPROV_DATA_DIR"])
manifest = client.record(
    ["sh", "-c", "printf 'value = 2\n' > app.py && printf artifact > artifact.txt"],
    run_id="run-python-helper-accept",
    workdir=os.environ["AGENTPROV_WORKDIR"],
)
assert manifest["schema_version"] == "agentprovenance.record/v1"
assert manifest["run_id"] == "run-python-helper-accept"
assert "app.py" in manifest["changed_files"]

evidence = client.evidence_manifest("run-python-helper-accept")
assert evidence["schema_version"] == "agentprovenance.evidence_manifest/v1"
assert evidence["run_id"] == "run-python-helper-accept"

ctx = client.eval_context("run-python-helper-accept")
assert ctx["schema_version"] == "agentprovenance.eval_context/v1"
assert ctx["run_id"] == "run-python-helper-accept"

report = client.import_signals(
    "run-python-helper-accept",
    [
        Signal.reward_feature(
            "python_helper_smoke",
            0.5,
            "thin Python helper can import evaluator signals",
            run_id="run-python-helper-accept",
        )
    ],
)
assert report["schema_version"] == "agentprovenance.eval_signals/v1"
assert report["signal_count"] == 1
print("python helper acceptance ok")
PY

echo "Python helper acceptance passed"
