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

echo "== record batch through thin Python helper"
BATCH_WORKDIR_A="$(mktemp -d "${TMPDIR:-/tmp}/agentprov-python-helper-batch-a.XXXXXX")"
BATCH_WORKDIR_B="$(mktemp -d "${TMPDIR:-/tmp}/agentprov-python-helper-batch-b.XXXXXX")"
printf 'a = 1\n' >"$BATCH_WORKDIR_A/app.py"
printf 'b = 1\n' >"$BATCH_WORKDIR_B/app.py"
PYTHONPATH=python AGENTPROV_BIN="$BIN" AGENTPROV_DATA_DIR="$DATA_DIR" BATCH_WORKDIR_A="$BATCH_WORKDIR_A" BATCH_WORKDIR_B="$BATCH_WORKDIR_B" python3 - <<'PY'
import os
from agentprov_eval import Client

client = Client(binary=os.environ["AGENTPROV_BIN"], data_dir=os.environ["AGENTPROV_DATA_DIR"])
manifest = client.record_batch(
    [
        {
            "job_id": "job-a",
            "shard_id": "shard-0",
            "run_id": "run-python-helper-batch-a",
            "workdir": os.environ["BATCH_WORKDIR_A"],
            "command": ["sh", "-c", "printf 'a = 2\n' > app.py"],
        },
        {
            "job_id": "job-b",
            "shard_id": "shard-0",
            "run_id": "run-python-helper-batch-b",
            "workdir": os.environ["BATCH_WORKDIR_B"],
            "command": ["sh", "-c", "printf 'b = 2\n' > app.py"],
        },
    ]
)
assert manifest["schema_version"] == "agentprovenance.record_batch/v1"
assert manifest["job_count"] == 2
assert manifest["passed"] == 2
assert manifest["shards"]["shard-0"] == 2
assert "run-python-helper-batch-a" in manifest["run_ids"]
assert manifest["items"][0]["evidence_manifest_command"].startswith("evidence manifest --run ")
summary = client.batch_summary(batch_id=manifest["batch_id"], shard_id="shard-0")
assert summary["schema_version"] == "agentprovenance.record_batch_summary/v1"
assert summary["batch_count"] == 1
assert summary["item_count"] == 2
assert summary["passed"] == 2
assert summary["items"][0]["batch_id"] == manifest["batch_id"]
run_summary = client.batch_summary(run_id="run-python-helper-batch-a")
assert run_summary["item_count"] == 1
assert run_summary["items"][0]["job_id"] == "job-a"
contexts = client.batch_eval_contexts(batch_id=manifest["batch_id"], shard_id="shard-0")
assert len(contexts) == 2
assert {ctx["run_id"] for ctx in contexts} == {"run-python-helper-batch-a", "run-python-helper-batch-b"}
ctx = client.eval_context("run-python-helper-batch-a")
assert ctx["run_id"] == "run-python-helper-batch-a"
contexts = client.batch_eval_contexts(batch_id=manifest["batch_id"], shard_id="shard-0")
assert len(contexts) == 2
assert {item["run_id"] for item in contexts} == {"run-python-helper-batch-a", "run-python-helper-batch-b"}
contexts_from_runs = client.batch_eval_contexts(run_ids=["run-python-helper-batch-a", "run-python-helper-batch-b"])
assert len(contexts_from_runs) == 2
print("python helper batch acceptance ok")
PY

echo "== export batch EvalContext JSONL through CLI"
BATCH_CONTEXT_JSONL="$("$BIN" --data-dir "$DATA_DIR" signal batch-context --shard shard-0 --latest --limit 10)"
python3 - <<'PY' "$BATCH_CONTEXT_JSONL"
import json
import sys

rows = [json.loads(line) for line in sys.argv[1].splitlines() if line.strip()]
assert len(rows) == 2
assert {row["run_id"] for row in rows} == {"run-python-helper-batch-a", "run-python-helper-batch-b"}
assert all(row["schema_version"] == "agentprovenance.eval_context/v1" for row in rows)
PY
rm -rf "$BATCH_WORKDIR_A" "$BATCH_WORKDIR_B"

echo "Python helper acceptance passed"
