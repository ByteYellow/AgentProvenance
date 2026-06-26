#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="${AGENTPROV_ACCEPT_PYTHON_HELPER_DATA_DIR:-.agentprov-python-helper-accept}"
BIN="${AGENTPROV_ACCEPT_PYTHON_HELPER_BIN:-$(mktemp "${TMPDIR:-/tmp}/agentprov-python-helper-bin.XXXXXX")}"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/agentprov-python-helper-work.XXXXXX")"
PY_TARGET="$(mktemp -d "${TMPDIR:-/tmp}/agentprov-python-helper-pkg.XXXXXX")"

cleanup() {
  rm -rf "$WORKDIR" "$PY_TARGET"
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

echo "== install local Python helper package"
python3 -m pip install --quiet --no-deps --target "$PY_TARGET" .
PYTHONPATH="$PY_TARGET" python3 - <<'PY'
from agentprov import Registry, Signal, rule
from agentprov_eval import Client
assert Registry
assert Signal
assert rule
assert Client
PY

echo "== record through thin Python helper"
PYTHONPATH="$PY_TARGET" AGENTPROV_BIN="$BIN" AGENTPROV_DATA_DIR="$DATA_DIR" AGENTPROV_WORKDIR="$WORKDIR" python3 - <<'PY'
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
PYTHONPATH="$PY_TARGET" AGENTPROV_BIN="$BIN" AGENTPROV_DATA_DIR="$DATA_DIR" BATCH_WORKDIR_A="$BATCH_WORKDIR_A" BATCH_WORKDIR_B="$BATCH_WORKDIR_B" python3 - <<'PY'
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
client.run_cli(["graph", "materialize", "--run", "run-python-helper-batch-a"])
objects = client.run_cli(["graph", "objects", "--run", "run-python-helper-batch-a", "--json"]).json()
object_types = {item["type"] for item in objects["objects"]}
assert "record_batch" in object_types
assert "record_batch_summary" in object_types
batch_objects = [item for item in objects["objects"] if item["type"] == "record_batch"]
assert batch_objects and batch_objects[0]["source_id"] == manifest["batch_id"]
batch_forensics = client.batch_forensics(batch_id=manifest["batch_id"], include_eval_contexts=True)
assert batch_forensics["schema_version"] == "agentprovenance.batch_forensics_export/v1"
assert batch_forensics["run_count"] == 2
assert batch_forensics["item_count"] == 2
assert len(batch_forensics["run_bundles"]) == 2
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

echo "== evaluate batch through Python rule registry"
PYTHONPATH="$PY_TARGET" AGENTPROV_BIN="$BIN" AGENTPROV_DATA_DIR="$DATA_DIR" python3 - <<'PY'
import os
from agentprov import Client, Registry, Signal, evaluate_batch, reports_jsonl, rule

client = Client(binary=os.environ["AGENTPROV_BIN"], data_dir=os.environ["AGENTPROV_DATA_DIR"])
contexts = client.batch_eval_contexts(shard_id="shard-0", latest=True)

registry = Registry(name="acceptance-registry")

@registry.rule("changed_file_reward", tags=["rl", "offline"])
def changed_file_reward(ctx):
    return Signal.reward_feature(
        "changed_file_reward",
        float(len(ctx.file_changes())),
        "reward feature from file state changes",
        evidence={"file_change_count": len(ctx.file_changes())},
    )

@registry.rule("no_metadata_penalty")
def no_metadata_penalty(ctx):
    if ctx.has_event_type("metadata_ip"):
        return Signal.penalty("metadata_ip", -1.0, "metadata IP access observed")
    return None

reports = evaluate_batch(contexts, registry=registry)
assert len(reports) == 2
assert all(report["schema_version"] == "agentprovenance.eval_signals/v1" for report in reports)
assert all(report["signal_count"] == 1 for report in reports)
assert all(report["signals"][0]["kind"] == "reward_feature" for report in reports)
assert all(report["result_set_id"].startswith("sha256:") for report in reports)
assert reports_jsonl(reports).count("\n") == 2

imported = client.import_signal_reports(reports, engine="acceptance-registry")
assert imported["schema_version"] == "agentprovenance.eval_signal_batch_import/v1"
assert imported["run_count"] == 2
assert imported["signal_count"] == 2
assert imported["failed"] == 0

@rule("default_registry_quality")
def default_registry_quality(ctx):
    return Signal.quality_signal("default_registry_quality", 1.0, "default registry works")

default_reports = evaluate_batch(contexts[:1])
assert default_reports[0]["signal_count"] == 1
assert default_reports[0]["signals"][0]["name"] == "default_registry_quality"
print("python evaluator registry acceptance ok")
PY

echo "== import batch signal reports through CLI"
PYTHONPATH="$PY_TARGET" AGENTPROV_BIN="$BIN" AGENTPROV_DATA_DIR="$DATA_DIR" python3 - <<'PY' > /tmp/agentprov-python-helper-reports.jsonl
import os
from agentprov import Client, Registry, Signal, evaluate_batch, emit_jsonl

client = Client(binary=os.environ["AGENTPROV_BIN"], data_dir=os.environ["AGENTPROV_DATA_DIR"])
contexts = client.batch_eval_contexts(shard_id="shard-0", latest=True)
registry = Registry(name="cli-import-registry")

@registry.rule("cli_quality")
def cli_quality(ctx):
    return Signal.quality_signal("cli_quality", 1.0, "cli batch import quality signal")

emit_jsonl(evaluate_batch(contexts, registry=registry))
PY
BATCH_IMPORT_JSON="$("$BIN" --data-dir "$DATA_DIR" signal import-batch --file /tmp/agentprov-python-helper-reports.jsonl --engine cli-import-registry --json)"
python3 - <<'PY' "$BATCH_IMPORT_JSON"
import json
import sys
report = json.loads(sys.argv[1])
assert report["schema_version"] == "agentprovenance.eval_signal_batch_import/v1"
assert report["engine"] == "cli-import-registry"
assert report["run_count"] == 2
assert report["signal_count"] == 2
assert report["failed"] == 0
assert report["result_set_id"].startswith("sha256:")
assert report["page_hash"].startswith("sha256:")
PY
rm -rf "$BATCH_WORKDIR_A" "$BATCH_WORKDIR_B"

echo "Python helper acceptance passed"
