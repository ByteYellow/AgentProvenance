#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DATA_DIR="${AGENTPROV_ACCEPT_DEPLOY1_DATA_DIR:-.agentprov-deploy1-accept}"
BIN="${AGENTPROV_ACCEPT_DEPLOY1_BIN:-$(mktemp "${TMPDIR:-/tmp}/agentprov-deploy1-bin.XXXXXX")}"
PY_TARGET="$(mktemp -d "${TMPDIR:-/tmp}/agentprov-deploy1-pkg.XXXXXX")"
WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/agentprov-deploy1-work.XXXXXX")"

cleanup() {
  rm -rf "$DATA_DIR" "$BIN" "$PY_TARGET" "$WORK_ROOT"
}
trap cleanup EXIT

echo "== build agentprov"
GOTOOLCHAIN="${GOTOOLCHAIN:-local}" go build -o "$BIN" ./cmd/agentprov

echo "== install Python helper package"
python3 -m pip install --quiet --no-deps --target "$PY_TARGET" .

echo "== run Deploy 1 batch pipeline"
PYTHONPATH="$PY_TARGET" AGENTPROV_BIN="$BIN" AGENTPROV_DATA_DIR="$DATA_DIR" WORK_ROOT="$WORK_ROOT" python3 - <<'PY'
import json
import os
from pathlib import Path

from agentprov import Registry, Signal, run_batch_pipeline

root = Path(os.environ["WORK_ROOT"])
jobs = []
for idx in range(4):
    workdir = root / f"job-{idx}"
    workdir.mkdir(parents=True)
    (workdir / "app.py").write_text(f"value = {idx}\n", encoding="utf-8")
    jobs.append(
        {
            "job_id": f"job-{idx}",
            "shard_id": "shard-a" if idx % 2 == 0 else "shard-b",
            "run_id": f"run-deploy1-{idx}",
            "workdir": str(workdir),
            "command": ["sh", "-c", f"printf 'value = {idx + 10}\\n' > app.py && printf artifact-{idx} > artifact.txt"],
        }
    )

registry = Registry(name="deploy1-offline-evaluator")

@registry.rule("changed_file_reward")
def changed_file_reward(ctx):
    return Signal.reward_feature(
        "changed_file_reward",
        float(len(ctx.file_changes())),
        "offline reward feature from file changes",
        evidence={"file_change_count": len(ctx.file_changes())},
    )

@registry.rule("candidate_label")
def candidate_label(ctx):
    return Signal.dataset_label(
        "candidate_label",
        "candidate",
        1.0,
        "offline dataset label from Deploy 1 evaluator",
    )

result = run_batch_pipeline(
    jobs,
    registry,
    binary=os.environ["AGENTPROV_BIN"],
    data_dir=os.environ["AGENTPROV_DATA_DIR"],
    engine="deploy1-offline-evaluator",
    import_signals=True,
    include_forensics=True,
    include_eval_contexts_in_forensics=True,
)
out = result.to_dict()
assert out["schema_version"] == "agentprovenance.python_batch_pipeline/v1"
assert out["record_manifest"]["schema_version"] == "agentprovenance.record_batch/v1"
assert out["record_manifest"]["job_count"] == 4
assert out["context_count"] == 4
assert out["report_count"] == 4
assert out["signal_count"] == 8
assert out["import_report"]["schema_version"] == "agentprovenance.eval_signal_batch_import/v1"
assert out["import_report"]["run_count"] == 4
assert out["import_report"]["signal_count"] == 8
assert out["import_report"]["failed"] == 0
assert out["import_report"]["result_set_id"].startswith("sha256:")
assert out["forensics"]["schema_version"] == "agentprovenance.batch_forensics_export/v1"
assert out["forensics"]["run_count"] == 4
assert out["summary"]["schema_version"] == "agentprovenance.record_batch_summary/v1"
assert out["summary"]["item_count"] == 4
print(json.dumps({"batch_id": out["batch_id"], "signals": out["signal_count"], "runs": len(out["run_ids"])}, sort_keys=True))
PY

echo "Deploy 1 batch pipeline acceptance passed"
