#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DATA_DIR="${AGENTPROV_ACCEPT_BATCH_FORENSICS_DATA_DIR:-.agentprov-batch-forensics-accept}"
BIN="${AGENTPROV_ACCEPT_BATCH_FORENSICS_BIN:-$(mktemp "${TMPDIR:-/tmp}/agentprov-batch-forensics-bin.XXXXXX")}"
JOBS_FILE="$(mktemp "${TMPDIR:-/tmp}/agentprov-batch-forensics-jobs.XXXXXX.jsonl")"
WORKDIR_A="$(mktemp -d "${TMPDIR:-/tmp}/agentprov-batch-forensics-a.XXXXXX")"
WORKDIR_B="$(mktemp -d "${TMPDIR:-/tmp}/agentprov-batch-forensics-b.XXXXXX")"
EXPORT_JSON="$(mktemp "${TMPDIR:-/tmp}/agentprov-batch-forensics-export.XXXXXX.json")"
LISTEN="${AGENTPROV_ACCEPT_BATCH_FORENSICS_LISTEN:-127.0.0.1:18575}"
DAEMON_URL="http://$LISTEN"

cleanup() {
  if [[ -n "${daemon_pid:-}" ]]; then
    kill "$daemon_pid" >/dev/null 2>&1 || true
    wait "$daemon_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$DATA_DIR" "$BIN" "$JOBS_FILE" "$WORKDIR_A" "$WORKDIR_B" "$EXPORT_JSON"
}
trap cleanup EXIT

echo "== build agentprov"
GOTOOLCHAIN="${GOTOOLCHAIN:-local}" go build -o "$BIN" ./cmd/agentprov

echo "== init"
"$BIN" --data-dir "$DATA_DIR" init

printf 'a = 1\n' >"$WORKDIR_A/app.py"
printf 'b = 1\n' >"$WORKDIR_B/app.py"
cat >"$JOBS_FILE" <<JSONL
{"job_id":"job-a","shard_id":"shard-0","run_id":"run-batch-forensics-a","workdir":"$WORKDIR_A","command":["sh","-c","printf 'a = 2\\n' > app.py && printf artifact-a > artifact.txt"]}
{"job_id":"job-b","shard_id":"shard-0","run_id":"run-batch-forensics-b","workdir":"$WORKDIR_B","command":["sh","-c","printf 'b = 2\\n' > app.py && printf artifact-b > artifact.txt"]}
JSONL

echo "== record batch"
"$BIN" --data-dir "$DATA_DIR" record batch --file "$JOBS_FILE" --json >/tmp/agentprov-batch-forensics-record.json

echo "== export batch forensics"
"$BIN" --data-dir "$DATA_DIR" forensics export-batch --latest --include-eval-contexts --json >"$EXPORT_JSON"

python3 - "$EXPORT_JSON" <<'PY'
import hashlib
import json
import os
import sys

with open(sys.argv[1]) as f:
    exported = json.load(f)

assert exported["schema_version"] == "agentprovenance.batch_forensics_export/v1"
assert exported["run_count"] == 2
assert exported["item_count"] == 2
assert len(exported["run_bundles"]) == 2
assert exported["sha256"]
path = exported["path"]
with open(path, "rb") as f:
    raw = f.read()
assert hashlib.sha256(raw).hexdigest() == exported["sha256"]
bundle = json.loads(raw)
assert bundle["schema_version"] == "agentprovenance.batch_forensics_bundle/v1"
assert bundle["summary"]["schema_version"] == "agentprovenance.record_batch_summary/v1"
assert bundle["summary"]["passed"] == 2
assert {item["run_id"] for item in bundle["summary"]["items"]} == {"run-batch-forensics-a", "run-batch-forensics-b"}
assert len(bundle["eval_contexts"]) == 2
assert {ctx["run_id"] for ctx in bundle["eval_contexts"]} == {"run-batch-forensics-a", "run-batch-forensics-b"}
assert len(bundle["run_bundles"]) == 2
assert all(os.path.exists(item["path"]) for item in bundle["run_bundles"])
assert {cmd["run_id"] for cmd in bundle["commands"]} == {"run-batch-forensics-a", "run-batch-forensics-b"}
assert all(cmd["evidence_manifest"].startswith("evidence manifest --run ") for cmd in bundle["commands"])
assert bundle["result_set_id"] == exported["result_set_id"]
assert bundle["page_hash"] == exported["page_hash"]
PY

echo "== export batch forensics through daemon client"
"$BIN" --data-dir "$DATA_DIR" daemon serve \
  --listen "$LISTEN" \
  --sample-interval 0 \
  --spool-interval 0 \
  --evidence-interval 0 \
  --gc-interval 0 >/tmp/agentprov-batch-forensics-daemon.log 2>&1 &
daemon_pid=$!
for _ in $(seq 1 80); do
  if curl -fsS "$DAEMON_URL/v1/health" >/tmp/agentprov-batch-forensics-health.json 2>/dev/null; then
    break
  fi
  sleep 0.1
done
"$BIN" --data-dir "$DATA_DIR" --daemon-url "$DAEMON_URL" forensics export-batch --latest --json >/tmp/agentprov-batch-forensics-daemon-export.json
python3 - <<'PY'
import json
with open("/tmp/agentprov-batch-forensics-daemon-export.json") as f:
    exported = json.load(f)
assert exported["schema_version"] == "agentprovenance.batch_forensics_export/v1"
assert exported["run_count"] == 2
assert exported["item_count"] == 2
assert len(exported["run_bundles"]) == 2
PY

echo "Batch forensics acceptance passed"
