#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DATA_DIR="${AGENTPROV_ACCEPT_QUERY_DATA_DIR:-.agentprov-query-accept}"
BIN="${AGENTPROV_ACCEPT_QUERY_BIN:-$(mktemp "${TMPDIR:-/tmp}/agentprov-query-bin.XXXXXX")}"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/agentprov-query-work.XXXXXX")"
PAGE1="$(mktemp "${TMPDIR:-/tmp}/agentprov-query-page1.XXXXXX.json")"
PAGE2="$(mktemp "${TMPDIR:-/tmp}/agentprov-query-page2.XXXXXX.json")"
MANIFEST_JSON="$(mktemp "${TMPDIR:-/tmp}/agentprov-query-manifest.XXXXXX.json")"
LISTEN="${AGENTPROV_ACCEPT_QUERY_LISTEN:-127.0.0.1:18576}"
DAEMON_URL="http://$LISTEN"

cleanup() {
  if [[ -n "${daemon_pid:-}" ]]; then
    kill "$daemon_pid" >/dev/null 2>&1 || true
    wait "$daemon_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$DATA_DIR" "$BIN" "$WORKDIR" "$PAGE1" "$PAGE2" "$MANIFEST_JSON"
}
trap cleanup EXIT

echo "== build agentprov"
GOTOOLCHAIN="${GOTOOLCHAIN:-local}" go build -o "$BIN" ./cmd/agentprov

echo "== init and record"
rm -rf "$DATA_DIR"
"$BIN" --data-dir "$DATA_DIR" init
printf 'value = 1\n' >"$WORKDIR/app.py"
"$BIN" --data-dir "$DATA_DIR" record \
  --run run-query-pagination \
  --workdir "$WORKDIR" \
  --json -- \
  sh -c "printf 'value = 2\n' > app.py && printf artifact > artifact.txt" >/tmp/agentprov-query-record.json
"$BIN" --data-dir "$DATA_DIR" graph materialize --run run-query-pagination >/tmp/agentprov-query-materialize.txt

echo "== verify timeline cursor pagination"
"$BIN" --data-dir "$DATA_DIR" timeline --run run-query-pagination --limit 2 --json >"$PAGE1"
NEXT_CURSOR="$(python3 - "$PAGE1" <<'PY'
import json
import sys
with open(sys.argv[1]) as f:
    page = json.load(f)
assert page["schema_version"] == "agentprovenance.timeline/v1"
assert page["event_count"] == 2
assert page["total_count"] >= page["event_count"]
assert page["has_more"] is True
assert page["next_cursor"]
assert "|" not in page["next_cursor"]
assert page["result_set_id"]
assert page["page_hash"]
print(page["next_cursor"])
PY
)"
"$BIN" --data-dir "$DATA_DIR" timeline --run run-query-pagination --limit 2 --cursor "$NEXT_CURSOR" --json >"$PAGE2"
python3 - "$PAGE1" "$PAGE2" <<'PY'
import json
import sys
with open(sys.argv[1]) as f:
    page1 = json.load(f)
with open(sys.argv[2]) as f:
    page2 = json.load(f)
assert page2["cursor"] == page1["next_cursor"]
assert page2["result_set_id"] == page1["result_set_id"]
assert page2["page_hash"] != page1["page_hash"]
assert page2["events"][0]["id"] != page1["events"][0]["id"]
PY

echo "== verify evidence manifest query refs"
"$BIN" --data-dir "$DATA_DIR" evidence manifest --run run-query-pagination --json >"$MANIFEST_JSON"
python3 - "$MANIFEST_JSON" <<'PY'
import json
import sys
with open(sys.argv[1]) as f:
    manifest = json.load(f)
assert manifest["schema_version"] == "agentprovenance.evidence_manifest/v1"
refs = {item["kind"]: item for item in manifest["query_refs"]}
for key in ["observability_summary", "timeline", "objects", "security_risks", "security_responses"]:
    assert key in refs, refs
    assert refs[key]["command"]
    assert refs[key]["result_set_id"]
    assert refs[key]["page_hash"]
assert refs["timeline"]["schema_version"] == "agentprovenance.timeline/v1"
assert refs["objects"]["schema_version"] == "agentprovenance.objects/v1"
PY

echo "== verify daemon timeline cursor path"
"$BIN" --data-dir "$DATA_DIR" daemon serve \
  --listen "$LISTEN" \
  --sample-interval 0 \
  --spool-interval 0 \
  --evidence-interval 0 \
  --gc-interval 0 >/tmp/agentprov-query-daemon.log 2>&1 &
daemon_pid=$!
for _ in $(seq 1 80); do
  if curl -fsS "$DAEMON_URL/v1/health" >/tmp/agentprov-query-health.json 2>/dev/null; then
    break
  fi
  sleep 0.1
done
"$BIN" --data-dir "$DATA_DIR" --daemon-url "$DAEMON_URL" timeline \
  --run run-query-pagination --limit 2 --cursor "$NEXT_CURSOR" --json >/tmp/agentprov-query-daemon-page.json
python3 - <<'PY'
import json
with open("/tmp/agentprov-query-daemon-page.json") as f:
    page = json.load(f)
assert page["schema_version"] == "agentprovenance.timeline/v1"
assert page["cursor"]
assert page["event_count"] > 0
PY

echo "Evidence query pagination acceptance passed"
