#!/usr/bin/env bash
set -euo pipefail

# Corrupted-evidence-chain scenario: prove `graph verify` detects tampering of
# the materialized evidence, both (A) a content-addressed object file edited on
# disk and (B) an in-DB row edited directly (the manifest rebuilt from SQLite no
# longer matches the materialized record_manifest object). This is the integrity
# claim v1 makes (docs/v1-definition-of-done.md Sec 0): graph verify catches
# corruption/divergence; it is NOT tamper-evidence against an attacker who also
# re-derives the chain (that needs off-host anchoring, deferred to v2).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BIN="${AGENTPROV_ACCEPT_TAMPER_BIN:-$(mktemp "${TMPDIR:-/tmp}/agentprov-tamper-bin.XXXXXX")}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/agentprov-tamper.XXXXXX")"

cleanup() { rm -rf "$BIN" "$WORK"; }
trap cleanup EXIT

assert_contains() {
  if [[ "$1" != *"$2"* ]]; then
    echo "expected output to contain: $2" >&2
    echo "$1" >&2
    exit 1
  fi
}

echo "== build agentprov"
GOTOOLCHAIN="${GOTOOLCHAIN:-local}" go build -o "$BIN" ./cmd/agentprov

run_and_materialize() {
  local data_dir="$1" run="$2" wd="$3"
  mkdir -p "$wd"
  echo seed > "$wd/seed.txt"
  "$BIN" --data-dir "$data_dir" init >/dev/null
  "$BIN" --data-dir "$data_dir" record --run "$run" --name t --workdir "$wd" \
    -- sh -c 'echo more >> seed.txt; echo out > out.txt' >/dev/null
  "$BIN" --data-dir "$data_dir" graph materialize --run "$run" >/dev/null
}

# --- Baseline: a clean run verifies ok ---
DATA_A="$WORK/a"
run_and_materialize "$DATA_A" run-tamper-a "$WORK/wd-a"
CLEAN_JSON="$("$BIN" --data-dir "$DATA_A" graph verify --run run-tamper-a --json)"
assert_contains "$CLEAN_JSON" '"status": "ok"'
echo "baseline verify ok"

# --- Tamper A: edit a content-addressed object file on disk ---
OBJ_PATH="$(sqlite3 "$DATA_A/agentprov.db" "SELECT path FROM provenance_objects WHERE run_id='run-tamper-a' AND object_type != 'record_manifest' LIMIT 1")"
if [[ -z "$OBJ_PATH" || ! -f "$OBJ_PATH" ]]; then
  echo "could not find a provenance object file to tamper: '$OBJ_PATH'" >&2
  exit 1
fi
printf 'TAMPER' >> "$OBJ_PATH"
OBJ_JSON="$("$BIN" --data-dir "$DATA_A" graph verify --run run-tamper-a --json || true)"
assert_contains "$OBJ_JSON" '"status": "failed"'
assert_contains "$OBJ_JSON" 'object_hash_mismatch'
echo "object-file tamper detected (object_hash_mismatch)"

# --- Tamper B: edit an in-DB row that feeds the record manifest ---
DATA_B="$WORK/b"
run_and_materialize "$DATA_B" run-tamper-b "$WORK/wd-b"
sqlite3 "$DATA_B/agentprov.db" "UPDATE fork_attempts SET command = command || ' --INJECTED' WHERE strategy = 'zero-sdk-record'"
DB_JSON="$("$BIN" --data-dir "$DATA_B" graph verify --run run-tamper-b --json || true)"
assert_contains "$DB_JSON" '"status": "failed"'
assert_contains "$DB_JSON" 'record_manifest_mismatch'
echo "in-DB row tamper detected (record_manifest_mismatch)"

echo "Evidence tamper-detection acceptance passed"
