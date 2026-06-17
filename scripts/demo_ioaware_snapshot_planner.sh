#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

AGENTPROV="${AGENTPROV:-./agentprov}"
DATA_DIR="${DATA_DIR:-.agentprov-demo-ioaware}"

go build -o "$AGENTPROV" ./cmd/agentprov
rm -rf "$DATA_DIR"
"$AGENTPROV" --data-dir "$DATA_DIR" init >/dev/null

lease_id=$("$AGENTPROV" --data-dir "$DATA_DIR" lease create --task examples/tasks/bugfix.yaml)
session_id=$("$AGENTPROV" --data-dir "$DATA_DIR" session create --lease "$lease_id")
cleanup() {
  "$AGENTPROV" --data-dir "$DATA_DIR" session rm "$session_id" >/dev/null 2>&1 || true
}
trap cleanup EXIT

"$AGENTPROV" --data-dir "$DATA_DIR" exec "$session_id" --stream -- sh -lc '
  mkdir -p .git/objects/aa node_modules/pkg .venv/lib/site-packages/pkg
  echo object > .git/objects/aa/obj
  echo module > node_modules/pkg/index.js
  echo venv > .venv/lib/site-packages/pkg/mod.py
' >/dev/null

"$AGENTPROV" --data-dir "$DATA_DIR" snapshot create "$session_id" --type directory --path /workspace --name ready
"$AGENTPROV" --data-dir "$DATA_DIR" snapshot inspect ready
"$AGENTPROV" --data-dir "$DATA_DIR" snapshot plan ready

echo "expecting_io_budget_reject=true"
if AGENTPROV_IO_MAX_FANOUT_PER_LOWER=1 "$AGENTPROV" --data-dir "$DATA_DIR" fork ready --count 2; then
  echo "unexpected_fork_success=true"
  exit 1
else
  echo "io_budget_reject_observed=true"
fi

"$AGENTPROV" --data-dir "$DATA_DIR" fork ready --count 1
"$AGENTPROV" --data-dir "$DATA_DIR" graph trace --run run-demo-bugfix
