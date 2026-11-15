#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
args=(run --events "${AGENTPROV_ACCEPT_100K_EVENTS:-100000}" --listen "${AGENTPROV_ACCEPT_100K_LISTEN:-127.0.0.1:0}")
if [[ -n "${AGENTPROV_ACCEPT_100K_DATA_DIR:-}" ]]; then
  args+=(--output "$AGENTPROV_ACCEPT_100K_DATA_DIR")
fi
if [[ -n "${AGENTPROV_ACCEPT_100K_BIN:-}" ]]; then
  args+=(--agentprov "$AGENTPROV_ACCEPT_100K_BIN")
fi
if [[ -n "${AGENTPROV_ACCEPT_100K_REPORT:-}" ]]; then
  args+=(--report "$AGENTPROV_ACCEPT_100K_REPORT")
fi
exec python3 "$ROOT_DIR/scripts/accept_telemetry_100k_pressure.py" "${args[@]}" "$@"
