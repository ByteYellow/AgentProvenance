#!/usr/bin/env bash
# Capture a workload's real syscalls with the eBPF sensor while recording it as a
# zero-SDK agent run, then ingest + materialize + show the taint lens.
# Usage: vm-capture.sh <run_id> <command...>
set -uo pipefail
RUN="$1"; shift
BIN="$HOME/bin/agentprov"
SENSOR="$HOME/bin/agentprov-sensor"
DD="$HOME/.agentprov-snake"
WORKDIR="$HOME/agentprov-snake-demo/workspace"
CAP="/tmp/sensor-$RUN.jsonl"
PIDF="/tmp/sensor-$RUN.pid"

"$BIN" --data-dir "$DD" init >/dev/null 2>&1 || true

echo "== start eBPF sensor (root, background)"
sudo -n /bin/bash -c "nohup '$SENSOR' >'$CAP' 2>/tmp/sensor-$RUN.err & echo \$! >'$PIDF'"
sleep 3
echo "   sensor pid=$(cat "$PIDF" 2>/dev/null) cap=$CAP"
head -c 200 /tmp/sensor-$RUN.err 2>/dev/null && echo

echo "== run workload under record (root_pid binding): $*"
timeout 330 "$BIN" --data-dir "$DD" record --run "$RUN" --name snake-demo --workdir "$WORKDIR" -- "$@"
echo "   record rc=$?"
sleep 1

echo "== stop sensor"
sudo -n /bin/bash -c "kill \$(cat '$PIDF') 2>/dev/null; sleep 1; pkill -f agentprov-sensor 2>/dev/null; chmod 644 '$CAP' 2>/dev/null; true"

echo "== captured: $(wc -l <"$CAP" 2>/dev/null) events; exfil-relevant lines:"
grep -aE '169\.254\.169\.254|\.aws/credentials|agentprov-demo-secrets|api_token' "$CAP" 2>/dev/null | head -6

echo "== ingest native sensor stream"
"$BIN" --data-dir "$DD" telemetry ingest-jsonl --file "$CAP" --format native --json 2>&1 | grep -aE '"detected_format"|"read"|"ingested"|"policy_decisions"|"correlation_method"' | head

echo "== materialize + taint lens"
"$BIN" --data-dir "$DD" graph materialize --run "$RUN" 2>&1 | tail -1
"$BIN" --data-dir "$DD" graph lens --run "$RUN" --lens data-flow-taint 2>&1 | grep -aE 'graph_lens|derived_edge' | head
echo "== run id: $RUN  data-dir: $DD"
