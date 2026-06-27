#!/usr/bin/env bash
set -euo pipefail

# Regenerate the committed eBPF sensor bindings (sensorbpf_bpf*.go/.o) from
# exec.c. The bindings ARE committed so `go build ./cmd/agentprov-sensor` works
# on a fresh Linux checkout without clang; run this after editing exec.c, then
# commit the result. Requires Linux + clang + bpftool + a BTF-enabled kernel.
#
#   scripts/regen-sensor.sh          regenerate + leave changes in the tree
#   scripts/regen-sensor.sh --check  regenerate and fail if the committed .go
#                                     bindings drifted (CI drift guard)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
SENSOR_DIR="internal/sensor"

CHECK=0
[[ "${1:-}" == "--check" ]] && CHECK=1

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "regen-sensor: must run on Linux (eBPF/clang); this is $(uname -s)" >&2
  exit 2
fi
for tool in clang bpftool go; do
  command -v "$tool" >/dev/null 2>&1 || { echo "regen-sensor: missing required tool: $tool" >&2; exit 2; }
done

echo "== generate vmlinux.h from kernel BTF"
bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$SENSOR_DIR/vmlinux.h"

echo "== go generate (bpf2go: clang-compile exec.c -> bindings + object)"
GOTOOLCHAIN="${GOTOOLCHAIN:-local}" go generate ./internal/sensor

echo "== build the sensor from the (re)generated bindings"
GOTOOLCHAIN="${GOTOOLCHAIN:-local}" go build -o /dev/null ./cmd/agentprov-sensor

if [[ "$CHECK" == "1" ]]; then
  # The .o is clang-version dependent, so only the deterministic .go bindings
  # are drift-checked (they change when exec.c structs / bpf2go flags change).
  if ! git diff --quiet -- "$SENSOR_DIR"/sensorbpf_bpfel.go "$SENSOR_DIR"/sensorbpf_bpfeb.go; then
    echo "regen-sensor: committed sensor .go bindings are stale; run scripts/regen-sensor.sh and commit" >&2
    git --no-pager diff -- "$SENSOR_DIR"/sensorbpf_bpfel.go "$SENSOR_DIR"/sensorbpf_bpfeb.go >&2
    exit 1
  fi
  echo "regen-sensor: committed .go bindings are up to date"
fi

echo "regen-sensor: done"
