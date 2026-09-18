#!/usr/bin/env bash
set -euo pipefail

# Regenerate only the native architecture's committed eBPF bindings/object.
# amd64 and arm64 have different uprobe register layouts; never reuse a generic
# endian-only object on another architecture. Requires clang, LLVM, libbpf-dev,
# bpftool and a BTF-enabled matching Linux kernel.
# --check compares generated Go bindings to the files before regeneration.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
SENSOR_DIR=internal/sensor
CHECK=0
case "${1:-}" in
  '') ;;
  --check) CHECK=1 ;;
  *) echo "usage: $0 [--check]" >&2; exit 2 ;;
esac
[[ "$(uname -s)" == Linux ]] || { echo 'regen-sensor: requires Linux' >&2; exit 2; }
case "$(uname -m)" in
  x86_64) ARCH=amd64; SUFFIX=x86_bpfel ;;
  aarch64) ARCH=arm64; SUFFIX=arm64_bpfel ;;
  *) echo 'regen-sensor: supported architectures are amd64 and arm64' >&2; exit 2 ;;
esac
for tool in clang llvm-strip go; do
  command -v "$tool" >/dev/null || { echo "regen-sensor: missing $tool" >&2; exit 2; }
done
BPFTOOL="${BPFTOOL:-$(command -v bpftool || true)}"
if [[ -z "$BPFTOOL" ]] || ! "$BPFTOOL" version >/dev/null 2>&1; then
  # Ubuntu's /usr/sbin/bpftool wrapper may require tools for the exact cloud
  # kernel. The standalone binary from linux-tools-generic can still dump BTF.
  for candidate in /usr/lib/linux-tools/*/bpftool; do
    if [[ -x "$candidate" ]] && "$candidate" version >/dev/null 2>&1; then
      BPFTOOL="$candidate"
      break
    fi
  done
fi
if [[ -z "$BPFTOOL" ]] || ! "$BPFTOOL" version >/dev/null 2>&1; then
  echo 'regen-sensor: install bpftool or set BPFTOOL to a working executable' >&2
  exit 2
fi
BTF="${VMLINUX_BTF:-/sys/kernel/btf/vmlinux}"
[[ -r "$BTF" ]] || { echo "regen-sensor: cannot read kernel BTF: $BTF" >&2; exit 2; }
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
BINDING="$SENSOR_DIR/sensorbpf_$SUFFIX.go"
if [[ "$CHECK" == 1 ]]; then
  [[ -s "$BINDING" ]] || { echo "regen-sensor: missing $BINDING" >&2; exit 1; }
  cp "$BINDING" "$TMP/before.go"
fi
# Buffer the large BTF header on the Linux filesystem before copying to a
# checkout that may reside on a Windows mount.
"$BPFTOOL" btf dump file "$BTF" format c > "$TMP/vmlinux.h"
cp "$TMP/vmlinux.h" "$SENSOR_DIR/vmlinux.h"
echo "== generate Linux $ARCH sensor bindings"
GOOS=linux GOARCH="$ARCH" GOTOOLCHAIN="${GOTOOLCHAIN:-local}" go generate ./internal/sensor
GOOS=linux GOARCH="$ARCH" GOTOOLCHAIN="${GOTOOLCHAIN:-local}" go build -o /dev/null ./cmd/agentprov-sensor
if [[ "$CHECK" == 1 ]] && ! cmp -s "$TMP/before.go" "$BINDING"; then
  echo "regen-sensor: $ARCH Go bindings drifted; regenerate and commit them" >&2
  diff -u "$TMP/before.go" "$BINDING" >&2 || true
  exit 1
fi
echo "regen-sensor: $ARCH done"
