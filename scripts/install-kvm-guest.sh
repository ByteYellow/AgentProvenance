#!/usr/bin/env bash
set -euo pipefail
# Run INSIDE the Linux guest. This installs the evidence collector, not a VM
# scheduler or a host-side proxy for the guest kernel.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ "$EUID" == 0 ]] || { echo 'run as root inside the guest' >&2; exit 2; }
AGENTPROV="${AGENTPROV:?set AGENTPROV to the guest-architecture CLI binary}"
SENSOR="${SENSOR:?set SENSOR to the guest-architecture raw sensor binary}"
[[ -r /sys/kernel/btf/vmlinux ]] || { echo 'guest kernel BTF is required' >&2; exit 2; }
[[ -x "$AGENTPROV" && -x "$SENSOR" ]] || { echo 'both binaries must be executable' >&2; exit 2; }
systemctl stop agentprov-sensor.service 2>/dev/null || true
install -m 0755 "$AGENTPROV" /usr/local/bin/agentprov
install -m 0755 "$SENSOR" /usr/local/bin/agentprov-sensor
install -m 0644 "$ROOT_DIR/deploy/kvm/agentprov-sensor.service" /etc/systemd/system/agentprov-sensor.service
install -d -m 0700 /var/lib/agentprov
systemctl daemon-reload
systemctl enable --now agentprov-sensor.service
# Type=simple only means a process started. Require the actual probe readiness
# emitted by this service invocation before reporting a successful installation.
INVOCATION="$(systemctl show agentprov-sensor.service --property=InvocationID --value)"
for _ in $(seq 1 100); do
  if journalctl "_SYSTEMD_INVOCATION_ID=$INVOCATION" --no-pager -o cat | grep -q 'ready probes-attached'; then
    echo 'AgentProvenance guest collector ready; store=/var/lib/agentprov'
    exit 0
  fi
  sleep 0.1
done
journalctl "_SYSTEMD_INVOCATION_ID=$INVOCATION" --no-pager -o cat >&2
echo 'guest collector did not attach its probes' >&2
exit 1
