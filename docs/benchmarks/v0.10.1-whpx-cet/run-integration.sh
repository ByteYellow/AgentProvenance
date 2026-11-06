#!/bin/bash
set -euo pipefail
cd /var/tmp/agentprov-procfs
report=/var/tmp/cet-fix/integration
mkdir -p "$report"
export PATH=/var/tmp/agentprov-go123/bin:$PATH GOTOOLCHAIN=local GOCACHE=/var/tmp/agentprov-go-cache
uname -a > "$report/environment.txt"
cat /proc/cmdline >> "$report/environment.txt"
grep -m1 '^flags' /proc/cpuinfo >> "$report/environment.txt"
sha256sum bin/agentprov bin/agentprov-sensor bin/sensor.test > "$report/binary-sha256.txt"
AGENTPROV_TEST_BINARY="$PWD/bin/agentprov" python3 -m unittest discover -s scripts -p test_kvm_guest.py -v > "$report/guest-tests.log" 2>&1
echo 'Guest CPU preflight and signed replay tests passed'
systemctl stop agentprov-sensor.service
cc -O2 internal/sensor/testdata/tls_client.c -lssl -lcrypto -o bin/c-client
python3 scripts/accept_sensor_live.py --sensor "$PWD/bin/agentprov-sensor" --go-client "$PWD/bin/tls-client" --c-client "$PWD/bin/c-client" --ssl-lib /usr/lib/x86_64-linux-gnu/libssl.so.3 --pause-drain 1.5 --require-cgroup-lifecycle --report "$report/sensor-live.json" > "$report/sensor-live.log" 2>&1
echo 'Independent native capture passed'
AGENTPROV="$PWD/bin/agentprov" SENSOR="$PWD/bin/agentprov-sensor" bash scripts/install-kvm-guest.sh > "$report/service-install.log" 2>&1
python3 scripts/accept_kvm_guest.py --data-dir /var/lib/agentprov-v0101 --report "$report/guest-service.json" > "$report/guest-service.log" 2>&1
echo 'Service and signed export/import passed'
AGENTPROV="$PWD/bin/agentprov" bash scripts/install-k3s-guest.sh > "$report/controller-install.log" 2>&1
python3 scripts/accept_k3s_guest.py --data-dir /var/lib/agentprov-v0101 --image docker.io/rancher/mirrored-library-busybox:1.37.0 --report "$report/guest-k3s.json" > "$report/guest-k3s.log" 2>&1
echo 'K3s attribution passed'
systemctl stop agentprov-sensor.service
trap 'systemctl start agentprov-sensor.service' EXIT
python3 scripts/accept_container_tls.py --sensor "$PWD/bin/agentprov-sensor" --go-client "$PWD/bin/tls-client" --c-client "$PWD/bin/c-client" --report "$report/container-tls.json" > "$report/container-tls.log" 2>&1
echo 'Container TLS recreation passed'
python3 scripts/accept_node_capture.py --agentprov "$PWD/bin/agentprov" --report "$report/node-capture.json" > "$report/node-capture.log" 2>&1
echo 'Crash recovery passed'
python3 scripts/accept_daemon_readiness.py --agentprov "$PWD/bin/agentprov" --report "$report/daemon-readiness.json" > "$report/daemon-readiness.log" 2>&1
echo 'Daemon health and storage faults passed'
systemctl start agentprov-sensor.service
trap - EXIT
uptime > "$report/uptime.txt"
dmesg > "$report/dmesg.txt"
systemctl show agentprov-sensor -p NRestarts -p ActiveState > "$report/service-state.txt"
