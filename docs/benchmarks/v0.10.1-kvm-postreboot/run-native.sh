#!/bin/bash
set -euo pipefail
cd /var/tmp/agentprov-procfs
mkdir -p results
uname -a > results/environment.txt
cat /proc/cmdline >> results/environment.txt
systemd-detect-virt >> results/environment.txt
grep -m1 '^flags' /proc/cpuinfo > results/cpu-flags.txt
sha256sum bin/agentprov bin/agentprov-sensor bin/sensor.test > results/binary-sha256.txt
cc -O2 cet-check.c -o bin/cet-check
./bin/cet-check > results/cet-check.log || true
env PATH=/var/tmp/agentprov-go123/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin GOTOOLCHAIN=local GOCACHE=/var/tmp/agentprov-go-cache AGENTPROV_LIVE_OUTCOMES=1 AGENTPROV_ACCESS_STATE_LIVE=1 AGENTPROV_LIVE_OPENSSL=1 AGENTPROV_LIVE_GOTLS=1 AGENTPROV_LIVE_TLS_CLIENT=/var/tmp/agentprov-procfs/bin/tls-client ./bin/sensor.test -test.run '^(TestLiveSyscallOutcomes|TestLiveSensorAccessState|TestLiveOpenSSL.*|TestLiveTLSDiscoveryShortClient|TestTLSMessageMap.*|TestLiveGoTLSReadConcurrentStackGrowth)$' -test.v -test.timeout=10m > results/native.log 2>&1
tail -8 results/native.log
