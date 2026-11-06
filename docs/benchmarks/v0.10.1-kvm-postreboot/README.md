# v0.10.1 KVM verification after the Windows update

English | [中文](README.zh-CN.md)

Follow-up: the WHPX/CET crash below was subsequently resolved by selecting
`-cpu max`, which exposes the missing state-save capabilities. See the
[CET configuration and acceptance report](../v0.10.1-whpx-cet/README.md).
This report retains the original KVM results and failing WHPX controls.

Tested on 2026-11-06 after the user restarted Windows. **Real KVM acceleration
is restored and the functional acceptance gates passed.** The remaining
WHPX/CET failure is documented separately below.

The tested source is `8ea1dbf226cba48e38754ee7d90af7d0fa6fbdf5`, with production
code from `d77712dca426ddbea3340f0a74ecf316bb491c83`. The same binaries used in
the [procfs acceptance](../v0.10.1-procfs/README.md) were reused; no production
code, capture budgets or wait windows changed for this run.
[Source and binary hashes](source-identity.json) record the build identity.
The ARM64 object remains byte-for-byte unchanged.

## Environment

Windows now reports build `26300.9818` after KB5127936, with no pending restart.
WSL kernel `6.18.33.2-microsoft-standard-WSL2` exposes `svm`; `/dev/kvm` supports
API version 12 and VM creation. Linux QEMU 10.2.1 was launched with
`-accel kvm -cpu host`. QMP reports KVM `enabled=true, present=true`, and
`systemd-detect-virt` inside the guest reports `kvm`.

The Ubuntu guest uses `6.8.0-139-generic`, four vCPUs and 4 GiB RAM. Its regular
kernel command line contains no `nousershstk`. This nested KVM CPU does not
expose `user_shstk`; the explicit shadow-stack enable check returned `-95`.
CET-enabled execution is therefore covered only by the separate WHPX experiment.
[Host record](host.json) · [Guest environment](environment.txt) ·
[CPU flags](cpu-flags.txt) · [CET check](cet-check.log)

## Results

| Check | Result | Evidence |
| --- | --- | --- |
| Native sensor tests | 14 top-level tests passed; all eight TLS discovery modes passed; no failures or skips | [Log](native.log) |
| Independent syscall, DNS, C/OpenSSL and Go TLS gate | 62/62 assertions passed | [Report](sensor-live.json) |
| systemd capture and signed export/import | 18 native workload events; original graph, signature and imported graph verified | [Report](guest-service.json) |
| K3s attribution and Pod deletion | 105 native events; 12 bindings closed; graph verified | [Report](guest-k3s.json) |
| Container TLS discovery and recreation | 30/30 assertions passed | [Report](container-tls.json) |
| Late bindings, SIGKILL recovery and deduplication | 13/13 assertions passed | [Report](node-capture.json) |
| Daemon readiness and storage failures | 11/11 assertions passed | [Report](daemon-readiness.json) |
| Collector service restart | Stored event counts stayed at 27 and 111 for the two runs; service returned active and ready | [Report](service-restart.json) |

The first recovery run overlapped the normal systemd collector and other guest
experiments. Its 13 target assertions passed, while the capture counters reported
**11,923 kernel-dropped events**. That [original report](node-capture-concurrent.json)
is retained. The recovery test was rerun with the normal collector stopped, then
the service was restored. All 13 assertions passed again and that report contains
no kernel-drop counter. These are functional recovery checks; the previously
deferred 24-hour soak has not been run.

The [raw archive](kvm-evidence.tar.gz) retains full JSON reports, command logs,
captured events, the signed replay bundle and its public verification key.
Readable JSON copies here omit verbose stderr/diagnostics fields where present;
the originals remain in the archive. Native tests use [run-native.sh](run-native.sh).
Other checks use the repository's `accept_sensor_live.py`, `accept_kvm_guest.py`,
`accept_k3s_guest.py`, `accept_container_tls.py`, `accept_node_capture.py` and
`accept_daemon_readiness.py`. The final restart check is preserved as
[service-restart.py](service-restart.py).

## WHPX and CET control experiment

On the updated Windows host, QEMU 11.1.0/WHPX with the same Ubuntu 6.8 kernel
still exposes `user_shstk`. A small explicit enable/status/function-return/disable
check passed, followed by all 14 native tests. The guest then lost PID 1 and
panicked at about 204.58 seconds.
[Environment](whpx-environment.txt) · [CET check](whpx-cet-check.log) ·
[Native log](whpx-native.log) · [Console](whpx-cet-console.log.gz)

Two further cold boots masked `agentprov-sensor`, K3s and Docker from startup.
The services were inactive and no AgentProvenance process was running. Launching
a standalone [CET test program](cet-context-check.c) in that environment again
preceded PID 1 panics, at 54.65 and 78.46 seconds. The final host-side log records
the launch marker and connection loss; no successful helper-start or completion
message was received. These runs reproduce the failure without starting the
project's collector in that boot. The precise WHPX/CET fault remains unresolved.

[Control environment](whpx-control-environment.txt) ·
[First control console](whpx-control-console.log.gz) ·
[Repeated control console](whpx-control-final-console.log.gz) ·
[Host-side output](whpx-control-live.log) ·
[QEMU stderr](whpx-control-final-stderr.log.gz)

Use the verified KVM path on this machine. The original VM disk and host security
settings were preserved; experiments used a separate KVM overlay and a disposable
WHPX disk copy. [SHA256SUMS](SHA256SUMS) covers this report's files, excluding itself.
