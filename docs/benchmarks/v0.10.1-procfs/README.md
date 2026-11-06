# v0.10.1 procfs namespace follow-up

English | [中文](README.zh-CN.md)

Tested on 2026-11-06 from `fix/v0.10.1-pr34-integration`, starting at `2ab9e92`.
This follow-up repairs direct WSL collection and adds a nested PID namespace
regression gate. [Source and binary hashes](source-identity.json) identify the
exact build. The ARM64 eBPF object remains byte-for-byte unchanged.

## Changes

The amd64 sensor retains the original kernel PID/TID and task lifetime. A separate
16,384-entry LRU map resolves each task into the collector's PID namespace,
including tasks in descendant containers. The namespace FD stays open while the
sensor runs. State sampling, TLS discovery and the procfs container fallback use
that address. Normalized events retain `procfs_pid`, `procfs_tid` and
`procfs_pid_namespace` through ingestion.

Missing mappings skip procfs lookup and increment `lookup_misses`, degrading the
capability report. Tasks outside the namespace have their own counter. A mismatched
proc mount fails startup explicitly. The capability report includes the namespace,
map capacity, translated-event count, outside-namespace count and lookup misses.

The guest acceptance script also recognizes QEMU/WHPX's Microsoft hypervisor ID
when DMI identifies QEMU. Reports preserve both observations.

## Verification

| Check | Result |
| --- | --- |
| WSL access-state sampling | Passed with translated PIDs and zero lookup misses. [Final log](access-state-final.log) |
| WSL short-lived TLS clients | All eight modes passed. [Final log](tls-final.log) |
| Nested PID and mount namespaces | State sampling plus automatic, concurrent, delayed-load and new-Go-executable discovery passed. [Log](pid-namespace.log) |
| Proc mount mismatch | Correctly mounted namespace passed; wrong proc mount was rejected with the expected diagnostic. [Log](namespace-guard.log) |
| Software regressions | Sensor, accesscontrol, telemetry, producer and K8s informer race tests passed. [Log](race-final.log) |
| Guest identification and signed replay | Three tests passed. [Log](guest-script-tests.log) |
| Native object generation | Regeneration check passed; ARM64 object unchanged. [Log](regenerate.log) |
| Ubuntu 6.8 native tests | All 14 top-level tests and eight TLS discovery modes passed, with no failures or skips. [Log](native.log) |
| Independent syscall/C/Go ABI gate | All 62 assertions passed. [Report](sensor-live.json) |
| systemd capture and signed replay | 20 native workload events; capture, signature and imported graph verified. [Report](guest-service.json) |
| K3s attribution and Pod deletion | 104 native events, 12 closed bindings; graph verified. [Report](guest-k3s.json) |
| TLS discovery after container recreation | All 30 assertions passed. [Report](container-tls.json) |

The first WSL TLS run missed one delayed-load request during concurrent build
activity; its [original failure](tls-initial.log) remains available. The isolated
[three-repeat check](tls-delayed-repeat.log) and the final eight-mode run passed.
Automatic attachment can still follow the earliest TLS call; configure explicit
targets when that first call must be captured. No wait windows or capture budgets
were increased for these tests.

The [guest archive](guest-evidence.tar.gz) retains full reports, captured events,
signed replay and the public verification key. The service remained active with
zero restarts; [state](service-state.txt), [environment](environment.txt).

## Windows host and CET investigation

The current AMD Windows host is build `26300.9711` with KB5127648. WSL exposes no
`svm` flag and `kvm_amd` rejects the CPU. Microsoft documents the nested
virtualization fix in [KB5127936, build 26300.9818](https://support.microsoft.com/en-us/servicing/os/windows-11/2026/10/kb5127936-windows-11-25h2-26h2-update).
The x64 package was downloaded from the Microsoft Update Catalog and its SHA-256
verified against catalog metadata. It has **not been installed**. Installation,
Windows restart and actual KVM acceptance remain pending. [Host record](host-update.json)

QEMU 11.1.0 with Ubuntu 6.8 and default CET settings booted and passed a small
shadow-stack enable/return test. At about 563 seconds, PID 1 faulted with error 44
and the guest panicked. The [console](whpx-cet-panic.log.gz) and
[QEMU errors](whpx-cet-stderr.log.gz) are retained. QEMU's `cet-ss=off,cet-ibt=off`
CPU options did not remove `user_shstk` under this WHPX setup.

A separate Ubuntu HWE `7.0.0-42-generic` experiment retained CET and passed 100
explicit shadow-stack checks. Its native suite had syscall-outcome and delayed
TLS-discovery failures, and the independent capture script missed an exec anchor.
It was not accepted as the replacement environment. [Complete experiment](hwe-experiment.tar.gz)
contains both successful and failed checks. The production sensor code was not
changed around this experimental kernel's failures.

The functional guest rerun uses Ubuntu `6.8.0-139-generic`, QEMU 11.1.0/WHPX and
`nousershstk` in a disposable disk copy. That parameter disables guest userspace
shadow stacks; see the [kernel documentation](https://docs.kernel.org/next/x86/shstk.html).
The original VM disk, host security settings and ARM64 object were preserved.
The 24-hour soak remains deferred as previously agreed.

[SHA256SUMS](SHA256SUMS) covers the files in this report, excluding itself.
