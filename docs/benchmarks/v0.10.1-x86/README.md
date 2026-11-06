# v0.10.1 Linux x86_64 acceptance

English | [中文](README.zh-CN.md)

Validated on 2026-11-06 against `fix/v0.10.1-pr34-integration`, starting at
`45d1c00`. The original portable package (`4828cce`) and the corrected native
build both passed on Ubuntu 24.04.5, kernel `6.8.0-139-generic`, using QEMU/WHPX.
The corrected build uses Go 1.23.12. [Source and binary hashes](source-identity.json)
identify the tested changes; the ARM64 object is unchanged.

## Results

| Gate | Result |
| --- | --- |
| Original portable package | All three groups PASS; no skipped tests. See [baseline logs](baseline-package). |
| Corrected native tests | 14 top-level tests, including syscall outcomes, procfs access state, OpenSSL lifecycle/concurrency/chunk boundaries/ring loss, and Go TLS Read; no failures or skips. [Log](native.log) |
| Short-lived TLS discovery | All eight modes passed: 1/1, 1/1, 1/1, 1/1, 1/1, 8/8, 2/2 and 1/1 first requests. Attach latency, CPU and scan counters remain in the native log. |
| x86 syscall/C/Go ABI and capture timestamps | All 62 assertions passed. [Report](sensor-live.json) |
| systemd capture and signed replay | 18 native workload events; capture and imported graph verified; signature verified. [Report](guest-service.json) |
| K3s attribution and Pod deletion | 105 native workload events and 12 closed bindings; graph verified. [Report](guest-k3s.json) |
| Late Pod binding, crash recovery and deduplication | All 13 assertions passed. [Report](node-capture.json) |
| Automatic container TLS after Pod recreation | All 30 assertions passed. [Report](container-tls.json) |
| Daemon readiness and storage faults | All 11 assertions passed. [Report](daemon-readiness.json) |
| Collector restart | Recorded runs retained exactly 27 and 111 events. [Report](service-restart.json) |

The [complete guest evidence archive](guest-evidence.tar.gz) retains original
JSON reports, event samples, diagnostic output, the signed replay bundle and its
public verification key. Compact JSON files beside this document omit repeated
capability dumps; the originals remain in the archive. [SHA256SUMS](SHA256SUMS)
covers every evidence file in this directory except the checksum list itself.

## Fixes and regression coverage

Named syscall tracepoints store `__syscall_nr` as a 32-bit integer followed by
alignment padding. The old 64-bit read included nonzero padding on the WSL 6.18
kernel, breaking entry/return pairing. The sensor now uses only the signed
32-bit number. Live assertions also require the architecture's exact syscall
number. [Original raw diagnostic](wsl-syscall-diagnostic.log)

BPF generation now explicitly selects ISA v3, which is required by the atomic
fetch-add used for TLS call sequence numbers. Native regeneration with `--check`
passes. The amd64 CI matrix now runs all eight short-lived discovery modes and
uploads their metrics. The guest guide also reflects default daemon authentication.

## Software regression checks

All 39 test-bearing packages passed both complete repository runs:

- `go test -count=1 -p 2 -timeout 10m ./...`: [ordinary tests](unit-tests.log).
- `CGO_ENABLED=1 go test -race -count=1 -p 2 -timeout 20m ./...`: [race tests](full-race.log).

The cache investigation's [runner stack](go-cache-diagnostic.log) is retained
separately from test results.

Race tests passed for `sensor`, `telemetry`, `producer`, `producer/k8sinformer`
and `record`; [log](targeted-race.log). `go vet ./...`, native regeneration,
signed CLI handoff (including tamper rejection), context display, Dashboard
workspace and static reader checks also passed. Documentation validation covers
58 Chinese documents and local links/images.

The first full-repository run stalled while Go computed test-cache input hashes
on the Windows-mounted worktree. A runner stack placed the work in
`computeTestInputsID` / `search.InDir` / `filepath.EvalSymlinks`, after test
subprocesses exited. [Initial partial log](full-race-incomplete.log).
Both final full-suite runs passed with `-count=1` to bypass test-result caching;
all tests, assertions and timeouts were kept intact.

## Environment boundaries and follow-up

- **KVM acceleration:** this Windows/WSL host still rejects `kvm_amd` with
  `SVM not supported by CPU 0`. This run used WHPX. An actual KVM rerun remains
  pending when nested virtualization is available.
- **WSL direct collection:** kernel PID/TID values differ from the distribution's
  `/proc` namespace. The default WSL run fails automatic state sampling and
  event-driven TLS discovery. Its [original logs](wsl-original) are retained.
  Namespace-aware process lookup and explicit coverage reporting remain needed;
  use the validated Linux guest for these paths on this machine.
- **CET under WHPX:** the first VM boot lost PID 1 to a `SIGSEGV` at a libc return
  instruction with page-fault error `44`, followed by a kernel panic. The
  [console](whpx-first-boot.log.gz) is retained. Final gates ran with the guest-only
  `nousershstk` kernel parameter; [environment](environment.json). The exact cause
  and CET-enabled compatibility need a separate controlled reproduction. The
  parameter is documented by the [Linux kernel](https://docs.kernel.org/next/x86/shstk.html).
- **Long-running acceptance:** the 24-hour soak remains deferred at the user's
  request. No long-duration claim is made by these functional and recovery gates.

No wait windows or capture budgets were increased, and no required test was
removed. This acceptance does not publish a release or merge the integration branch.
