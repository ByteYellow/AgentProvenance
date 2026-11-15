# v1.0 Linux amd64 acceptance

[中文](README.zh-CN.md)

Recorded on 2026-11-16 for `feature/v1.0-portable-evidence`, continuing the
[ARM64 candidate handoff](../v1.0-candidate/README.md). The
[result index](report.json) records the tested binaries, fixed budgets, runtime
inputs, and private evidence hashes. Runtime measurements use the working builds
identified there; candidate archive provenance is recorded separately.

## Correctness changes

- Restoring an execution reads the checkpoint referenced by the verified,
  persisted delivery manifest. A later executor checkpoint does not replace the
  contents of an earlier immutable package. Regression cases cover normal replay,
  lost ACK requests, lost ACK responses, and executor restart with one command
  side effect.
- Kernel event timestamps use bounded, bracketed monotonic/realtime sampling.
  An injected 8 ms scheduling delay fails the old conversion and passes the new
  conversion. The adjacent access-control tests pass with their original tolerance.
- Remote readiness checks validate caller, target generation, receiver, keys,
  worker, and capture readiness before launch. Explicit `wait_capture` configuration
  makes early delivery visible. Optional local runsc / Firecracker checks inspect
  dependencies without starting a workload.
- Guest images include udev and readable network/service configuration. Retirement
  requires the controller's target generation, expected execution inventory, and
  every verified receipt. Empty or mismatched inventories keep the evidence disk.

## Runtime results

| Coverage | Result |
| --- | --- |
| Ubuntu KVM, Linux 6.8.0-149 | All 17 recorded gates passed: syscall/TLS, lifecycle, namespace, audit variants, recovery, K3s and container TLS |
| Go 1.23.12, 1.24.13, 1.25.8, 1.26.4 | All 16 matrix cells passed: syscall/TLS, concurrent read and stack growth, discovery, PID namespace |
| Full kernel ring and mismatched procfs namespace | Explicit retained-order test passed; mismatched namespace rejected |
| Claude Code with DeepSeek | Two sessions, three attempts, explicit reexecution, lost ACK response and offline verification passed |
| gVisor | Pinned `release-20261109.0` receive/fault tests, memory restore and two-clone checks retained from this amd64 run |
| Firecracker | v1.18.0 with kernel 6.18.62 booted the current guest image; two commands, native file evidence, signed receipt and retirement passed |

The native model matrix retains `scope_state_sampling_gap` as incomplete capture.
The previous first-request discovery failure remains in the private evidence;
the final four-version namespace matrix passed. Known TLS targets can be attached
before readiness. Strict first-request coverage for an unknown new container
requires lifecycle coordination. The 24-hour soak remains deferred.

## Frozen performance budgets

Baseline and candidate used Go 1.26.4, Linux amd64, CGO disabled, `-trimpath`, and
`-s -w`, on the same 4-vCPU KVM guest. Node services were held constant during
measurement and restored afterward. Budgets were frozen before candidate runs.
Sensor and telemetry baselines use v0.10.1; Browser/Notebook costs use the clean
v1.0 source baseline because those entries are new in this version.

| Fixed workload | Result |
| --- | --- |
| Sensor off/minimal/default, burst/paced, three repeats | 18 budget checks passed |
| 100,000-event ingest and query, three baseline runs | 5 budget checks passed; candidate drain 55.84 s, peak RSS 82.1 MiB, query p95 11.15 ms |
| Browser/Notebook basic/detailed/attachments omitted, three repeats | 68 budget checks passed |
| Deliberate 1 MiB overload | Loss reported; the default burst and paced workloads reported zero kernel drops |

See the [measurement guide](../../performance-validation.md) for workload,
allowance, and storage definitions. Budgets and individual comparisons are
recorded in `report.json`.

## Reproduce and review

Use the existing [amd64 handoff commands](../v1.0-candidate/README.md#linux-amd64-continuation)
and [execution guide](../../execution-handoff.md). Firecracker's executable entry
is `scripts/accept_microvm_boot.py`; the caller supplies the pinned runtime,
kernel, built rootfs and a new output directory. Failed runs retain their disks.

The [reader preview code](../../../previews/v1.0-reader/README.md) has its own
build/check commands and synthetic Notebook fixture. The maintainer requested
that it remain available for later review; the formal Dashboard layout is unchanged.

Raw captures, signing keys, API credentials, databases, and complete diagnostic
logs stay in the private acceptance directory. This directory contains only the
reviewed summary and evidence hashes. Main merge, tagging, publication, and Pages
deployment remain subject to the final release review.
