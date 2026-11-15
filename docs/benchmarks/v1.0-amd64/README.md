# v1.0 Linux amd64 acceptance

[中文](README.zh-CN.md)

Recorded on 2026-11-16 for `feature/v1.0-portable-evidence`, continuing the
[ARM64 candidate handoff](../v1.0-candidate/README.md). The
[result index](report.json) records the tested binaries, fixed budgets, runtime
inputs, and private evidence hashes. Earlier measurements retain their working
build identities. The final Linux archive is built from clean commit
`8e044fa0543c7081065940e3f4d7ae2b82265044`; its checks are recorded separately.
The remote [runtime commit](https://github.com/ByteYellow/AgentProvenance/commit/3fd467d6e903524432b2eb4ce8991eef532aac37)
has the identical full source tree. The result index records both commit IDs
and the verified tree hash; the archive retains its original build identity.

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

The v1.0 requirements are reconciled as follows:

| Requirement | Implementation and acceptance | Review boundary |
| --- | --- | --- |
| CS-01–05 | Native call identity, parallel attempts, explicit reexecution, receipt recovery, durable capture/delivery; live model matrix and failure regressions passed | None for the recorded paths |
| CS-06–07 | Bidirectional links and selection-aware offline indexes; candidate interaction checks passed | Formal UI integration deferred by maintainer |
| CS-08 | WSL caller to KVM executor and independent offline verification; ARM64 handoff results retained | Cross-machine reproduction instructions included |
| RT-01 | Producer identity, capture manifests, capability history, late Pod attribution, JSONL receipts; KVM/K3s gates passed | Short-lived sampling gaps remain visible |
| RT-02–04 | gVisor receive/recovery/clone checks and actual Firecracker boot/retirement passed | Pinned versions and image hashes define the tested profiles |
| APP-01–02 | Browser/Notebook identities, retention, attachments and signed/offline round trips; reader preview includes body and image checks | Final reader placement deferred |
| DEMO-01–06 | Existing examples preserved; investigation, remote execution and non-coding paths available in the review build | Formal gallery integration deferred with the UI |
| DEMO-07 | Existing static publication chain retained | Publication awaits final authorization |
| N1 | Remote and optional runtime doctor/preflight implemented and tested | CLI remains English by default |
| N2 | Recovery guidance present in the retained candidate reader | Formal UI integration deferred |
| N3 | Fixed runtime inputs, evidence index, portable preview builder and candidate archive workflow | Credentials and raw logs remain local |

| Coverage | Result |
| --- | --- |
| Ubuntu KVM, Linux 6.8.0-149 | All 17 recorded gates passed: syscall/TLS, lifecycle, namespace, audit variants, recovery, K3s and container TLS |
| Go 1.23.12, 1.24.13, 1.25.8, 1.26.4 | All 16 matrix cells passed: syscall/TLS, concurrent read and stack growth, discovery, PID namespace |
| Full kernel ring and mismatched procfs namespace | Explicit retained-order test passed; mismatched namespace rejected |
| Claude Code with DeepSeek | Two sessions, three attempts, explicit reexecution, lost ACK response and offline verification passed |
| gVisor | Pinned `release-20261109.0` receive/fault tests, memory restore and two-clone checks; [original results and summary](gvisor/summary.json) archived |
| Firecracker | v1.18.0 with kernel 6.18.62 booted a guest containing the final archive's CLI; two commands, native file evidence, signed receipt and retirement passed |

The three gVisor result files are byte-for-byte copies of the original KVM
records. They were produced on **Linux 6.8.0-139-generic, x86_64**, using the
working candidate identified by CLI hash `ec65c79e…` and runsc
`release-20261109.0`. Their original timestamps, executable hashes and coverage
states are retained in the files and [summary](gvisor/summary.json).

| Acceptance | Original result | Recorded checks |
| --- | --- | --- |
| Reception | [receive.result.json](gvisor/receive.result.json) | Two targets, 130 events, drained spool, no reported target drops, graph verification |
| Fault recovery | [faults.result.json](gvisor/faults.result.json) | Pressure loss counters, 82 recovered and 341 preserved observations, reconnect, signed import and graph verification |
| Restore / two clones | [restore-clones.result.json](gvisor/restore-clones.result.json) | Four phases, preserved memory, four distinct scopes/process nodes, eight historical spool records deduplicated across clones, receipt reuse and signer reauthorization |

The first restore run failed while producing its report because it assumed a
BusyBox rootfs. The corrected run supports the Ubuntu rootfs. The
[original exit codes](gvisor/initial-run-exit-codes.tsv),
[first failure](gvisor/restore-first-failure.log) and
[successful completion record](gvisor/restore-fixed.log) are retained alongside
the successful result. [SHA-256 checksums](gvisor/SHA256SUMS) cover the archive.

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

The final archive also passed all 18 Sensor and 68 context-cost checks against
the same frozen budgets. Its first telemetry drain took **75.89 s**, exceeding
the **69.19 s** budget; the other four metrics passed. That failed measurement
remains in `release_performance.telemetry`.

After flushing pending writes before each run, the unchanged workload was
measured in baseline/candidate/candidate/baseline order. Candidate drain times
were **54.80 s** and **55.51 s**; baseline times were **56.13 s** and **69.05 s**.
Every control met the original budget. The initial cause was not instrumented;
the paired runs did not show a persistent candidate regression. All four reports
and the initial exceedance remain available. No budget was increased.

## Candidate archive

`agentprov_v1.0.0-candidate_linux_amd64.tar.gz` and its SHA-256 file are retained
in the maintainer's handoff. The result index records the complete archive hash,
build metadata, guest rootfs and runtime input hashes. The final archive passed
the no-Go acceptance: 12 signed replays, 14 demo guides, 20 user guides, English
and Chinese pages, recorded-context queries, and process cleanup.

The same CLI verified six frozen v0.8.2 signed examples, compared 144 graph
views, preserved 47,997 original rows, and upgraded six databases from schema
17 to 27. Duplicate imports and unknown historical coverage stayed intact.
The recorded DeepSeek example also passed signature, content, query and
duplicate-import checks. Full Go tests, vet, affected-package race tests,
Python, eight frontend suites and localized-document checks passed.

The reader preview is retained separately as
`AgentProvenance-v1.0-reader-preview-20261116.zip`. Extract it and open
`index.html`; all four example inventories were verified. The preview can also
be rebuilt from the source instructions below. This candidate has not been
published as a GitHub release.

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
