# v1.0 x86 Completion Evidence

[简体中文](README.zh-CN.md)

These machine-readable summaries retain the measured results from the November
16 x86 work. They cover the scenarios below; remaining v1.0 requirements stay
open. The 24-hour soak is maintainer-deferred.

| Scenario | Result | Evidence |
| --- | --- | --- |
| Workspace with native Sensor and real Claude MCP calls | Passed: Inspect, Read, Edit, Write, Bash, final Read; conflict, concurrent edit, path and generation checks | [Workspace](workspace.json) |
| Workspace signed delivery and disconnected reader | Passed: source stores retired, fresh receiver import, trusted/unknown-key/wrong-role/tamper checks, two readers with zero network requests | [Workspace](workspace.json) |
| Browser native capture and signed delivery | Passed: concurrent contexts/tabs, redirect, iframe/worker, background traffic, download, selective export and four disconnected readers | [Browser](browser.json) |
| Browser SIGKILL recovery with native capture | Passed: completed and interrupted operations queried three times each; each HTTP side effect occurred once; interrupted generation stayed unsealed | [Browser](browser.json) |
| Controlled runsc launch | Passed on clean source `45ce9ad`: exact Sentry birth persisted before dispatch, failed checkpoint prevented dispatch, cancellation retained unknown completion | [runsc](runsc-controlled.json) |
| runsc command capture | Passed: successful and nonzero exits, native child ownership, committed completion marker and original event identities | [Command evidence](runsc-command-capture.json) |
| runsc authenticated API and faults | Passed: lost response, duplicate submission/query, explicit retry, wrong generation, signed delivery, receiver reconnect/restart, executor restart and cancellation | [Fault matrix](runsc-execution.json) |
| Kata/QEMU Guest | Incomplete: Guest Sensor and required probes reached ready; command preparation exposed competing SQLite writers, with the subsequent fix awaiting a complete rerun | [Kata attempts](kata-startup.json) |

## Source and Checksum Scope

Workspace and Browser CLI binaries were built from local commit `cdfb7cb`, whose
full Git tree equals published commit `71d8625`. Their summaries preserve that
binary identity and the original report digests. Those original top-level reports
did not record a fixture checkout SHA. Keep these historical measurements with
that identity; final candidate acceptance will record the complete fixture pin.

The runsc retest used a clean checkout of published commit
`45ce9ad3179d55091073775af1893f805336e240`, rebuilt CLI and test executables, and a
fresh disposable container. Its summary includes executable hashes, process birth
checkpoints, failure/cancellation outcomes and the test log digest.

The command capture and API matrix summaries record their own clean CLI and
fixture commits, executable hashes, original report hashes and per-case
checkpoints. The API matrix completed all five scenarios in 82.98 seconds.
Its CLI source `afe3f96` differs from published `5fea599` only in
`scripts/accept_execution_runsc.py`; application source is identical. The tested
fixture is pinned separately as `fbaebd3` and by its file digest. Three earlier
fixture failures remain alongside the successful result.

The JSON files are reviewed summaries of synthetic fixtures. They include full
check outcomes, evidence references, capture counters, archive hashes and original
report hashes. Provider credentials, private signing keys and model transcripts
remain in private acceptance directories. [SHA256SUMS](SHA256SUMS) covers these
published files.

## Remaining Completion Work

- Complete Kata command preparation under native ingestion, concurrent execution, recovery, Pod
  rebuild, stale Target rejection and the real Workspace Harness.
- Complete the remaining boundary review, bounded resource validation, final
  package checks (including the runsc regression) and preview/documentation review.

Formal Dashboard integration, main merge, tags, Release and Pages deployment
remain for maintainer review.
