# v1.0 x86 Completion Evidence

[简体中文](README.zh-CN.md)

Updated 2026-11-17 for `feature/v1.0-portable-evidence`. The recorded x86 cases,
bounded performance checks and portable packages are ready for review. Dashboard
changes remain in [local preview](../../../previews/v1.0-reader/README.md).
The maintainer has deferred the 24-hour soak, formal UI integration and publication.

## Requirement Results

| Requirement | Recorded result | Evidence |
| --- | --- | --- |
| C-01 | Authenticated recipient API retains exact Sentry birth, command watermark and command counts separately from container counts | [runsc final](runsc-final.json) |
| W-01 | Native Sensor and real Claude MCP Inspect/Read/Edit/Write/Bash/final Read; conflicts, concurrent edits, restart queries, path and generation checks; signed delivery and disconnected reading | [Workspace final](workspace-final.json) |
| E-01/E-02 | Three delivery modes, producer/exporter trust, unknown key, wrong role and tamper outcomes; four same-source packages include the independent verifier | [Candidate packages](candidate-packages.json) |
| R-01 | Native, K3s, gVisor and Firecracker evidence retained; new runsc and Guest bindings checked against observed lifetimes | [Earlier platform matrix](../v1.0-amd64/README.md), [runsc](runsc-final.json), [Kata](kata-final.json) |
| R-02 | Five scenarios pass: baseline, receiver reconnect, receiver restart, executor restart and cancellation; duplicate submit/query, lost reply, explicit retry and wrong-generation rejection | [runsc final](runsc-final.json) |
| R-03 | Nine required checks pass: Guest kernel, single delivery, concurrency, recovery, runtime binding, offline delivery, verifier, Pod rebuild and real Workspace Harness | [Kata final](kata-final.json), [version lock](kata-versions.lock.json), [four offline readers](kata-offline-final.json) |
| B-01/B-02/B-03 | Concurrent contexts/tabs, redirect, iframe/worker, background requests, download, process custody, SIGKILL recovery and query without repeated actions; selected readers remove unsupported native relations | [Browser final](browser-final.json) |
| Q-01, bounded scope | Sensor pressure, 100,000-event ingestion, resource and context/export budgets pass; frozen limits and earlier failures retained | [Performance final](performance-final.json) |
| Reader preview | Five desktop examples; English/Chinese mobile and offline checks; real selected Workspace export; existing graph, Compare, search, body and attachment readers retained | [Preview final](preview-final.json) |
| Full CI | All 15 jobs pass at `b9e6b8f`, including race checks for 50 Go packages, historical bundles/database upgrades, both Linux architectures and eBPF bindings | [CI run](https://github.com/ByteYellow/AgentProvenance/actions/runs/43997596391), [full result](ci-final.json) |

## Versions and Reuse

Each result preserves its actual capture and export identity:

- Native Workspace, runsc and Kata binaries: clean `d8a7b60`.
- Browser launcher and final Kata fixture: clean `85dd7be`; capture binaries remain `d8a7b60`.
- Shared graph encoding and Workspace/Browser reader exports: clean `f3deb10`.
- Final packages: clean `b9e6b8f`, including the updated embedded guides.
- Audit rule v4: `e82f1a3`, including the retained CI failure regression.
- Acceptance helpers and performance comparison rules: `4fb34ea`.

The `f3deb10` reader stores repeated complete graph objects once. All 36
view/query comparisons preserve their results, and historical readers still work.
Three Browser export sizes return below the original frozen limits; the basic
case falls from 2,447,919 to 1,476,157 bytes. Native Sensor and ingestion code is
unchanged, so their `d8a7b60` measurements are reused. Context/export measurements
and signed/offline delivery were rerun with `f3deb10`.

Kata used runtime-rs 4.3.1, QEMU 11.0.1, Guest kernel 6.18.56 with BTF,
K3s 1.36.4+k3s1 and containerd 2.3.4. The lock records exact artifacts,
configuration and executable hashes. Both Guest boots passed identity rejection,
delivery, concurrent isolation and recovery. The second boot also completed the
real Workspace Harness and rejected the old Target.

The general Kata runner retains `status=PENDING` for its broader future matrix;
its `r03_status=PASS` and nine required rows are preserved. Kata-specific Browser,
restore/clone, forced reclaim, late-evidence, compatibility and 24-hour rows remain
visible. This round uses the separately recorded platform cases for those shared
contracts and defers the long run.

## Performance and Failures

[performance](performance) retains original reports, frozen budgets and comparisons.
The final comparisons pass 18 Sensor checks, five ingestion checks and 68 context
checks. Recorded durations are approximately 201 seconds for the Sensor matrix,
24 seconds for full-ring pressure, 52 seconds for 100,000-event ingestion and
56 seconds for final context/export measurement.

The first strict comparison rejected a 4 KiB Linux `MemTotal` variation after a
VM boot. An explicit comparison records that one-page difference; all other
environment, input and measurement identities and every metric limit stay fixed.
The original strict failure and three export-size failures remain archived.
See [performance validation](../../performance-validation.md) for reproduction.

Kata's earlier attempts retain their original hashes and failures: Guest identity
and AppArmor configuration, ring pressure, and the owned K3s API/CoreDNS binding.
The final fixed combination passes. Host C-drive exhaustion interrupted later
archiving; WSL and the owned VM were recovered before the final export checks.

CI also exposed a short-process lifetime falling just after
the nominal coarse-clock window. Rule v4 applies the validated saved journal
receipt to process candidates, matching the existing operation-time rule.
Actual failing AppArmor/seccomp records, PID reuse and invalid-clock regressions
are retained in [the audit result](audit-final.json).

Browser CLI regression tests now resolve the shared graph format (`b9e6b8f`).
They preserve exact online/offline edge comparisons and require unsupported
relations to disappear when source records or runtime data are excluded.
The [Browser result](browser-final.json) records the executable CLI and race checks.

## Candidate Packages and Review

[Package metadata](candidate-packages.json) records source, toolchain, program
hashes and archive sizes. [CANDIDATE_SHA256SUMS](CANDIDATE_SHA256SUMS) covers
Linux/macOS amd64/arm64. Linux amd64 was executed with Go absent from `PATH`:
12 signed examples, 14 demo guides, 20 user guides, basic recording and the
standalone verifier passed. Other packages were cross-built; existing ARM/macOS
acceptance remains linked from earlier results.

Rebuild with `scripts/build-release.py` from the recorded source. Packages remain
review artifacts; this round creates no release tag or Pages deployment.
See the [candidate notes](../../releases/v1.0.0-preview.md) and
[preview instructions](../../../previews/v1.0-reader/README.md).

## Archive Scope

The `*-final.json` files contain reviewed machine-readable summaries and original
report hashes. Performance JSON and the Kata lock preserve source bytes.
Private keys, provider credentials and raw model transcripts remain local.
[SHA256SUMS](SHA256SUMS) covers this archive.

Earlier `workspace.json`, `browser.json`, `runsc-*.json` and `kata-startup.json`
remain as historical results with their original source identities.
The [gVisor receive, fault and two-clone originals](../v1.0-amd64/gvisor/summary.json)
and [Firecracker/KVM/K3s matrix](../v1.0-amd64/README.md) remain available.
