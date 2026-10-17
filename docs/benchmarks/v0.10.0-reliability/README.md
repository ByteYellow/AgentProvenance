# v0.10.0 correctness and x86 regression acceptance

English | [中文](README.zh-CN.md)

Checked on 2026-10-17 against the six review findings on `cd66fa9`. See [acceptance.json](acceptance.json) for machine-readable results and the tested CLI hash.

## Changes

- Current-schema opens avoid migration writes. Native replay commits at most 16 rows per transaction, ending after the current row when 50 ms has elapsed. Transient SQLite contention receives at most three attempts. Sealing runs independently, queue priorities refresh after each batch, and canceled processing becomes immediately retryable.
- Malformed transcript input reports its line and preserves the previous objects and graph.
- Dashboard overviews verify current data and object files. Counts and old bundle metadata no longer substitute for verification. The existing full-verification path remains for runs above 5,000 objects.
- Unknown substrate confidence stays absent; explicit zero remains meaningful.
- Historical process and thread-group projections remain compatible with the six pinned demo bundles; new process-lifetime identities retain their current behavior.
- Live OpenSSL fixtures use their observed kernel PID across PID namespaces.

Regression tests cover partial chunk commits followed by failure and recovery, receipt/manifests/counter consistency, automatic sealing during capture, cancellation recovery, malformed reanalysis, and verification after data, schema and object-file changes.

## Results

| Gate | Result |
| --- | --- |
| Full Go race suite and vet | 35 tested packages passed; vet passed |
| Targeted regressions and frontend evidence status | Passed |
| Six pinned v0.8.2 signed demos | All 144 views, original contents/signatures and database upgrades passed with the original assertions |
| DeepSeek replay | 2,532 records, 379 objects, duplicate import and HTTP checks passed; zero graph errors/warnings |
| WSL amd64, Linux 6.18.33.2 | All 62 native capture checks passed |
| Ubuntu amd64, Linux 6.8.0-139 | All 62 native capture checks passed |
| Live OpenSSL on both kernels | Lifecycle, nesting, exit/exec cleanup and 32 concurrent reads passed |
| Go TLS on WSL | 32 concurrent connections matched exact bytes, with zero drops or retained contexts |
| Guest service | 16 native events; graph verification, export and imported verification passed |
| K3s | 66 Pod events correctly attributed, 12 bindings closed after deletion; zero graph errors/warnings |
| Collector restart | 102 existing event IDs preserved, zero duplicate native events, probes reattached and replay resumed |
| Documentation and auxiliary workflows | 50 Chinese documents and 311 links/images passed; Phase 1, LLM causality and native risk gates passed |

During service and K3s acceptance the collector had zero automatic restarts and no SQLite lock or spool retry errors. The node-wide status snapshot recorded two kernel-buffer drops and retained pending unattributed events; these counters remain separate from individual fixture results.

## Environment and reproduction

The guest used Windows QEMU with **WHPX hardware acceleration**, Ubuntu 24.04.5 and K3s v1.36.4+k3s1. The guest reports virtualization as `qemu`. Current WSL does not expose the extensions required for hardware KVM; that acceleration layer awaits environment restoration. TCG runs on this machine experienced timeouts and kernel drops, so final guest acceptance used WHPX. Testing used a disposable snapshot and preserved the original image.

The existing [guest service](../../../scripts/accept_kvm_guest.py), [K3s](../../../scripts/accept_k3s_guest.py), [native capture](../../../scripts/accept_sensor_live.py), [legacy demo](../../../scripts/accept_legacy_context.py) and [DeepSeek](../../../scripts/accept_deepseek_context.py) gates retain their assertions and default waits. Native capture used `--require-cgroup-lifecycle --pause-drain 1.5`.

This run covers amd64. ARM64 retains its earlier acceptance; the previously deferred 24-hour soak remains outside this run.
