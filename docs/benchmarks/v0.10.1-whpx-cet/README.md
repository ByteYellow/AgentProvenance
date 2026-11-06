# v0.10.1 WHPX CPU configuration and CET verification

Follow-up: the remaining XSAVE warning is resolved in the [capture/WHPX/TLS follow-up](../v0.10.1-followup/README.md). The logs below preserve the earlier stock-QEMU run.

English | [中文](README.zh-CN.md)

Tested on 2026-11-06–07, Asia/Shanghai. **The reproduced WHPX guest crash is
resolved by selecting `-cpu max`. CET remains enabled.** Windows stays at
`26300.9818`, QEMU at the stock 11.1.0 build, and the guest kernel at Ubuntu
`6.8.0-139-generic`. No `nousershstk` parameter or host security change is used.

## Cause and configuration

The [earlier controls](../v0.10.1-kvm-postreboot/README.md) booted without an
explicit CPU model. The guest exposed `user_shstk`, but its boot log said
`x87 FPU will use FXSAVE`. FXSAVE does not preserve CET task state. Enabling
shadow stacks and switching tasks could therefore corrupt execution in another
task, including PID 1. This also explains why a short enable/return/disable check
passed while the sustained context-switch check crashed the guest.

QEMU 11.1.0's [WHPX CPUID handler](https://github.com/qemu/qemu/blob/v11.1.0/target/i386/whpx/whpx-all.c)
overrides the CET bits from the hypervisor result after applying the configured
CPU model. This also explains why the earlier `cet-ss=off` attempt still exposed
`user_shstk`. Use a consistent CPU feature set and cold boot:

```text
qemu-system-x86_64.exe -accel whpx -cpu max ...
```

With this configuration, the guest exposes `xsave`, `xsaves` and `user_shstk`.
Its boot log includes XSAVE feature `0x800`, `Control-flow User registers`, and
uses the compacted save format. CPUID leaf `0xD`, subleaf 1 reports CET state
support in the XSS mask. While four helpers ran, `/proc/<pid>/status` reported
`x86_Thread_features: shstk` for each; this is the kernel's
[per-thread shadow-stack status](https://docs.kernel.org/arch/x86/shstk.html).
[Environment](max-environment.txt) · [CPUID and active thread state](max-cpuid-and-active-cet.txt)

## Verification

The first cold boot disabled the collector, K3s and Docker to repeat the original
control. A second cold boot enabled the normal services and repeated collection
acceptance. Both use the corrected CPU model and retain CET.

| Check | Result | Evidence |
| --- | --- | --- |
| One CET-enabled process, 120 seconds | 107,166 iterations with nested returns, CPU migration, yield and sleep; no errors | [Log](max-context-single.log) |
| Four CET-enabled processes, 240 seconds each | Each completed over 215,000 iterations and disabled CET successfully on exit | [Log](max-context-parallel.log) |
| Native sensor tests | 14 top-level tests, including all eight TLS discovery modes, passed with no skips | [Log](native.log) |
| CPU preflight and signed replay tests | 10/10 passed | [Log](guest-tests.log) |
| Independent syscall/DNS/C/OpenSSL/Go gate | 62/62 assertions passed | [Report](sensor-live.json) |
| systemd capture and signed export/import | 20 native events; original graph, signature and replay graph verified | [Report](guest-service.json) |
| K3s attribution and deletion | 107 native events, 12 closed bindings; graph verified | [Report](guest-k3s.json) |
| Container TLS recreation | 30/30 assertions passed | [Report](container-tls.json) |
| Late binding, crash recovery and deduplication | 13/13 assertions passed; no kernel-drop counter reported | [Report](node-capture.json) |
| Daemon readiness and storage failures | 11/11 assertions passed | [Report](daemon-readiness.json) |
| Service restart | Run event counts remained 27 and 114; service active and ready | [Report](service-restart.json) |
| CET under normal services | Four processes ran for 300 seconds each; all completed successfully | [Log](service-context-parallel.log) |
| Second boot observed beyond 600 seconds | Collector ready; explicit CET check passed; no kernel panic or segfault reported | [Report](final-check.json) |

The kernel still emits a `misordered xstate` warning at boot under this QEMU
CPU model; the raw logs retain it. The context-switch and collection checks above
passed with that warning present. The separately deferred 24-hour soak remains
outside this run.

## Preventing the same configuration error

`scripts/accept_kvm_guest.py` now checks every x86 CPU before running workloads.
If `user_shstk` is present without `xsave` or `xsaves`, it stops with a diagnostic
that names the missing capability and recommends the cold-boot configuration.
The report retains the common CPU flags. ARM guests skip this x86 check.

The CLI and sensor binaries are unchanged from the prior acceptance; the ARM64
object is unchanged. [Source identity](source-identity.json) records their hashes,
the updated acceptance scripts and the QEMU executable. The local WHPX launcher
now includes `-cpu max`; its previous version is backed up.

[Raw integration evidence](integration-evidence.tar.gz) contains complete logs,
events, JSON reports, signed replay and its public key. Readable JSON copies here
omit verbose stderr/diagnostics fields; readable text copies trim trailing whitespace.
The archive preserves the original text. The [CET helper](cet-context-check.c),
[CPUID probe](cpuid-state.c), [integration runner](run-integration.sh),
[restart check](service-restart.py) and [final check](final-check.py) are retained.
[Control console](control-console.log.gz) and [service console](service-console.log.gz)
preserve both boots. [SHA256SUMS](SHA256SUMS) covers all files except itself.
