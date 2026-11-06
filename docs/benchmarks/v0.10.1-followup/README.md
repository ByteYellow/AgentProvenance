# v0.10.1 x86 follow-up: capture pressure, WHPX and TLS

English | [中文](README.zh-CN.md)

Tested on 2026-11-07, Asia/Shanghai, on the existing Ubuntu
`6.8.0-139-generic` x86 guests. This change handles the selected capture-pressure,
WHPX warning and TLS gaps. The long soak, additional kernel matrix, merge and
release remain deferred.

## Capture under pressure

The reader now decodes without reflection or per-record allocations, drains the
kernel ring independently of JSON output, and uses bounded caches keyed by task
or process lifetime. The default ring is 64 MiB; the userspace queue holds 16,384
records. `--ring-buffer-mib` accepts powers of two from 1 to 256. Normal shutdown
flushes pending records before closing the reader.

The [pressure gate](../../../scripts/accept_sensor_pressure.py) launches four
processes and counts every open attempt, result and exit. It stops the sensor
immediately after the workload, so the test also covers shutdown drain.

| Workload | Previous binary | Updated binary |
| --- | --- | --- |
| 40,000 opens in about 0.12 seconds | 60,428 kernel drops; shutdown left queued events unread | 40,000 attempts + 40,000 results + 5 exits; zero drops |
| 160,000 paced opens in about 17 seconds | 33,477 kernel drops; incomplete counts | 160,000 attempts + 160,000 results + 5 exits; zero drops |
| Deliberate overload with a 1 MiB ring | — | 61,810 drops reported; bounded queue and clean shutdown |

Peak sensor RSS was 265,608 KiB (about 259 MiB) in the default-buffer burst.
The increase includes the larger kernel mapping and userspace queue. Smaller
nodes can select a lower ring budget. These are measured workloads, not an
unlimited throughput guarantee. [Full counts and timings](pressure.json)

## WHPX XSAVE metadata

The remaining warning came from QEMU 11.1.0's WHPX XSAVE initialization: it copied
component sizes and offsets but omitted the ECX attributes used to distinguish
supervisor state. The [one-line patch](../../../scripts/patches/qemu-11.1-whpx-xsave-ecx.patch)
copies those attributes from the hypervisor as well.

The local executable was rebuilt from the official QEMU 11.1.0 source archive.
The guest still uses `-accel whpx -cpu max`, with CET enabled and no
`nousershstk`. CPUID `0xD.11` and `0xD.12` now report ECX `1`; the
`misordered xstate` warning is absent. Four CET-enabled processes each ran
120 seconds of nested returns, CPU migration, yield and sleep, with zero
failures. Normal collector, Docker and K3s services remained enabled.

[CPUID and context switches](whpx-cpuid-cet-context.log) ·
[Boot and final environment](whpx-environment.txt) · [Build recipe](qemu-build.md)

## TLS coverage

- amd64 Go 1.23–1.26 binaries can resolve TLS functions from bounded Go function
  metadata after `-s -w`, including PIE. Read still uses decoded return-site
  uprobes. Both regular and stripped fixtures matched the exact bytes returned
  by 32 concurrent goroutines with stack growth and no retained read contexts.
- Shared and statically linked BoringSSL fixtures captured their first request
  and exact response. Missing `_ex` APIs are `not_applicable`; lifecycle probes
  remain required. The static fixture retains C function symbols.
- Installed host OpenSSL libraries are attached before readiness. Repeatable
  `--tls-target` paths prepare known libraries or Go executables before workload
  startup and are revisited after file replacement. The new first-request test
  adds no client startup delay.

Automatic attachment to a newly appearing, unconfigured container inode can
still lose its first call. Unknown Go ABIs and C TLS binaries without resolvable
function symbols remain unsupported. The existing 4 KiB per-call capture budget
also remains in effect; capability and gap reports retain these boundaries.

## Regression results

| Check | Result | Evidence |
| --- | --- | --- |
| KVM native tests | 15 top-level tests passed; eight automatic-discovery modes and five first-request variants; no skips | [Log](kvm-native.log) |
| Patched WHPX native tests | Same 15 tests passed; no skips | [Log](whpx-native.log) |
| Independent syscall/DNS/C/OpenSSL/Go acceptance | 62/62 | [Report](kvm-sensor-live.json) |
| K3s container TLS recreation | 30/30 | [Report](kvm-container-tls.json) |
| Late binding, SIGKILL recovery and deduplication | 13/13 | [Report](kvm-node-capture.json) |
| Sensor/CLI/telemetry/producer race checks | Passed | [Log](race.log) |
| CLI and translation tests | Passed | [Log](cli-tests.log) |
| Updated guest services | Both active and ready with the configured buffers | [KVM](kvm-installed.json), [WHPX](whpx-installed.json) |

The live service still reports `degraded` when it encounters unsupported
background TLS executables; the individual reasons remain visible. Required
syscall capture is ready on both guests.

The BPF objects, including the ARM64 object, are unchanged. Production source,
binaries, QEMU and BoringSSL fixture versions are recorded in
[source-identity.json](source-identity.json). [SHA256SUMS](SHA256SUMS) covers this
evidence directory. The existing branch receives the changes; no release or
merge is performed.
