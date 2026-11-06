# Sensor shutdown and diagnostic regression

English | [中文](README.zh-CN.md)

Verified on 2026-11-07. The implementation commit is
`687d43c6f984c8fa6c19faa719496e3b29dcca92`; the baseline is
`ddfefdf837acc131982a904bf53f646f771f3f7c`. Source and tested binary hashes,
commands, counts and results are recorded in [verification.json](verification.json).

## Fixes

Shutdown now detaches syscall probes and stops TLS discovery and its probes
before flushing the ring. The consumer drains a finite set of accepted records,
even while other node workloads keep running. Detachment and flush errors are
returned to the caller, and cleanup waits for the shutdown worker.

The current ELF error text has matching Chinese copy and a persisted-diagnostic
format. The older error text remains supported for historical records. Protocol
errors remain English; localization applies at the presentation boundary.

## Regression evidence

| Check | Before | After |
| --- | --- | --- |
| Stop during continuous file activity | Still capturing after the five-second test deadline | Exits while the workload remains active, with TLS discovery on and off |
| Same shutdown test with the race detector | Not run against the baseline | Three repetitions of both modes passed |
| Translation source consistency | Missing Chinese copy for `invalid ELF symbol string-table link` | Current, historical and shutdown diagnostics pass |
| 40,000 file opens | See the earlier pressure report | 40,000 attempts, 40,000 results, five exits; zero drops |
| 160,000 paced opens | See the earlier pressure report | 160,000 attempts, 160,000 results, five exits; zero drops |
| Deliberate overload with a 1 MiB ring | — | Loss reported and clean shutdown |

The live environment was Linux `6.8.0-142-generic`, ARM64, four CPUs.
The independent syscall, DNS, OpenSSL, Go-write and cgroup-lifecycle acceptance
passed all 58 checks. The native race suite passed ten top-level tests, covering
access-state sampling, syscall outcomes, TLS discovery, OpenSSL concurrency,
connection lifetime and capture gaps.

Repository-wide `go test ./...`, `go vet ./...` and
`go test -race -p 2 -timeout 20m ./...` passed; both test runs covered 39
packages. All eight frontend regression scripts passed. The KVM script suite
passed nine tests and skipped its opt-in signed-bundle test.

The AMD64 sensor and test binary compile. This follow-up's live checks ran on
ARM64; the earlier [x86 report](../v0.10.1-followup/README.md) remains the record
of the previous x86 runtime acceptance. No BPF object was changed.

## Reproduce

On a disposable Linux node with eBPF permissions, a C compiler and OpenSSL
development headers:

```sh
go test -c -race -o /tmp/sensor.test ./internal/sensor
cd internal/sensor
sudo env AGENTPROV_LIVE_SHUTDOWN=1 /tmp/sensor.test \
  -test.run '^TestLiveSensorShutdown$' -test.count=3 -test.v -test.timeout=90s
```

The test keeps four file-opening threads active until after the sensor exits.
The existing [pressure gate](../../../scripts/accept_sensor_pressure.py) checks
the complementary case: the workload finishes first, then all pending attempts,
results and process exits must survive shutdown. The Linux CI workflow now
includes the continuous-traffic regression in the native sensor job.

The earlier follow-up's translation log preceded the final source consistency
failure. Its original log is retained; this report supersedes that result.
