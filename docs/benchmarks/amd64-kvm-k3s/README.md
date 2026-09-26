# amd64 / KVM / K3s acceptance evidence

English | [中文](README.zh-CN.md)

Recorded locally on 2026-09-19 (Asia/Shanghai), on the working branch based on
`fc2e626`. This is live validation on the two listed kernels, not a claim that
hosted CI or every Linux/kernel/TLS combination has passed.

- `sensor-live-wsl.json`, `sensor-live.json`: 26 assertions on WSL and KVM guest;
  userspace draining was paused while kernel probes continued.
- `kvm-service.json`, `kvm-after-reboot.json`: scoped service ingestion,
  graph verification and export/import into a fresh store. Boot IDs differ.
- `k3s-continuous.json`, `k3s-after-reboot.json`: Pod events flow through the
  informer binding into the shared node store, and deletion closes the binding.
- `k3s-multiworkload.json`: eight independently scheduled workloads observed by
  one real sensor DaemonSet, with a verified graph.
- `k3s-parity.json`: canonical exec/graph semantics agree between local record
  and a Pod, retaining the different attribution confidence tiers.
- `k3s-informer.json`: container restart rebinds and Pod deletion closes both
  generations of the binding.
- `environment.json`: base commit, branch, actual KVM enablement, binary hashes
  and unchanged ARM64 object hash.

The local delivery folder also retains fixture-only JSONL, exported bundles and
verification logs. Private VM keys and cloud-init credentials are not in this
repository. See [the runbook](../../amd64-kvm-k3s.md) for reproduction and limits.

## Native capture and container TLS follow-up

The following reports are from the subsequent hardening work on the same
adaptation branch. Earlier reports above remain the original baseline.

- `sensor-live-hardening-wsl.json`, `sensor-live-hardening-kvm.json`: 27 live
  assertions including Go TLS response plaintext, with paused draining.
- `container-tls.json`: 30 assertions across two generations of three containers;
  automatic discovery captures exactly one request and response per container
  for Go, OpenSSL legacy and OpenSSL `_ex`, including shared overlay libraries.
- `node-capture.json`: immediate-exit Pods precede their informer bindings;
  two collector crashes test durable recovery, closed historical attribution,
  graph verification, run isolation and event-ID stability.
- `kvm-service-hardening.json`, `k3s-continuous-hardening.json`,
  `k3s-informer-hardening.json`: upgraded installed collector/controller,
  evidence export/import and container restart/delete lifecycle.
- `upgrade-hardening.json`: a frozen store built with `3093335` upgrades from
  schema 15 to 16 without changing any imported historical evidence rows;
  collector liveness, queue status and binary hashes are recorded. A separate
  live snapshot comparison is explicitly inconclusive: the old collector was
  still inserting/deleting uncorrelated rows while the snapshot was taken.

These gates do not prove multi-day soak stability or capture of TLS plaintext
before probes attach. The TLS fixture waits six seconds for discovery. Go TLS
Read concurrency and stack growth were also exercised on WSL with Go 1.23.12
and Go 1.26 (32 connections, exact returned bytes, no retained contexts).

## Correctness and reliability completion

The completion reports were collected after the next correctness pass. Falco's
legacy importer/worker was preserved; native recovery guarantees are not claims
about that compatibility path.

- `node-capture-completion.json`: all 13 late-attribution/crash-recovery checks
  pass again with schema 17 and transaction-local correlation.
- `daemon-readiness-completion.json`: 11 real HTTP checks, including incompatible
  schemas, missing tables, recovery, unauthenticated health, protected ordinary
  routes, and historical loss without falsely declaring the database unavailable.
- `upgrade-completion.json`: all writers were stopped before the schema 16
  snapshot. All 9,500 historical event rows match after upgrade to 17 and again
  after a normal full guest reboot. Both boot IDs and installed binary hash are
  included. This test does not emulate abrupt host power loss.
- `kvm-completion.json`, `kvm-reboot-completion.json`: installed service
  collection, graph verification and bundle export/import before and after reboot.
- `k3s-completion.json`, `k3s-reboot-completion.json`: passive Pod attribution,
  event ingestion, closed bindings and graph verification across the reboot.
- `informer-completion.json`: restart creates a second binding; deletion closes
  both, with zero retries or failed reconciliations in the recorded status.

Full `go test -race -p 4 ./...`, `go vet ./...`, formatting and Phase 1 passed.
The standalone readiness gate is included in CI. These are local acceptance
results; hosted CI status and artifacts are reported separately by GitHub Actions.
Go TLS Read was also tested locally with Go 1.24.0 and 1.25.0: each matched exact
returned bytes for 32 concurrent connections (71 chunks), with zero drops or
retained contexts. Together with the earlier 1.23.12/1.26 runs this exercises all
four declared supported minor versions, without claiming every patch release.

Code and regression evidence:

| Issue | Implementation | Regression |
| --- | --- | --- |
| String ordering of mixed timestamp representations | `correlation.resolveWindow` parses candidate instants, preserving evidence strings | `TestResolveWindowComparesInstantsWithoutRewritingEvidence` |
| Same-batch exit invisible to later correlation | `NativeStream.processBatch` and strict ingest resolve using the evidence transaction | `TestNativeBatchObservesItsOwnProcessExit` |
| Unknown database state reported healthy | `daemon.health` returns 503 and null unknown counts; `/v1/live` is separate | `TestHealthFailsWhenDatabaseUnavailable`, `TestHealthFailsWhenRequiredTableMissing`, readiness HTTP gate |
| Missing accepted capture file silently forgotten | Separate `initializing` from `capturing`; retain and report missing capture metadata | `TestNativeMissingCaptureFileIsNotSilentlyForgotten`, `TestNativeUninitializedBatchRecoveryAcceptsNewCapture` |
| Normalization creates rows too large to replay | Check normalized encoded size before accepting; persist oversized-drop count | `TestNativeNormalizationCannotCreateAnUnreplayableRow` |
| Cleanup failure prevents collector restart | Defer completed payload cleanup to bounded runtime sweeps, retain capacity accounting | `TestNativeRestartDefersCleanupFailureWithoutBlockingCapture` |
| Newer store modified by unsupported binary | Reject future schema before executing migration DDL | `TestNewerSchemaIsRejectedBeforeMigrationWrites` |
