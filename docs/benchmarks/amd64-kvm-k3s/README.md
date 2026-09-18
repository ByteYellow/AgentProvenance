# amd64 / KVM / K3s acceptance evidence

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
