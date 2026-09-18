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
