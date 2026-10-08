# v0.9.0 acceptance — 2026-10-08

English | [中文](README.zh-CN.md)

The agreed A1–A4 and B1 scope passed the checks below, based on
`186e6c7ce889df0c414fd01c65bf504b44273c58` plus the fixes in this change.
[report.json](report.json) preserves checks, counts, binary/object hashes and
initial failures. This is an acceptance result, not a published release.

| Gate | Result |
| --- | --- |
| Existing context adapters, DeepSeek, binding/resume, configuration and coverage | All Go packages passed on Go 1.23.12 and 1.26.0; vet and race checks passed |
| Real signed DeepSeek evidence | Original signature, 2,532 rows, content, graph links, duplicate import and negative API cases passed |
| Six v0.8.2 signed bundles | 47,997 original rows, 144 semantic graph queries, schema 17→19 upgrades and duplicate imports preserved |
| Real replay browser checks | DeepSeek: 71 assertions; historical demos: 313 assertions, including 144 rendered lens views |
| Synthetic browser edge cases | Session/configuration/coverage: 83 assertions; artifacts: 18 assertions, traversing 135 pages past 8 MiB |
| KVM Linux 6.8.0-139 x86_64 | 43 live sensor assertions; installed service, recording, attribution, graph verification and export/import passed |
| Native lifecycle ingestion | Real fork, cgroup migration and clone3 evidence retained correct process/run ownership through durable ingestion |
| K3s v1.36.4+k3s1 | Pod recording, deletion closure, local/Pod semantic parity, one DaemonSet with eight workloads, informer restart/rebinding passed |
| Short-lived Pods and crash recovery | 13 assertions: no early binding, durable capture before SIGKILL, late attribution, closed windows, isolation and no duplicates after another restart |
| Container TLS discovery | 30 assertions across OpenSSL, Go and container recreation, without explicit target paths |
| Go TLS under concurrent stack growth | 32 connections, 71 exact-byte chunks, zero drops and zero retained contexts on WSL x86_64 |
| Storage/schema faults | 11 readiness assertions, including unavailable storage, unknown counts and recovery |
| Portable Linux amd64 archive | Seven signed replays, nine bilingual guides, context and cleanup passed without Go on PATH |

The synthetic UI fixtures exercise long content, missing/null configuration,
history boundaries, ambiguous saved files, language switches, API failure and
scroll retention. They are not represented as real model executions. Existing
Claude/Codex live-session evidence remains the Mac validation documented in the
[context guide](../../agent-context.md#native-format-compatibility).

## Fixes found by acceptance

- The committed amd64 BPF object lacked the child birth-cgroup change already in
  C source and the ARM64 object. Regeneration against the guest BTF fixed the
  failing `clone-child:birth_cgroup` assertion. ARM64 bytes were unchanged.
- A busy-node readiness pipeline returned `kubectl=141`, `grep=0`: early pipe
  closure turned a successful match into failure. KVM/DaemonSet checks now drain
  logs and match the exact readiness line.
- The timestamp test now brackets its monotonic sample so scheduling between
  clock reads does not shift its expected capture time.
- `release/v0.9.0-review` previously entered publishing and looked for a missing
  review-specific release note. Review refs now validate/build only; release
  routing and notes are checked before building. Release PRs also run validation.
- Historical acceptance now recognizes all four pinned official v0.8.2 native
  binaries. CI verifies archive and executable hashes before running real old
  database migrations and the unchanged signed bundles.

## Reproduce

Build the CLI and sensor from this checkout. For historical compatibility, obtain
the matching v0.8.2 archive, verify the archive and executable hashes in
`scripts/testdata/v0.8.2-bundles.json`, then run:

```sh
python3 scripts/accept_legacy_context.py --binary /path/to/new/agentprov \
  --baseline-binary /path/to/v0.8.2/agentprov \
  --manifest scripts/testdata/v0.8.2-bundles.json --evidence-root . \
  --output /tmp/new-legacy-acceptance
python3 scripts/accept_deepseek_context.py --binary /path/to/new/agentprov \
  --output /tmp/new-deepseek-acceptance
python3 -m unittest discover -s scripts -p test_release_plan.py -v
go vet ./...
go test -race -p 2 ./...
```

The [deployment guide](../../amd64-kvm-k3s.md) describes the privileged KVM/K3s
environment. Run `accept_sensor_live.py` with `--require-cgroup-lifecycle` and
`--pause-drain 1.5`, then supply its `.events.jsonl` through
`AGENTPROV_LIVE_LIFECYCLE_EVENTS` to `TestNativeLiveLifecycleAttribution`.
Run `accept_node_capture.py`, `accept_container_tls.py`, and the three K8s
profile/lifecycle scripts in that test environment. `--image`/`IMAGE` can select
an already cached BusyBox image; this run used Rancher's BusyBox 1.37.0 mirror
after a Docker Hub pull timed out. No host proxy configuration was changed.

ARM live revalidation and the 24-hour soak remain deferred as agreed. TLS
polling/format limits remain visible in capability reports. Four-platform
release builds passed at the base commit; hosted results for this change must
be read separately from this local acceptance report.
