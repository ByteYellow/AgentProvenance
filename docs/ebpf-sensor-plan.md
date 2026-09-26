# eBPF Sensor Plan (Phase 4: self-owned system telemetry)

English · [简体中文](zh-CN/ebpf-sensor-plan.md)

> Status: **IMPLEMENTED** and expanded well past the original 3-probe scope
> (`internal/sensor`, `cmd/agentprov-sensor`; Linux amd64/arm64). The **As built**
> section describes current coverage. The original design below it is historical;
> current setup and measured environments are in the [KVM/K3s runbook](amd64-kvm-k3s.md).

## As built

Probes (all → the normalized schema, ingested as `source=agentprov_ebpf`):

- `execve` (+ argv), `connect` (IPv4), `openat` — **writes and sensitive
  reads** (read of a credential/secret path → `secret_path`), `process_exit`.
- Privilege/tamper: `setuid`/`setgid`, `ptrace`, `rename`/`renameat`/`renameat2`,
  `unlinkat`; amd64 also handles legacy `open`/`unlink`.
- TLS plaintext: `SSL_write`/`SSL_read` plus modern `SSL_write_ex`/`SSL_read_ex`
  uprobes → `tls_write`/`tls_read` chunks, normalized into captured-byte hash,
  short preview and allow-listed HTTP metadata. Previews can still contain
  sensitive text. Ingest derives `llm_call` and `llm_intent_caused` relationships;
  these are heuristics, not direct kernel proof of causation. See the
  [telemetry schema](telemetry-schema.md).
- Go TLS: unstripped `crypto/tls` write capture on amd64/arm64; amd64 Go
  ABIInternal 1.23-1.26 read capture at decoded return sites, paired by
  goroutine/frame. HTTP/1.1 and HTTP/2/HPACK reassembly are implemented.
- DNS: `getaddrinfo` uprobe (glibc), plus amd64 UDP/sendto DNS capture.
- Automatic TLS target discovery through visible process mappings and container
  roots, with shared-library deduplication and explicit coverage limitations.

Key learnings: noise-prefix filtering runs **before** `bpf_ringbuf_reserve` (a
discarded record still occupies the buffer), which removed a containerd-teardown
firehose; output is the **native** normalized schema (decision (b) below);
race-free `container_id` comes from a cgroup-id → cgroup-dir-inode resolver.
The product path is now `agentprov sensor stream`: a per-node supervisor that
persists bounded native batches, correlates at capture time (including late
bindings), and evaluates runtime policy without a manual JSONL ingest step.
[Native persistence](native-capture-spool.md) defines its restart, retry and
drop-accounting guarantees. Ordinary KVM guests run the collector in-guest.

Open follow-ups include ARM64 Go TLS reads, broader DNS/network coverage,
BoringSSL and unsupported stripped/static TLS targets. amd64 live syscall/TLS,
KVM and K3s gates already have [checked reports](benchmarks/amd64-kvm-k3s/README.md).
Observed privilege-call attempts are not proof of successful escalation, and
automatic discovery cannot guarantee capture before attachment.

## Original design

The following sections retain the initial three-probe plan. Use the linked
runbook, not this historical prerequisite list, to install the current sensor.

## Goal

A small, self-owned Linux sensor that captures the three events the correlation
engine already keys on, and emits them in the **existing normalized telemetry
schema** so the correlation/evidence core needs **zero changes** — the sensor is
just another telemetry source alongside Falco/Tetragon.

## Scope (first cut — deliberately minimal)

Three probes only:

| Event | Probe (CO-RE) | Normalized `event_type` |
|---|---|---|
| process exec | tracepoint `sched/sched_process_exec` (or `syscalls/sys_enter_execve`) | `execve` |
| network connect | kprobe `tcp_connect` (or tracepoint `syscalls/sys_enter_connect`) | `network_connect` |
| file open | tracepoint `syscalls/sys_enter_openat` | `file_open` |

Each event carries the identity the correlation engine needs:
`pid, tgid, ppid, cgroup_id, container_id (derived from cgroup path), timestamp,
+ event-specific fields (cmdline / dst_ip / path)`.

## Architecture

```
[kernel probes] -> BPF ring buffer -> [agentprov-sensor / sensor stream]
                                      -> normalized events
                                      -> ingest -> correlation -> policy/risk -> graph
```

- **Loader:** `cilium/ebpf` (pure-Go, CO-RE). Avoids libbpf at runtime. `bpf2go`
  compiles the `.c` -> `.o` at build time (needs clang/llvm + `vmlinux.h` from
  `bpftool btf dump`). Keeps runtime deps minimal; build deps are clang/llvm only.
- **Binary:** `cmd/agentprov-sensor` and `agentprov sensor stream`, Linux-only
  via `//go:build linux`. A non-Linux stub returns "sensor requires linux" so the
  main module still builds/tests on macOS/Windows.
- **Output contract:** the standalone sensor can still emit normalized JSONL for
  pipes/tests, but `agentprov sensor stream` is the supervised product path: it
  ingests into the local store, applies self-noise filtering, correlates against
  open bindings, and evaluates policy/risk by default. **Resolved → (b):** the
  sensor emits a native normalized schema, auto-detected on `source=agentprov_ebpf`
  by `mapNative` (rather than mimicking Falco/Tetragon shapes), so own-kernel
  telemetry drives the same correlation → policy → risk path.

## Container/cgroup identity

`container_id` is derived from the cgroup path of the event's task (cgroup v2:
`/sys/fs/cgroup/...`; the container runtime encodes the container id in the path,
same as Falco/Tetragon do). This is exactly the key the correlation tiers use
(`cgroup+time` 0.98 / `container+time` 0.92), so events drop straight into the
existing join. In K8s, the node resolver and informer enrich that identity with
Pod/container metadata and lifecycle intervals; a path alone is not the full
application context.

For zero-SDK supervised capture, `agentprov record` can create a real cgroup v2
leaf for the launched command. The child and descendants inherit that cgroup, so
host-level eBPF events join to the run by `cgroup_id` instead of by PID polling.
Set `AGENTPROV_CGROUP_PARENT` to a delegated parent such as
`/sys/fs/cgroup/agentprov`, or run the recorder with enough privilege to create
the leaf. On non-Linux or record-only runs, AgentProvenance uses a synthetic
scope id; that is correct when no kernel sensor is present.

## Build / run prerequisites (Linux)

- Ubuntu 22.04+ / Debian 12, kernel **5.15+**, root/sudo (CAP_BPF + CAP_PERFMON).
- `clang llvm libbpf-dev linux-headers-$(uname -r) bpftool make` + Go 1.23.
- `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h` for CO-RE.
- Docker/containerd present, to produce real container cgroups for correlation.

## Verification plan

1. Unit-test the event->normalized-schema mapping on any OS (synthetic events).
2. On Linux: run the sensor, exec a command / open a secret path / connect to a
   metadata IP inside a container; confirm events are captured and, after ingest,
   correlate to the ToolCallScope and raise the existing risk signals.
3. Extend `accept_unified_signals_attestation.sh` (or a new accept script) to
   drive the loop from REAL sensor output instead of the synthetic Falco JSONL.

## Boundaries (not in this phase)

- No kernel-side filtering policy language (consume-time policy stays in Go).
- No Windows eBPF. No cross-host aggregation (see north-star scoping decisions).
- Off-host signing/anchoring of sensor output is a later deployment concern.
