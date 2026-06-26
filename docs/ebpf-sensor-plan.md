# eBPF Sensor Plan (Phase 4: self-owned system telemetry)

> Status: design, pre-implementation. Captures the agreed approach so the build
> moves fast once a Linux environment is available. Review/edit this before
> implementation. This is the differentiated half of the thesis: today the
> system-side telemetry is consume-only (Falco/Tetragon JSONL); this sensor makes
> AgentProvenance capture its own kernel events.

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
[kernel probes] -> BPF ring buffer -> [agentprov-sensor (Go)] -> normalized JSONL
                                                              -> telemetry ingest -> correlation -> signals
```

- **Loader:** `cilium/ebpf` (pure-Go, CO-RE). Avoids libbpf at runtime. `bpf2go`
  compiles the `.c` -> `.o` at build time (needs clang/llvm + `vmlinux.h` from
  `bpftool btf dump`). Keeps runtime deps minimal; build deps are clang/llvm only.
- **Binary:** new `cmd/agentprov-sensor` (or `agentprov sensor run`), Linux-only
  via `//go:build linux`. A non-Linux stub returns "sensor requires linux" so the
  main module still builds/tests on macOS/Windows.
- **Output contract:** the sensor does NOT touch the DB. It emits normalized
  telemetry events to stdout/JSONL (or a spool file). Ingestion reuses the
  existing path. **Open decision (decide on Linux, not now):**
  - (a) emit Falco/Tetragon-shaped JSONL -> reuse `telemetry ingest-falco` as-is
    (zero new ingest code), or
  - (b) emit a native normalized schema -> add a thin `telemetry ingest` receiver.
  Lean (a) for the first cut (fastest, no new format); revisit if the mapping is
  lossy.

## Container/cgroup identity

`container_id` is derived from the cgroup path of the event's task (cgroup v2:
`/sys/fs/cgroup/...`; the container runtime encodes the container id in the path,
same as Falco/Tetragon do). This is exactly the key the correlation tiers use
(`cgroup+time` 0.98 / `container+time` 0.92), so events drop straight into the
existing join. In K8s the cgroup path encodes pod/container — no extra work.

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

## Connection mode for implementation

- **A — SSH direct:** Linux reachable from the dev host; build/test driven over
  `ssh`. Provide host/port/user/key.
- **B — copilot:** commands/code authored here, run on Linux, output pasted back.
