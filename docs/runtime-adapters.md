# Runtime Adapters

Runtime adaptation separates a trusted platform binding, command execution, and capture. The handoff ledger remains the authority for admission, attempts, cancellation requests, query, checkpoints, recovery, and delivery. Adapters do not keep a second execution journal.

## Current Boundary

| Mode | Execution | Capture | Acceptance boundary |
| --- | --- | --- | --- |
| Default / `native` | Existing `record.Service`, policies, snapshots, scope lifecycle and recovery | Existing native capture controller | Existing native behavior and local regression tests |
| `guest` | The same executor inside the Guest | Native sensor with `guest_kernel` placement | Trusted Guest mapping and the existing native evidence pipeline; platform-specific live validation remains separate |
| `runsc` | One fixed `runsc exec` container entry | A separately managed SecCheck receiver | Container/Sentry range observations plus operation API receipts; per-command event association remains pending |

Per-command event association remains pending for runsc. A successful execution receipt may coexist with `capture=incomplete`, retaining `shared_call_identity_unavailable` and `command_capture_watermark_unavailable`. Receiver events stay in their configured run, separately from the command run; read both scopes during an investigation. Deployment-host validation for this entry and the new Kata/QEMU combination uses the commands below.

## Native And Guest Configuration

Continue using `agentprov daemon serve --execution-config PATH`. Omitting `backend` preserves the native default, including non-root development configuration and existing concurrency defaults. Explicit `{"backend":{"mode":"native"}}` selects the same path.

Guest configuration extends the existing handoff configuration:

```json
{
  "target": {"producer_id":"node-a","instance_id":"pod-uid","generation":"operator-generation-1"},
  "caller": {"principal_id":"router","producer_id":"source","namespace":"lab"},
  "concurrency": 2,
  "backend": {
    "mode":"guest",
    "guest": {
      "runtime_class":"kata-qemu",
      "runtime_handler":"kata-qemu-runtime-rs",
      "pod_uid":"pod-uid",
      "container_id":"raw-cri-container-id",
      "guest_boot_id":"actual-guest-kernel-boot-id"
    }
  },
  "capture": {"mode":"native","placement":"guest_kernel"}
}
```

`backend.guest` is optional for existing Guest deployments; when supplied, all five fields are required. The trusted platform launcher compares live RuntimeClass/handler, Pod UID and CRI container identity with its operator receipt before producing this configuration. Workload labels are not identity sources. The daemon separately checks `guest_boot_id` against `/proc/sys/kernel/random/boot_id`.

The configuration file and all its ancestors must be root-owned, non-symlink paths without group/other write permission for Guest and runsc modes. Place checked projected-volume content into real files in a root-owned, read-only binding directory before starting the daemon. Keep the executor store, runsc state, binary and PID scratch directory outside workload-writable mounts.

The full Target and platform mapping are saved in `checkpoint.platform_binding`. Guest checkpoints also expose the mapping at `checkpoint.runtime_report.execution.binding`; their native sensor boundaries remain in `checkpoint.capture_report`. Guest execution and recovery continue through the existing native scope lifecycle. Restarting the same Target with a different saved mapping is rejected. Restore/clone generation assignment belongs to the external trusted launcher, including cases that retain a copied Guest boot ID.

## Fixed Runsc Entry

The supported protocol pin is `release-20261109.0`, upstream commit `a0e6be6fb5e03d8ebea13592f36a097c7e9a41b9`. This is a compatibility pin; live acceptance of this adapter is still required on the deployment host.

```json
{
  "target": {"producer_id":"node-a","instance_id":"sandbox-1","generation":"generation-1"},
  "caller": {"principal_id":"router","producer_id":"source","namespace":"lab"},
  "concurrency": 1,
  "backend": {
    "mode":"runsc",
    "runsc": {
      "binary":"/usr/local/bin/runsc",
      "root":"/run/runsc",
      "container_id":"container-1",
      "state_created":"2026-11-16T00:00:00Z",
      "runtime_release":"release-20261109.0",
      "workdir":"/workspace",
      "allow_uncorrelated":true
    },
    "seccheck": {
      "status_file":"/run/agentprov/receiver-status.jsonl",
      "target": {
        "run_id":"sentry-container-run",
        "socket_path":"/run/agentprov/events.sock",
        "registration": {
          "namespace":"node-a","instance_id":"sandbox-1","generation":"generation-1",
          "sandbox_id":"sandbox-1","container_id":"container-1","peer_uid":0
        }
      }
    }
  }
}
```

Read `state_created` from the actual `runsc --root=ROOT state CONTAINER` result. It is checked before execution, alongside the container ID, running state and binary version. A trusted launcher must retire the binding before replacing/restoring its container. Paths are absolute; `workdir` is fixed inside the container. Requests must set `command.disable_snapshot=true` and either omit `command.workdir` or use this exact workdir. Host-side snapshots and host path walks are not used for a container workspace.

The entry is fixed to:

```text
runsc --root=ROOT exec --new-pidns --internal-pid-file=PRIVATE_FILE --cwd=WORKDIR CONTAINER ARGV...
```

Requests cannot choose runtime flags, container IDs or receiver identities. Shell interpreters require the existing `--record-allow-shell` policy. The transport uses a minimal host environment. `--record-timeout` and durable stop requests cancel and reap the local transport.

The optional `seccheck` block points to the existing independent receiver. Its registration namespace, instance and generation must equal the execution Target's producer, instance and generation, and the container must match. Start the receiver with its existing trusted collection configuration, redirecting JSON status into the checked file:

```sh
agentprov --data-dir /var/lib/agentprov-sentry telemetry receive-seccheck \
  --config /run/agentprov/receiver.json --json --status-interval 100ms \
  > /run/agentprov/receiver-status.jsonl
agentprov --data-dir /var/lib/agentprov-executor daemon serve \
  --execution-config /run/agentprov/execution.json --record-timeout 30s
```

Run these in separate root-managed processes. The receiver must be connected before a command is executed. A missing, stale, disconnected or mismatched configured receiver fails command admission. Omitting it is an explicit execution-only configuration with `receiver_not_configured`. The mandatory `allow_uncorrelated=true` acknowledges the remaining operation-to-Sentry association gap.

Only the selected receiver target is retained in checkpoint status snapshots. `node_spool` is omitted. Collector ID, connection ID, accepted-record/loss/identity-gap counters describe the container receiver boundary, not a per-command event count. Receiver restart, reconnect and loss changes remain explicit gaps.

## Results And Recovery

The original `/v1/executions` admission, query and stop APIs are unchanged. Read `checkpoint.runtime_report.execution` and `.capture` for the adapter receipt. Query and duplicate admission never invoke `runsc exec` again.

- Successful runsc transport completion with its internal PID receipt records execution success.
- A failure before dispatch records failure. Nonzero runsc completion after dispatch stays unknown because the CLI shares its failure channel with runtime/control errors.
- Timeout, cancellation, lost result or executor restart keeps an unresolved workload result unknown. Its exit code is absent.
- An unresolved attempt fences further executions for that Target in the durable ledger, including after restart. Retire the old workload and assign a new generation through the trusted launcher before continuing.
- `concurrency=1` serializes this executor. External container executions remain explicitly untracked; no global container lock or shared task identity is claimed.

## Identity Evidence

The pinned [`exec` implementation](https://github.com/google/gvisor/blob/a0e6be6fb5e03d8ebea13592f36a097c7e9a41b9/runsc/cmd/exec.go#L189) writes the returned internal PID but not the task's birth timestamp. The pinned [process creation path](https://github.com/google/gvisor/blob/a0e6be6fb5e03d8ebea13592f36a097c7e9a41b9/pkg/sentry/kernel/kernel.go#L1523) returns its root-namespace thread-group ID. [SecCheck ContextData](https://github.com/google/gvisor/blob/a0e6be6fb5e03d8ebea13592f36a097c7e9a41b9/pkg/sentry/seccheck/points/common.proto#L78) separately carries thread/group birth times and an exec-session flag.

There is no atomic call-plus-birth receipt in this integration. The adapter never substitutes a host PID, rounded `ps` time, argv, or arrival-time match for that missing identity. Even a single same-PID sample remains a candidate until PID reuse, late evidence, reconnect and lifecycle binding have been resolved by a stronger contract.

## Validation Commands

Local regression and Linux build:

```sh
go test ./internal/runtimeadapter ./internal/handoff ./internal/record ./internal/daemon
go test ./internal/cli -run 'TestExecutionBackend|TestExecutionCapture|TestRecord|TestDaemon'
go test -race ./internal/runtimeadapter ./internal/handoff
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/agentprov ./cmd/agentprov-sensor
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o /tmp/runtimeadapter-amd64.test ./internal/runtimeadapter
```

On an isolated Linux x86 host, provision the pinned root-owned runsc binary and a disposable rootfs containing `/bin/true` and `/bin/sleep`. Run the opt-in probe as root, with a short trusted output path for the Unix socket:

```sh
AGENTPROV_TEST_RUNSC=/usr/local/bin/runsc \
AGENTPROV_TEST_GVISOR_ROOTFS=/opt/agentprov-test/rootfs \
AGENTPROV_TEST_RUNTIME_ADAPTER_OUTPUT=/root/ap-r02 \
go test ./internal/runtimeadapter -run '^TestRunscLiveExecutionIdentityEvidence$' -count=1 -v
```

The probe creates and removes its own container and keeps artifacts under a new `run-*` output directory. It records `runtime-state.json`, successful/cancelled operation receipts, `acceptance-boundary.json`, and `sentry-identity-records.json`. Identity samples retain exact protobuf `time_ns`, thread ID/birth, group ID/birth, container ID, parent group ID and `is_exec_session`, plus registration, connection, sequence, packet digest/header and loss delta. Protobuf 64-bit values are encoded as decimal strings, without float conversion. Credentials, argv and environment are excluded. Transport peer PID is labelled separately.

This probe checks the real runtime entry and receiver identity fields. Complete integration acceptance additionally runs the existing authenticated handoff API against the configured daemon, verifies duplicate/query/no-reexecution and generation rejection, exercises receiver restart/disconnect and executor restart, and collects the command and container-run evidence separately. For native/Guest capture, retain the existing live tests:

```sh
AGENTPROV_TEST_EXECUTION_CAPTURE=1 go test ./internal/handoff -run '^TestLiveExecutorSealsNativeCapture$' -count=1 -v
AGENTPROV_TEST_REQUIRE_CGROUP=1 go test ./internal/handoff -run '^TestExecutorRecoversLiveScope$' -count=1 -v
```

Record the commit, architecture, runsc digest, kernel/rootfs versions, configuration hashes and acceptance artifacts. The real x86 run, complete R-02 fault matrix and Kata/QEMU platform acceptance remain pending until those artifacts are collected.
