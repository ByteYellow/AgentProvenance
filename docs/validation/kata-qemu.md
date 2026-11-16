# Kata/QEMU x86 Acceptance

[简体中文](../zh-CN/validation/kata-qemu.md)

This is the R-03/Q-01 portable acceptance fixture for **Kubernetes +
`kata-qemu-runtime-rs` on Linux x86_64**. The runner uses the existing Guest
executor, native Sensor, execution handoff and signed delivery protocol. Run it
on the selected Kubernetes node, against a dedicated, already authorized test
namespace. The ARM development VM has no `/dev/kvm`; hardware rows start at
`PENDING`.

## Version Lock

The [lock template](../../scripts/acceptance/kata-qemu/versions.lock.json) accepts
the **measured, installed runtime-rs/QEMU combination**. Active versions and hashes
are unset until the operator inventories it. `candidate_reference` records the
research baseline: Kata **4.3.1**, upstream commit
`03cf2ec06a5d302f23af811744f6bcea49988bfb`, QEMU **11.0.1**, and guest kernel
**6.18.56**. That reference does not require reinstalling an existing deployment.
The profile follows the official [RuntimeClass guide](https://kata-containers.github.io/kata-containers/kata-deploy-runtimeclasses/)
and [version manifest at the pinned revision](https://github.com/kata-containers/kata-containers/blob/03cf2ec06a5d302f23af811744f6bcea49988bfb/versions.yaml).

Copy the template to a private `versions.local.json` and fill every missing
required value. The runner never fetches a release, automatically approves live
artifact hashes, or selects `latest`. All versions, paths and hashes must describe
one reviewed combination. Other installed versions and custom BTF-enabled guest
builds are accepted when their exact pins and the required CRI, QEMU and Guest
capability checks match. The fixed profile remains `kata-qemu-runtime-rs` with QEMU.

| Lock Field | Required Evidence |
| --- | --- |
| `artifacts.kata` | Runtime-rs shim version, upstream revision, installed path and SHA-256 |
| `artifacts.qemu` | QEMU version, installed path and SHA-256 |
| `artifacts.guest_kernel` | Kernel version, exact `uname -r`, boot image SHA-256, SHA-256 of guest `/sys/kernel/btf/vmlinux` |
| `artifacts.guest_image` | Exact guest image build label, installed path and SHA-256 |
| `artifacts.kata_config` | Installed runtime-rs QEMU TOML path, version and SHA-256 |
| `sensor` | Embedded Sensor/CLI build version, full source commit and executable SHA-256 |
| `kubernetes` / `containerd` | Exact API server, kubelet and running CRI versions |
| `workload_image` | Preloaded test container image with immutable `@sha256:` reference |
| `verifier` | When `--verifier` is supplied: standalone verifier version, full source commit and executable SHA-256 |

Use `sha256sum FILE` on the reviewed artifacts. Obtain the BTF digest and exact
kernel release from the matching guest build or an operator-owned inspection
session. Supply release build metadata for `internal/buildinfo.Version` and
`internal/buildinfo.Commit`; the live Sensor producer must match the lock. The
collector is embedded in `agentprov`, so its executable digest is the CLI digest.
There is no second raw Sensor process in this profile.

The test container image must already contain Python 3.11+, `bpftool`, `sleep`,
`true`, and the dynamic loader/libraries required by the selected `agentprov`
binary. The Pod uses `imagePullPolicy: Never`. Image construction and host/guest
provisioning remain explicit operator steps.

## Prerequisites

- Root access on the selected node, Python 3.11+, `kubectl`, `crictl`, Git, and the exact Linux amd64 `agentprov` binary.
- Accessible `/dev/kvm`, a working Kubernetes API context, and an explicit local containerd CRI socket.
- An existing `kata-qemu-runtime-rs` RuntimeClass and handler with pinned `runtimePath` and `ConfigPath`.
- The selected CRI handler must already set `privileged_without_host_devices=true`.
- A dedicated namespace whose existing admission policy permits this privileged test Pod and three scoped `hostPath` volumes: read-only fixture inputs, read-only binding configuration, and writable evidence.
- Guest BTF, BPF kprobe/tracepoint programs, ring/hash maps, visible tracefs, and writable delegated cgroup v2.

If tracefs is absent from the privileged fixture container, add
`--mount-guest-tracefs`. After checking the actual Pod/container and Guest boot,
the node runner mounts tracefs inside that owned container before publishing its
binding. Each stage records the mount and boot identity. The default remains an
inspection-only prerequisite check; this option does not mount the node's tracefs.

The handler check reads **the running CRI's `info`**, not labels or an arbitrary
configuration file. For each created Pod it also checks CRI `inspectp`
`runtimeHandler` by Pod UID. The node boot ID, node/API versions, runtime binary
version, configuration paths and artifact digests are checked before Pod creation.
These fields follow the pinned [kata-deploy containerd implementation](https://github.com/kata-containers/kata-containers/blob/03cf2ec06a5d302f23af811744f6bcea49988bfb/tools/packaging/kata-deploy/binary/src/runtime/containerd.rs)
and [Kubernetes RuntimeClass contract](https://kubernetes.io/docs/concepts/containers/runtime-class/).

## Platform Binding

The node-side operator creates each Pod, validates its UID and RuntimeClass, and
resolves the running sandbox through CRI. Container inspection must match both
the raw container ID and sandbox ID. An operator `kubectl exec` probe reads the
Guest boot ID; the Pod/container and RuntimeClass are rechecked before publishing
the binding. Node and Guest boot IDs must differ.

The runner then generates `binding-N/execution.json`, signing keys and a
`receipt.json` with schema `agentprovenance.kata_binding_receipt/v1`. These are
root-owned regular files mounted read-only at `/binding`. The receipt records
the API/CRI identities, full executor Target, config/binary/lock hashes and public
key hashes. It is an operator launcher assertion, protected by file ownership
and mount boundaries. Labels are only an additional cleanup guard.

The generated configuration uses the implemented execution backend:

```json
{
  "target": {
    "producer_id": "kata-acceptance-fixture",
    "instance_id": "<observed-pod-uid>",
    "generation": "<fresh-operator-assigned-generation>"
  },
  "backend": {
    "mode": "guest",
    "guest": {
      "runtime_class": "kata-qemu-runtime-rs",
      "runtime_handler": "kata-qemu-runtime-rs",
      "pod_uid": "<observed-pod-uid>",
      "container_id": "<raw-64-hex-cri-container-id>",
      "guest_boot_id": "<observed-guest-boot-uuid>"
    }
  },
  "capture": {"mode": "native", "placement": "guest_kernel"}
}
```

This excerpt omits the generated caller, concurrency and delivery settings.
The Guest checks the trusted receipt before starting the daemon; the daemon
also verifies the actual kernel boot ID. Each checkpoint must preserve the same
binding in `platform_binding` and `runtime_report.execution.binding`. The fixture
checks it again in the signed checkpoint imported into the offline store. Local
tests reject changed Pod/boot identity and Target generation; live checks require
HTTP 403 for a mismatched Target instance or generation and the previous Pod's
Target after rebuilding. Generation is assigned independently of the Pod UID.

## Commands

Run from the repository root. Both data and output paths must be fresh and
separate. `preflight` does not create the data directory. The source checkout is
required so reused fixture bytes and current source SHA can be inventoried.

```sh
python3 scripts/acceptance/kata-qemu/run.py preflight --dry-run \
  --binary /srv/agentprov/agentprov \
  --lock /srv/agentprov/versions.local.json \
  --data-dir /var/tmp/ap-kata-data-001 \
  --output /var/tmp/ap-kata-plan-001 \
  --context lab-x86 --namespace agentprov-acceptance --node x86-01 \
  --cri-endpoint unix:///run/containerd/containerd.sock
```

Dry-run only hashes local inputs and writes `pod-plan.json`, a reference
RuntimeClass document, the lock copy and `report.json`. It does not execute the
binary, contact Kubernetes/CRI, or inspect KVM. A complete lock produces
`PENDING`; missing pins produce `BLOCKED` with a field list. Neither path marks
a hardware row as passed.

Remove `--dry-run`, choose a new output path and run `preflight` for real node
checks. Then execute the bounded fixture with explicit privileged-Pod consent:

```sh
sudo python3 scripts/acceptance/kata-qemu/run.py run \
  --binary /srv/agentprov/agentprov \
  --lock /srv/agentprov/versions.local.json \
  --data-dir /var/tmp/ap-kata-data-001 \
  --output /var/tmp/ap-kata-run-001 \
  --context lab-x86 --namespace agentprov-acceptance --node x86-01 \
  --cri-endpoint unix:///run/containerd/containerd.sock \
  --allow-privileged-guest
```

Ensure that this user has the intended kubeconfig/context. The runner never
prints kubeconfig or requests Secrets. The generated RuntimeClass JSON is a
review reference only; the runner does not apply it.

## Executed Checks

| Step | Evidence Required for `PASS` |
| --- | --- |
| Guest preflight | Exact kernel/BTF, `bpftool feature probe kernel`, required kernel config, tracepoints, namespaces, capabilities and owned writable cgroup parent |
| Single command | Existing `accept_execution_delivery.py`: synthetic CSV result, signed transfer, receipt retry, native sealed scope, graph and artifact body |
| Concurrent isolation | Existing `accept_execution_handoff.py`: source/scope/native-file isolation and idempotency; additional distinct marker outputs and artifacts in separate cgroups |
| Recovery | SIGKILL only the fixture daemon, restart its embedded collector, retain `unknown` output and `incomplete` capture, replay the same admission, then explicitly retry with `previous_attempt_id` |
| Platform identity | API/CRI binding receipt, actual `backend.guest`, both checkpoint projections, mismatched Pod/generation rejection and signed imported checkpoint |
| Offline handoff | Stop the fixture daemon, `seal-executions`, retain packages, move the source store, import with an operator-selected public key into a fresh store, verify graph, output and platform binding |
| Pod rebuild | Delete the first owned Pod, recreate the same name, compare new UID/container IDs/guest boot ID, reject the old Target with HTTP 403 |
| Optional reader verification | Signed `--delivery derived` export; independent verifier accepts recipient trust, rejects an unknown key, wrong role and tampered reader |

The single-command fixture adds a recorded two-second sleep before the existing
CSV task so native process-state sampling has an observation window. The reused
script on disk is unchanged; `delivery_task_prelude` records this invocation detail.

Guest checks have a 600-second deadline; each Pod has a 720-second active
deadline. Node waits, CRI calls and cleanup are bounded. Processes are addressed
by handles created by this invocation. Pod deletion uses a label/UID ownership
check followed by an atomic UID deletion precondition. No broad selectors,
`pkill`, namespace deletion, host service restart, mount, sysctl, policy reload,
RuntimeClass update or software installation occurs.

To include reader verification, add `--verifier /srv/agentprov/agentprov-verify`
and complete `lock.verifier`. The fixture exports the independently imported run
with `dashboard export --delivery derived --sign-key KEY --exporter-id ID`, then
runs `agentprov-verify --trust-policy FILE ZIP`. The recipient policy is supplied
separately from the archive and authorizes the `exporter` role. Omitting this
option leaves `derived_verifier` pending.

## Optional Workspace Case

Add `--workspace-case contract --verifier /srv/agentprov/agentprov-verify` to the
same node command to exercise the existing `scripts/accept_workspace.py` stdio
MCP fixture in the **second, rebuilt Guest**. The default two-boot profile is
unchanged when this option is omitted; `--workspace-case` alone selects `contract`.
Complete `lock.verifier` and set
`lock.workspace.mcp_version` to the exact MCP package version already installed
in the workload image. The runner copies and hashes the existing Python MCP
bridge and SDK modules; it does not install dependencies.

The fixture uses the same operator-authorized Target as `execution.json`, from
the read-only `/binding/workspace-target.json`. Each workspace keeps a private
copy for stale-generation rejection tests; the operator file is never edited.
Read, Edit, Write and Bash operate on one remote-authoritative root per case.
Input/output revisions, manifests and the actual record attempt are checked
again from content-addressed workspace evidence, including after signed import.

The existing handoff collector is stopped before workspace capture starts. The
workspace fixture runs `sensor stream --placement guest_kernel` against its own
store, waits for attached required probes, and stops/drains that collector before
export. The same run and record attempt must have native exec/file observations
in its nonzero owned cgroup. Accepted correlation methods are
`cgroup_time_window:*` and `kernel_process_instance:*`; every selected event's
cgroup must equal that scope. Scope-only events retain their empty tool ID and
are reported as `owned_record_cgroup`, not upgraded to tool-level attribution.
Sensor build/placement/Guest boot and collector lifetime are checked against
the lock and operator binding. Missing prerequisites remain `BLOCKED`/exit 2.

After the MCP fixture, the runner uses the existing signed `forensics export`
and pinned-public-key import into a fresh store, compares imported workspace
and native-event evidence, then runs the signed derived-reader export and
independent verifier. Results and packages are retained under
`boot-2/workspace/{contract,harness}-delivery/`; `kata-workspace.json` records the
case, target and verification results.

`contract` is a real CLI/MCP contract test without a model provider. Its success
records the contract result while leaving the full `workspace_case` matrix row
`PENDING`. For the real Harness case, select `--workspace-case harness` and set
`lock.workspace.harness.path` and `.sha256` to an **existing authenticated Claude
entrypoint inside the Guest container**. The same fixture uses its existing
`--claude` path and verifies actual controlled MCP tool calls. Authentication
must already be available there through the operator's deployment. Never put
credentials in the image, lock, entrypoint script, Pod plan or evidence. The
runner does not copy credential files, add Secret mounts, log in, or forward
provider credentials through MCP tool arguments. Missing entrypoints are
reported rather than provisioned. Harness logs remain private and are redacted.

Only a successful native Guest Harness case plus verified signed delivery sets
`workspace_case=PASS`. Local Sensor-off CLI/MCP runs, dry-runs and contract-only
mode keep that row pending. The existing 600-second Guest flow, 690-second node
stage and 720-second Pod deadlines still apply; the optional case shares that
budget. Its own subprocess bound is 150 seconds for contract mode and 400
seconds with the existing bounded Harness run. No UI integration is required.

## Results and Privacy

`report.json` records current source SHA/dirty state, binary and fixture hashes,
the lock digest, node/runtime identity, per-boot results and the release matrix.
`data-dir/assets` contains the exact inputs copied into the Pod.
`data-dir/binding-N` retains the root-owned configuration, receipt and keys. Each
`data-dir/boot-N` retains reports, redacted daemon logs, execution/capture data,
signed packages, public keys, receiver/offline stores and an artifact digest index.
No evidence directory is deleted, including after a failed Pod.

Private output permissions are enforced with umask `077`. Synthetic fixture keys
and the daemon token stay in the private data directory and are excluded from
the digest index. Known tokens, bearer headers, credential assignments and URL
passwords are removed from emitted diagnostics and daemon logs. Review paths,
raw evidence and attachments before sharing; do not publish the entire data tree.
The portable single-command package is under `boot-N/portable/`. Its public key
must reach the recipient through a trusted channel.

Local internal evidence belongs under the ignored
`scripts/acceptance/kata-qemu/.local/` or outside the repository. Only scripts,
the unfilled template and these bilingual docs belong in a public change.

## Acceptance Status

This fixture starts native execution inside a privileged **container in the Kata
Guest**, with the Sensor observing that Guest kernel. It records container
namespaces explicitly. Ordinary unprivileged application-container deployment
and guest-wide collection beyond this fixture require their own deployment and
capture validation.

The local configuration and rejection contracts are executable without KVM.
Live R-03 acceptance is **x86 `PENDING`** until the hardware run completes.
`runtimeadapter_binding` is an implemented live assertion, with no unconditional
integration block. A successful two-boot run sets `r03_status=PASS`; Q-01 and the
overall report remain `PENDING` while the remaining release rows are open.

Exit **2** means a required pin, capability, permission or binding is missing or
mismatched. Exit **1** means a test/runtime failure. Exit **0** means the requested
phase completed; inspect `r03_status`, `q01_status` and the matrix for its scope.
Dry-run and node-only preflight leave all hardware acceptance rows pending.

Q-01 additionally retains `PENDING` rows for late evidence, forced retirement,
supported restore/clone, 24-hour soak, compatibility and Browser scenarios. The
workspace row stays pending unless the optional native Harness case completes.
Recovery here restarts the collector together
with its owning daemon. Final packages for other attempts remain retained until
their receipts are reconciled; the fixture never authorizes evidence reclamation.

## Local Validation

```sh
python3 -B -m unittest discover -s scripts/acceptance/kata-qemu -p 'test_*.py' -v
python3 -m compileall -q scripts/acceptance/kata-qemu
go test ./scripts/acceptance/kata-qemu
```

Tests cover missing pins, measured versions, handler/config mismatches, immutable
Pod ownership, operator receipts, binding rejection and both checkpoint
projections, bounded cleanup, redaction, unknown/incomplete recovery and
side-effect-free dry-run. The Go tests feed the Python-generated configuration
into the production handoff decoder and runtimeadapter validators.
A separate local run of `scripts/accept_execution_seal.py` without
`--native` can validate the real CLI/receipt/offline contract on macOS; keep its
results separate from Kata hardware acceptance. See the existing
[execution handoff guide](../execution-handoff.md) for the reused protocol.

An existing imported run can also exercise the real export/verifier contract
without Kubernetes:

```sh
python3 scripts/acceptance/kata-qemu/reader.py \
  --binary /srv/agentprov/agentprov --verifier /srv/agentprov/agentprov-verify \
  --data-dir /srv/agentprov/imported-store --run RUN_ID \
  --output /var/tmp/ap-reader-contract-001
```
