# Linux amd64, KVM guest and K3s

English | [中文](zh-CN/amd64-kvm-k3s.md)

AgentProvenance supports **Linux x86-64 / Go amd64 and ARM64**, with separate
native eBPF objects. Validated deployment paths include local Linux, a KVM
guest, and K3s Pods inside that guest. The sensor runs **inside the guest
kernel**; KVM capture uses the existing `local-record` profile and the same
evidence model as local capture. This is not host-side inspection across a VM
boundary or a VM lifecycle manager. The amd64 addition preserves the existing
ARM64 object byte-for-byte.

## What changed

- Build selection uses architecture and OS, rather than endianness alone.
  `sensorbpf_x86_bpfel.*` implements amd64; `sensorbpf_arm64_bpfel.*` preserves ARM64.
- C/OpenSSL uprobes read System V argument registers. The amd64 Go TLS entry
  probe separately reads AX/BX/CX for Go ABIInternal. Go TLS Read uses ordinary
  uprobes at decoded RET instructions, paired by goroutine and stack frame;
  it does not use a Go uretprobe or modify Go return addresses.
- x86 legacy `open` and `unlink` supplement `openat` and `unlinkat`.
- New amd64 event records carry the kernel monotonic capture timestamp, converted
  to wall time during normalization. Queueing does not retimestamp old events
  into a later workload window. This conversion assumes a consistent wall clock
  while the events are queued; it is not a distributed clock synchronization protocol.
- `record` publishes its cgroup binding before launching a workload. Failed
  scope publication prevents an unattributable launch.
- Correlation parses identity-matched timestamps into actual instants. This
  handles Kubernetes whole-second timestamps, mixed fractional precision and
  timezone offsets without changing stored evidence strings. Identity indexes
  keep the candidate lookup scoped; time comparisons retain nanosecond precision.
- The parity gate uses the root record binding for the complete workload
  window instead of accidentally selecting a short descendant window.
- Readiness is emitted after attachment. Live acceptance waits for that signal,
  rather than relying on process or Pod liveness. Optional failures appear in
  the per-probe capability report; readiness promises only required probes.
- The native stream persists bounded batches before asynchronous ingestion,
  retries late bindings at capture time, and recovers interrupted batches.
  See [native capture persistence](native-capture-spool.md) for guarantees and limits.
- An amd64 kernel map retains up to 16,384 cgroup identities at capture time,
  including up to three ancestor names. Userspace can resolve a short-lived Pod
  after both its process and cgroup directory have disappeared.

## Validated environments

The checked reports in [benchmarks/amd64-kvm-k3s](benchmarks/amd64-kvm-k3s)
record the actual kernel, architecture and individual assertions. The
[CI workflow](../.github/workflows/ci.yml) repeats the amd64 live sensor gate
with Go 1.23 through 1.26 and uploads its own reports. Lab reports and hosted CI
are separate evidence: consult the report for its environment and revision.

| Environment | Validation |
| --- | --- |
| Windows / WSL2, Ubuntu 26.04, kernel `6.18.33.2-microsoft-standard-WSL2` | Native amd64 syscalls, C/OpenSSL and Go TLS, delayed draining |
| QEMU 10.2.1 with KVM acceleration, Ubuntu 24.04 guest, kernel `6.8.0-139-generic` | Same live sensor gate, systemd capture, scoped ingestion, graph verification and export/import |
| Guest K3s `v1.36.4+k3s1`, containerd `2.3.4` | Eight workloads through one sensor DaemonSet, local/Pod parity, informer restart/delete lifecycle, continuous Pod attribution |

The live sensor gate checks exec, file open/write, sensitive reads, rename,
unlink, process exit, IPv4 connect, glibc DNS, UDP/sendto DNS, same-identity
setuid/setgid calls, an invalid ptrace request, OpenSSL legacy and `_ex`
request/response bodies, Go TLS request/response bodies, and capture time under a paused
drain. Privilege tests prove observation of **attempts**, not successful privilege
escalation. The fixtures use loopback services and synthetic text without API keys.

## Build and regenerate

Run on Linux amd64 with Go 1.23 or newer. Building committed objects needs no
Clang or kernel headers:

```sh
mkdir -p bin
CGO_ENABLED=0 go build -o bin/agentprov ./cmd/agentprov
CGO_ENABLED=0 go build -o bin/agentprov-sensor ./cmd/agentprov-sensor
```

Regeneration requires matching native Linux BTF, Clang/LLVM, bpftool and
libbpf headers. For Ubuntu:

```sh
sudo apt-get install clang llvm libbpf-dev linux-tools-common linux-tools-generic
scripts/regen-sensor.sh
scripts/regen-sensor.sh --check
```

On distributions with a standalone package, install `bpftool` instead of
`linux-tools-*`. `BPFTOOL` and `VMLINUX_BTF` can point to the matching tool and
BTF. The script selects only the native architecture and never regenerates the
other architecture. `--check` compares generated Go bindings; it does not claim
byte-for-byte `.o` reproducibility across kernels or compiler versions.

## Install inside a KVM guest

Use a BTF-enabled Linux kernel, writable cgroup v2 and root for collection.
Copy the static binaries and repository into the guest, then run there:

```sh
sudo env AGENTPROV="$PWD/bin/agentprov" SENSOR="$PWD/bin/agentprov-sensor" \
  scripts/install-kvm-guest.sh
sudo agentprov --data-dir /var/lib/agentprov record --run demo-kvm -- sh -c 'id; echo hello > demo.txt'
sudo python3 scripts/accept_kvm_guest.py --report /tmp/kvm-acceptance.json
```

The installer enables `agentprov-sensor.service`, stores evidence under
`/var/lib/agentprov`, and checks that its probes attached. `record` must use the
same data directory. Stop the collector with `systemctl stop agentprov-sensor`;
it detaches eBPF and closes ingestion through SIGINT. Data persists across a
guest reboot. The service does not reconstruct events that occurred while it
was stopped.

Optional `/etc/default/agentprov-sensor` settings:

```sh
AGENTPROV_SSL_LIB=/usr/lib/x86_64-linux-gnu/libssl.so.3
AGENTPROV_LIBC_LIB=/usr/lib/x86_64-linux-gnu/libc.so.6
AGENTPROV_GO_TLS_BIN=/absolute/path/to/unstripped-go-agent
```

Restart the service after changing explicit paths. Native collection also enables
automatic TLS discovery by default: it scans visible process mappings and
container roots, attaches OpenSSL and unstripped Go targets, and reconciles
replacement or departed targets. `sensor stream --auto-tls=false` disables it.
Discovery has bounded process/target budgets and reports attachment failures.
Observed process starts also wake a coalesced, rate-limited discovery scan.
For supported overlay mounts, discovery resolves the backing inode so containers
sharing one library receive one attachment. Unresolvable or unsupported overlay
layouts report a coverage limitation rather than installing duplicate probes.

Go response capture is limited to amd64 Go ABIInternal 1.23–1.26 with symbols;
unsupported versions and stripped binaries report degraded coverage. Automatic
discovery does not guarantee a first request before attachment, nor coverage for
a process that starts and exits between discovery passes. BoringSSL, arbitrary
static/custom TLS stacks and encrypted traffic without a supported plaintext
probe are not claimed as covered.

The concurrent Read fixture has been run with Go 1.23.12, 1.24.0, 1.25.0 and 1.26 on WSL,
including goroutine stack growth, exact returned bytes, and context cleanup.
The CI live Go TLS matrix covers the same four minor versions; its result and
artifacts are attached to each pull request's checks.

Inspect the actual live capabilities and queue state with:

```sh
sudo agentprov --data-dir /var/lib/agentprov sensor status --json
```

The report lists individual syscall/DNS/TLS paths and degradation reasons, along
with collector liveness. A historical capability file does not prove the sensor
is still running. TLS reassembly also bounds pending bytes and stream counts;
truncation, kernel loss and reassembly eviction are recorded as coverage gaps.

## K3s inside the guest

Install K3s using its official installer or air-gap procedure. This lab uses the
pinned version above and its matching air-gap image bundle. AgentProvenance
requires node BTF, tracefs, cgroup v2 and root/privileged attachment. K3s uses the
guest kernel, so the in-guest sensor can observe its Pods.

For continuous ingestion, combine the systemd collector above with the existing
node attribution controller. Docker is used only to build the scratch controller
image; K3s runs it through its own containerd:

```sh
sudo env AGENTPROV="$PWD/bin/agentprov" scripts/install-k3s-guest.sh
sudo k3s kubectl annotate pod MY_POD agentprov.io/run=MY_RUN
sudo agentprov --data-dir /var/lib/agentprov telemetry list --run MY_RUN --json
sudo python3 scripts/accept_k3s_guest.py --report /tmp/k3s-continuous.json
```

The controller shares `/var/lib/agentprov` with the host service, resolves host
cgroup identity, and closes bindings on container/Pod lifecycle changes. Its
passive attribution remains `k8s_cgroup` with confidence 0.8. Very early Pod
activity is retained in the native spool pending a binding (default two minutes).
Terminated, previous-attempt, init and ephemeral containers can establish closed
historical intervals. When the host cgroup is gone, the runtime container ID can
still join kernel-captured evidence. Kubernetes timestamps are often whole
seconds: a closed interval conservatively includes the reported finishing second.
This is passive attribution, not a claim of nanosecond-accurate termination time.

`accept_node_capture.py` specifically starts immediate-exit Pods **before** the
informer, verifies the target events reached disk, kills the collector, and then
requires late closed-window attribution, graph verification and a second restart
without duplicate events. The older continuous gate still checks live bindings.

Alternatively, the existing `deploy/k8s/agentprov-sensor-daemonset.yaml` emits
raw JSONL for an external receiver. It does not itself ingest into the database.
The multi-workload test independently deploys this actual DaemonSet. Avoid two
ingesting collectors writing duplicate observations into the same store.

```sh
sudo env AGENTPROV="$PWD/bin/agentprov" SENSOR="$PWD/bin/agentprov-sensor" \
  scripts/accept_k8s_node_multiworkload.sh
sudo env AGENTPROV="$PWD/bin/agentprov" SENSOR="$PWD/bin/agentprov-sensor" \
  scripts/accept_k8s_pod_parity.sh
sudo env AGENTPROV="$PWD/bin/agentprov" scripts/accept_k8s_informer_controller.sh
```

Set `IMAGE` to a locally available BusyBox image when Docker Hub is unavailable;
the K3s air-gap bundle used here includes
`docker.io/rancher/mirrored-library-busybox:1.37.0`. The Python K3s gate accepts
`--image`. The shell gates use separate temporary test resources and clean up.

## Reproduce the amd64 ABI gate

```sh
sudo apt-get install gcc libssl-dev openssl python3
CGO_ENABLED=0 go build -o bin/tls-go-client ./internal/sensor/testdata/tls_client.go
gcc -O2 internal/sensor/testdata/tls_client.c -lssl -lcrypto -o bin/tls-c-client
sudo python3 scripts/accept_sensor_live.py \
  --sensor "$PWD/bin/agentprov-sensor" \
  --go-client "$PWD/bin/tls-go-client" --c-client "$PWD/bin/tls-c-client" \
  --ssl-lib /usr/lib/x86_64-linux-gnu/libssl.so.3 \
  --pause-drain 1.5 --report /tmp/sensor-live.json
```

The JSON report lists assertions; the adjacent `.events.jsonl` retains only the
fixture processes. The gate intentionally pauses the sensor userspace while
kernel probes continue, then resumes after clients exit. Existing ARM64 runtime
validation was not repeated for this task.

## Reproduce native recovery and container TLS gates

Run these on an isolated K3s test node with Docker available for fixture image
building. The scripts use temporary stores and unique test Pods; TLS traffic
stays on the node and uses synthetic markers.

```sh
sudo python3 scripts/accept_node_capture.py \
  --agentprov "$PWD/bin/agentprov" --report /tmp/node-capture.json
sudo python3 scripts/accept_container_tls.py \
  --sensor "$PWD/bin/agentprov-sensor" \
  --go-client "$PWD/bin/tls-go-client" --c-client "$PWD/bin/tls-c-client" \
  --report /tmp/container-tls.json
sudo env PATH="$PATH" AGENTPROV_LIVE_GOTLS=1 \
  go test ./internal/sensor -run '^TestLiveGoTLSReadConcurrentStackGrowth$' -v
```

The container TLS gate supplies no explicit sensor TLS target paths. It recreates
Pods containing Go, legacy OpenSSL and OpenSSL `_ex` clients, checks request and
response bodies in both generations, and rejects duplicate captured messages.
Those clients intentionally wait six seconds for discovery; the separate instant
Pod gate proves late syscall attribution, not zero-gap TLS attachment.

## Daemon readiness and storage faults

`GET /v1/live` reports that the HTTP process can respond. `GET /v1/ready` and
`GET /v1/health` check the database and schema, with a two-second check deadline.
Database errors, missing required tables and incompatible schemas return 503;
unknown queue counts stay null. These three GET endpoints remain accessible
without the optional API bearer token.

Query availability is distinct from evidence coverage. Historical loss produces
`status: degraded`, `coverage_status: gaps_recorded` and `ready: true` with HTTP
200 when the database is usable. Pending correlation is reported separately.
This readiness check is not proof that every background worker is progressing;
inspect sensor liveness, capabilities and backlog as well.

Run the real HTTP fault gate against its own temporary store:

```sh
python3 scripts/accept_daemon_readiness.py \
  --agentprov "$PWD/bin/agentprov" --report /tmp/daemon-readiness.json
```

Falco import and its legacy worker remain compatibility paths. Shared ingestion
now commits each event and its evidence atomically, but Falco-specific worker
restart recovery is unchanged. The native spool guarantees above apply to
`sensor stream`. Native capture is the primary path for this deployment.
