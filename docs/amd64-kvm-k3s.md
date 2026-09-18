# Linux amd64, KVM guest and K3s

This adaptation adds **x86-64 / Go amd64**, with a separate native eBPF object.
It preserves the previously validated ARM64 object byte-for-byte. 32-bit x86,
Firecracker guest-init and transparent observation across a VM boundary are not
part of this deployment. The sensor runs **inside the guest kernel**. Ordinary
KVM guests use the existing `local-record` profile; `microvm-guest-init` remains
planned.

## What changed

- Build selection uses architecture and OS, rather than endianness alone.
  `sensorbpf_x86_bpfel.*` implements amd64; `sensorbpf_arm64_bpfel.*` preserves ARM64.
- C/OpenSSL uprobes read System V argument registers. The amd64 Go TLS entry
  probe separately reads AX/BX/CX for Go ABIInternal. No Go return probe is used.
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
  rather than relying on process or Pod liveness.

## Validated environments

The checked reports in [benchmarks/amd64-kvm-k3s](benchmarks/amd64-kvm-k3s)
record the actual kernel, architecture and individual assertions. The new
GitHub Actions job repeats the amd64 live sensor gate; hosted CI has not yet
been run for this local branch.

| Environment | Validation |
| --- | --- |
| Windows / WSL2, Ubuntu 26.04, kernel `6.18.33.2-microsoft-standard-WSL2` | Native amd64 syscalls, C/OpenSSL and Go TLS, delayed draining |
| QEMU 10.2.1 with KVM acceleration, Ubuntu 24.04 guest, kernel `6.8.0-139-generic` | Same live sensor gate, systemd capture, scoped ingestion, graph verification and export/import |
| Guest K3s `v1.36.4+k3s1`, containerd `2.3.4` | Eight workloads through one sensor DaemonSet, local/Pod parity, informer restart/delete lifecycle, continuous Pod attribution |

The live sensor gate checks exec, file open/write, sensitive reads, rename,
unlink, process exit, IPv4 connect, glibc DNS, UDP/sendto DNS, same-identity
setuid/setgid calls, an invalid ptrace request, OpenSSL legacy and `_ex`
request/response bodies, Go TLS request bodies, and capture time under a paused
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

Restart the service after changing these paths. A uprobe observes the specified
library/binary inode; a container with its own copy requires a path to that
copy, such as `/proc/<host-pid>/root/...`, and reattachment when it changes.
Automatic discovery of every container TLS library is not implemented. Go TLS
capture remains request/write only; stripped Go, BoringSSL and other TLS stacks
are not newly claimed as covered.

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
activity can precede informer binding; this adaptation does not add an event
reconciliation queue. The continuous acceptance waits for a real binding before
stimulating its assertions.

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
