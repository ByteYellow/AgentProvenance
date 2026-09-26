# Linux amd64、KVM 虚拟机与 K3s

[English](../amd64-kvm-k3s.md) | 中文

AgentProvenance 支持 Linux x86-64（Go 中称为 `amd64`）和 ARM64，两种架构分别使用原生 eBPF 对象。已验收的部署方式包括本机 Linux、KVM 虚拟机，以及虚拟机中的 K3s Pod。

传感器运行在**虚拟机内部的内核**中。KVM 采集复用 `local-record` 配置和本机采集的证据模型，不跨虚拟机边界从宿主机检查来宾，也不管理虚拟机生命周期。新增 amd64 支持时，原 ARM64 对象的字节内容保持不变。

## 适配内容

- 按操作系统和 CPU 架构选择构建文件，不再仅按字节序区分。amd64 使用 `sensorbpf_x86_bpfel.*`，ARM64 保留 `sensorbpf_arm64_bpfel.*`。
- C 和 OpenSSL 用户态探针读取 System V ABI 的参数寄存器。amd64 Go TLS 入口探针按 Go ABIInternal 单独读取 AX、BX、CX。Go TLS Read 在解码得到的 RET 指令处挂载普通 uprobe，并按 goroutine 和栈帧配对；不使用 Go uretprobe，也不修改 Go 返回地址。
- 为 x86 补充旧式 `open`、`unlink`，与已有的 `openat`、`unlinkat` 配合使用。
- 新的 amd64 事件包含内核单调时钟的采集时间，规范化时再转换为墙上时钟时间。事件排队不会使其时间被改成后续工作负载的时间窗口。转换假定排队期间墙上时钟保持一致，不提供分布式时钟同步。
- `record` 在启动工作负载前发布 cgroup 绑定。如果发布失败，则不启动工作负载，避免执行后无法归属。
- 关联器先按身份查找候选，再将时间字符串解析为实际时刻进行比较，支持 Kubernetes 整秒时间、不同小数秒精度和时区偏移。原始证据字符串不变；身份索引限制候选范围，比较保留纳秒精度。
- 能力对齐验收使用覆盖完整工作负载窗口的根记录绑定，避免误选生命周期较短的子进程绑定。
- 探针挂载后才发出就绪信号，实机验收等待此信号。进程或 Pod 存活不等于探针就绪。可选挂载失败会列入逐项能力报告；就绪只保证必需探针已经挂载。
- 原生事件流先将有界批次写入磁盘，再异步摄入；按采集时刻重试迟到的绑定，并恢复中断批次。保证与限制见[原生采集持久化](native-capture-spool.md)。
- amd64 内核映射在采集时保留最多 16,384 个 cgroup 身份，每个身份包含最多三级祖先名称。即使短命 Pod 的进程和 cgroup 目录都已消失，用户态仍可解析归属。

## 已验收环境

[amd64/KVM/K3s 报告目录](../benchmarks/amd64-kvm-k3s/README.zh-CN.md)记录了实际内核、架构和各项断言。[CI 工作流](../../.github/workflows/ci.yml)使用 Go 1.23 至 1.26 重复运行 amd64 传感器实机验收，并上传报告。实验环境报告与托管 CI 是两组独立证据，具体环境和代码版本以各自报告为准。

| 环境 | 验收内容 |
|---|---|
| Windows / WSL2，Ubuntu 26.04，内核 `6.18.33.2-microsoft-standard-WSL2` | amd64 原生系统调用、C/OpenSSL 与 Go TLS、延迟读取事件 |
| QEMU 10.2.1，启用 KVM 加速；Ubuntu 24.04 虚拟机，内核 `6.8.0-139-generic` | 同一套传感器实机验收、systemd 常驻采集、按范围摄入、图校验、导出与导入 |
| 虚拟机中的 K3s `v1.36.4+k3s1`、containerd `2.3.4` | 一个传感器 DaemonSet 采集八个工作负载；本机与 Pod 能力对齐；informer 重启、删除和持续归属 |

传感器实机验收覆盖进程执行、文件打开与写入、敏感文件读取、重命名、删除、进程退出、IPv4 连接、glibc DNS、UDP/sendto DNS、保持当前身份的 setuid/setgid 调用、无效 ptrace 请求、OpenSSL 旧接口与 `_ex` 接口的请求和响应正文、Go TLS 请求和响应正文，以及暂停读取期间的采集时间。

权限相关用例证明的是能够观察到**操作尝试**，不代表成功提权。测试使用回环服务和合成文本，不使用 API 密钥。

## 构建与重新生成探针

在 Linux amd64 上使用 Go 1.23 或更高版本。直接构建仓库中已提交的对象，不需要 Clang 或内核头文件：

```sh
mkdir -p bin
CGO_ENABLED=0 go build -o bin/agentprov ./cmd/agentprov
CGO_ENABLED=0 go build -o bin/agentprov-sensor ./cmd/agentprov-sensor
```

重新生成对象时，需要匹配当前 Linux 内核的 BTF、Clang/LLVM、bpftool 和 libbpf 头文件。Ubuntu 可执行：

```sh
sudo apt-get install clang llvm libbpf-dev linux-tools-common linux-tools-generic
scripts/regen-sensor.sh
scripts/regen-sensor.sh --check
```

如果发行版单独提供 `bpftool` 包，可安装它来代替 `linux-tools-*`。可通过 `BPFTOOL` 和 `VMLINUX_BTF` 指定工具及匹配的 BTF。脚本只选择本机架构，不会重新生成另一种架构的对象。

`--check` 比较生成的 Go 绑定，不保证不同内核或编译器生成的 `.o` 文件逐字节相同。

## 在 KVM 虚拟机中安装

采集需要启用 BTF 的 Linux 内核、可写的 cgroup v2 和 root 权限。将静态可执行文件及仓库复制到虚拟机后，在虚拟机内运行：

```sh
sudo env AGENTPROV="$PWD/bin/agentprov" SENSOR="$PWD/bin/agentprov-sensor" \
  scripts/install-kvm-guest.sh
sudo agentprov --data-dir /var/lib/agentprov record --run demo-kvm -- sh -c 'id; echo hello > demo.txt'
sudo python3 scripts/accept_kvm_guest.py --report /tmp/kvm-acceptance.json
```

安装器启用 `agentprov-sensor.service`，将证据保存在 `/var/lib/agentprov`，并检查探针是否挂载。`record` 必须使用同一个数据目录。

执行 `systemctl stop agentprov-sensor` 可停止采集器。服务通过 SIGINT 卸载 eBPF 并关闭摄入流程。数据在虚拟机重启后保留，但服务无法补回停止期间发生的事件。

可在 `/etc/default/agentprov-sensor` 中设置以下可选路径：

```sh
AGENTPROV_SSL_LIB=/usr/lib/x86_64-linux-gnu/libssl.so.3
AGENTPROV_LIBC_LIB=/usr/lib/x86_64-linux-gnu/libc.so.6
AGENTPROV_GO_TLS_BIN=/absolute/path/to/unstripped-go-agent
```

修改显式路径后需要重启服务。原生采集默认也启用 TLS 自动发现：扫描可见进程的映射和容器根目录，为 OpenSSL 及保留符号的 Go 程序挂载探针，并处理目标替换与退出。使用 `sensor stream --auto-tls=false` 可关闭自动发现。

发现过程对扫描进程数和目标数设有上限，并报告挂载失败。观测到进程启动时，还会触发经过合并和限流的扫描。对于支持的 overlay 挂载，发现器会解析底层 inode，让共享同一个库的容器共用一次挂载。无法解析或不支持的 overlay 布局会报告覆盖缺口，不重复安装探针。

Go 响应采集目前限于 amd64、Go ABIInternal 1.23–1.26 且保留符号的程序。版本不受支持或符号被剥离时，会报告覆盖降级。自动发现不保证捕获探针挂载前的首次请求，也不保证覆盖在两次扫描之间启动并退出的进程。BoringSSL、任意静态或自定义 TLS 实现，以及没有受支持明文探针的加密流量，不在已声明的覆盖范围内。

并发 Read 用例已在 WSL 上使用 Go 1.23.12、1.24.0、1.25.0 和 1.26 验收，包括 goroutine 栈增长、实际返回字节和上下文清理。CI 的 Go TLS 实机矩阵覆盖相同的四个次版本，结果与产物附在各拉取请求的检查中。

查看当前采集能力和队列状态：

```sh
sudo agentprov --data-dir /var/lib/agentprov sensor status --json
```

报告逐项列出系统调用、DNS、TLS 路径及降级原因，同时报告采集器是否存活。历史能力文件不能证明传感器当前仍在运行。TLS 重组也限制待处理字节数和流数量；截断、内核丢失及重组淘汰会计入覆盖缺口。

## 在虚拟机中使用 K3s

按照 K3s 官方安装器或离线安装流程安装。本实验环境固定使用前文版本及其配套离线镜像包。AgentProvenance 需要节点 BTF、tracefs、cgroup v2，以及 root 或特权挂载权限。K3s 使用虚拟机内核，因此虚拟机内的传感器能够观察 Pod。

持续摄入可以组合前文的 systemd 采集器和现有节点归属控制器。Docker 只用于构建基于 scratch 的控制器镜像；K3s 通过自己的 containerd 运行镜像：

```sh
sudo env AGENTPROV="$PWD/bin/agentprov" scripts/install-k3s-guest.sh
sudo k3s kubectl annotate pod MY_POD agentprov.io/run=MY_RUN
sudo agentprov --data-dir /var/lib/agentprov telemetry list --run MY_RUN --json
sudo python3 scripts/accept_k3s_guest.py --report /tmp/k3s-continuous.json
```

控制器与主机服务共享 `/var/lib/agentprov`，解析主机 cgroup 身份，并在容器或 Pod 生命周期变化时关闭绑定。被动归属仍使用 `k8s_cgroup`，置信度为 0.8。

Pod 启动初期的活动会在原生磁盘队列中等待绑定，默认等待两分钟。已终止容器、上一次启动的容器、init 容器和临时容器都可以建立已结束的历史时间窗口。主机 cgroup 消失后，运行时容器 ID 仍可与内核保存的证据关联。

Kubernetes 时间戳通常只有整秒精度，已关闭的区间会保守地包含报告的结束秒。这是被动归属，不表示终止时间精确到纳秒。

`accept_node_capture.py` 会在 informer 启动前运行立即退出的 Pod，先确认目标事件已落盘，再强制终止采集器。后续检查要求完成迟到的已关闭窗口归属、图校验，并在第二次重启后确认没有重复事件。较早的持续采集验收仍用于检查活动绑定。

也可以使用 `deploy/k8s/agentprov-sensor-daemonset.yaml` 向外部接收器输出原始 JSONL；它本身不写入数据库。多工作负载测试会独立部署这份实际 DaemonSet。不要让两个执行摄入的采集器把同一观测重复写入同一存储。

```sh
sudo env AGENTPROV="$PWD/bin/agentprov" SENSOR="$PWD/bin/agentprov-sensor" \
  scripts/accept_k8s_node_multiworkload.sh
sudo env AGENTPROV="$PWD/bin/agentprov" SENSOR="$PWD/bin/agentprov-sensor" \
  scripts/accept_k8s_pod_parity.sh
sudo env AGENTPROV="$PWD/bin/agentprov" scripts/accept_k8s_informer_controller.sh
```

Docker Hub 不可用时，可将 `IMAGE` 设置为本地已有的 BusyBox 镜像。这里使用的 K3s 离线包包含 `docker.io/rancher/mirrored-library-busybox:1.37.0`。Python K3s 验收脚本接受 `--image` 参数。Shell 验收脚本使用独立临时资源，并负责清理。

## 复现 amd64 ABI 验收

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

JSON 报告列出各项断言；旁边的 `.events.jsonl` 只保留测试进程的事件。验收会有意暂停传感器用户态读取，让内核探针继续运行，并在客户端退出后恢复读取。本次任务没有重跑此前已完成的 ARM64 运行时验收。

## 复现原生恢复与容器 TLS 验收

在隔离的 K3s 测试节点上运行。构建测试镜像需要 Docker。脚本使用临时存储和名称唯一的测试 Pod；TLS 流量留在节点内，正文为合成标记。

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

容器 TLS 验收不显式指定传感器的 TLS 目标路径。它重建包含 Go、旧式 OpenSSL 和 OpenSSL `_ex` 客户端的 Pod，检查重建前后的请求与响应正文，并拒绝重复捕获的消息。

这些客户端会主动等待六秒，让自动发现完成。独立的短命 Pod 用例证明系统调用可以迟到补关联，不证明 TLS 探针可以无间隙挂载。

## 后台服务就绪与存储故障

`GET /v1/live` 表示 HTTP 进程可以响应。`GET /v1/ready` 和 `GET /v1/health` 检查数据库及表结构，检查时限为两秒。数据库错误、缺少必需表或结构不兼容时返回 503；未知队列数量保持 `null`。这三个 GET 接口不要求可选的 API bearer token。

查询可用性与证据覆盖分别报告。数据库可用但存在历史丢失时，HTTP 返回 200，并报告 `status: degraded`、`coverage_status: gaps_recorded` 和 `ready: true`。待关联事件单独报告。就绪检查不证明每个后台工作器都在推进，还应查看传感器存活状态、实际能力和积压。

以下真实 HTTP 故障验收使用自己的临时存储：

```sh
python3 scripts/accept_daemon_readiness.py \
  --agentprov "$PWD/bin/agentprov" --report /tmp/daemon-readiness.json
```

Falco 导入及旧版工作器保留为兼容路径。共享摄入现在会原子提交每个事件及其证据，但 Falco 工作器的重启恢复机制没有改变。前述原生磁盘队列保证适用于 `sensor stream`；本文部署方式以原生采集为主。
