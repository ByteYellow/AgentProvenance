# 原生 eBPF 传感器：现状与最初设计

[English](../ebpf-sensor-plan.md) · 简体中文

传感器已经实现，现有范围超过最初的三个探针。代码位于 `internal/sensor` 和 `cmd/agentprov-sensor`，支持 Linux amd64、arm64。安装及已验证环境见[KVM/K3s 部署指南](amd64-kvm-k3s.md)；本文后半部分保留最初设计作为历史背景。

## 当前实现

事件经过标准化后，以 `source=agentprov_ebpf` 进入共同的接收流程：

- `execve` 及 argv、IPv4 `connect`、`openat`、`process_exit`。文件打开覆盖写入和经过过滤的敏感读取，凭据或密钥路径读取映射为 `secret_path`。
- 权限与文件操作：`setuid`、`setgid`、`ptrace`、`rename`、`renameat`、`renameat2`、`unlinkat`；amd64 还处理旧式 `open` 和 `unlink`。
- OpenSSL 明文边界：`SSL_write`、`SSL_read`、`SSL_write_ex`、`SSL_read_ex` uprobe。标准化后默认保留捕获字节哈希、短预览和允许保留的 HTTP 元数据。预览仍可能包含敏感内容，不等于自动脱敏保证。
- Go TLS：amd64、arm64 均支持未去除符号的 `crypto/tls` 写入采集。amd64 还支持 Go 1.23–1.26 ABIInternal 的读取返回点采集，按 goroutine 和栈帧配对。HTTP/1.1 与 HTTP/2/HPACK 重组已经实现，但仍受捕获范围和缓冲上限约束。
- DNS：glibc 的 `getaddrinfo` uprobe，以及 amd64 的 UDP/sendto DNS 采集。
- TLS 自动发现：扫描可见进程映射和容器根目录，跟踪目标并对共享库去重，同时报告覆盖限制。

接收流程还会推断 `llm_call` 和 `llm_intent_caused` 关系。它们不是内核直接给出的因果事实，配对规则和限制见[遥测格式](telemetry-schema.md)。

实现中的几个关键点：噪声路径过滤在 `bpf_ringbuf_reserve` 之前完成，因为丢弃一个已预留记录仍会占用缓冲区；传感器输出自己的事件格式，由 `mapNative` 转换，不模拟 Falco 或 Tetragon；容器身份通过 cgroup 标识到目录 inode 的解析获得。

常驻采集入口是 `agentprov sensor stream`。它将原生事件分成有界批次并持久化，按采集时间关联，重试迟到绑定，默认运行策略评估，无需另行手工导入 JSONL。重启、重试和丢失计数规则见[持久缓冲说明](native-capture-spool.md)。普通 KVM 虚拟机在来宾内部运行采集器。

尚未覆盖的方向包括 ARM64 Go TLS 读取、更广的 DNS 与网络路径、BoringSSL，以及当前不支持的去符号或静态 TLS 目标。amd64 系统调用、TLS、KVM 和 K3s 已有[实测报告](../benchmarks/amd64-kvm-k3s/README.md)。权限调用尝试不证明提权成功；自动发现也不能保证挂载前的事件可被捕获。

## 最初设计：历史记录

以下保留最初的三探针方案。安装当前版本请使用部署指南，不要将此处的早期前置条件当作现行安装要求。

### 目标

实现一个小型 Linux 传感器，采集关联引擎已经使用的事件，将其接入现有遥测格式。它与 Falco、Tetragon 一样，作为额外事件来源复用关联和证据核心。

### 首版范围

| 行为 | 拟用探针 | 标准化 `event_type` |
|---|---|---|
| 进程执行 | `sched/sched_process_exec` 或 `syscalls/sys_enter_execve` tracepoint | `execve` |
| 网络连接 | `tcp_connect` kprobe 或 `syscalls/sys_enter_connect` tracepoint | `network_connect` |
| 文件打开 | `syscalls/sys_enter_openat` tracepoint | `file_open` |

每条事件携带关联所需的 `pid`、`tgid`、`ppid`、`cgroup_id`、由 cgroup 路径解析的 `container_id`、`timestamp`，以及命令行、目标 IP、路径等事件字段。

### 架构

```text
内核探针 → BPF 环形缓冲区 → agentprov-sensor / sensor stream
                              → 标准化事件
                              → 接收 → 关联 → 策略与风险 → 证据图
```

- 加载器采用纯 Go 的 `cilium/ebpf`，使用 CO-RE，运行时不依赖 libbpf。最初方案通过 `bpf2go` 在构建时将 C 编译为对象文件，使用 clang/LLVM 和从内核 BTF 生成的 `vmlinux.h`。
- 提供独立 `cmd/agentprov-sensor` 和 `agentprov sensor stream`。平台构建约束使不支持的平台仍能编译主程序，并在尝试采集时返回明确错误。
- 独立传感器输出 JSONL，供管道和测试使用；`sensor stream` 负责本地存储、自身噪声过滤、绑定关联和默认策略评估。输出最终选择原生格式，由 `mapNative` 根据 `source=agentprov_ebpf` 识别和转换。

### 容器与 cgroup 身份

容器运行时通常将容器标识编码在 cgroup 路径中。解析出的 cgroup 与容器身份进入已有的时间窗口关联方法，其基础置信值分别为 0.98 和 0.92，最终结果还受绑定来源限制。Kubernetes 需要节点解析器和 informer 补充 Pod、容器元数据及生命周期，路径本身不包含完整应用上下文。

监督采集时，`agentprov record` 可以为命令创建真实 cgroup v2 叶节点，后代进程继承该 cgroup。`AGENTPROV_CGROUP_PARENT` 可指定获授权的父目录，例如 `/sys/fs/cgroup/agentprov`；记录器需要足够权限创建子组。非 Linux 或基础记录使用合成作用域标识，此时不声称有内核遥测覆盖。

### 早期构建条件

- Ubuntu 22.04+ 或 Debian 12、内核 5.15+，root/sudo 或 CAP_BPF 与 CAP_PERFMON。
- `clang llvm libbpf-dev linux-headers-$(uname -r) bpftool make` 和 Go 1.23。
- 通过 `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h` 生成 CO-RE 头文件。
- Docker 或 containerd，用于生成可验证的真实容器 cgroup。

这些是初始计划的条件，不能用来推断所有符合版本号的内核都通过了实测。当前已提交生成绑定和对象，普通构建不需要重新生成它们。

### 最初的验证计划

1. 在任意操作系统用合成事件测试格式映射。
2. 在 Linux 容器中执行命令、读取模拟敏感路径、尝试访问元数据 IP，检查采集、归属和风险信号。
3. 扩展 `accept_unified_signals_attestation.sh` 或新增验收脚本，使用真实传感器输出驱动完整流程。

### 不属于该阶段的内容

- 内核侧过滤策略语言，接收后的策略继续使用 Go。
- Windows eBPF 和跨主机汇总。
- 传感器输出的主机外签名或锚定。
