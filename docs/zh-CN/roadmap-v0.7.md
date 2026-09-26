# AgentProvenance v0.7：跨环境证据生产者

[English](../roadmap-v0.7.md) | 中文

> 本文记录 v0.7 的设计与验收。后续实现见 [v0.8.0 发行说明](releases/v0.8.0.md)和 [Linux/KVM/K3s 部署指南](amd64-kvm-k3s.md)。

## 目标

将本地 Linux 已有的采集能力扩展到 **Kubernetes Pod**，沿用同一证据模型、核心图和数据格式。v0.7 的工作集中在证据生产者：部署位置、归属解析、事件传输，以及各环境实际能采集什么。项目不承担工作负载调度。Firecracker/Kata 客体集成属于后续计划，不计入 v0.7 验收。

## 为什么从生产者入手

核心模块 `internal/provenance`、`internal/evidence`、`internal/forensics` 和 `internal/signals` 从 SQLite 读取规范化的遥测数据，不直接依赖运行环境。生产者负责写入这些数据。因此，适配新环境主要需要增加生产者，无需为每种环境重写图查询、差异比较、校验或导出。

三层采集各有不同的适用范围：

| 层次 | 实现方式与代码 | 依赖 | 一种机制能否覆盖全部场景 |
|---|---|---|---|
| **系统遥测** | eBPF tracepoint：`execve`、`connect`、`openat`、`exit`；见 `internal/sensor/sensor_linux.go` | 目标内核 | ✅ 与 Agent 框架和编程语言无关 |
| **模型意图** | libssl 的 `SSL_write`、`SSL_read`、`SSL_write_ex`、`SSL_read_ex` uprobe；通过 `AGENTPROV_GO_TLS_BIN` 指定 Go `crypto/tls.(*Conn).Write` 的部分请求写入路径；用户态解析 HTTP/1.1 和 HTTP/2/HPACK；见 `sensor_linux.go`、`internal/tlsintent` | 目标内核与 TLS 实现 | ⚠️ 当时覆盖动态 OpenSSL，以及保留符号的部分 Go 请求路径 |
| **应用上下文** | 框架 hook JSONL，见 `internal/hooksbridge` 的 Claude Code 格式；通过命令匹配建立 `agent_syscall` 关系 | Agent 框架的事件格式 | ❌ 每种框架需要相应的轻量适配器 |

当时的设计通过命令匹配，将应用上下文、模型意图与系统遥测关联起来。每个绑定记录置信等级，见 `internal/correlation/binding.go` 的 `defaultBindingConfidence`：内核验证为 `1.0`，应用声明为 `0.5`。某一层缺失或降级时，应降低覆盖范围与关联置信度，仍保留其他可用层的记录。在具备内核采集条件时，系统遥测提供不依赖具体 Agent 框架的基础记录。

因此，v0.7 优先处理部署拓扑和被动归属解析。跨 TLS 实现的模型意图采集、不同框架的应用上下文接入，分别列入下文的 v0.7.x 和后续计划。

## 生产者配置描述什么

`Producer Profile` 由四部分组成：

| 配置项 | 含义 |
|---|---|
| `sensor placement` | eBPF 传感器挂载在哪个内核上 |
| `scope resolution` | 如何把 `run/session/tool_call` 绑定到 `cgroup/container/pid` |
| `event transport` | 规范化事件如何到达接收端 |
| `capability level` | 三层数据中，当前实际能采集哪些层 |

`ScopeSource` 分为两种模式，沿用现有置信等级：

- **被动 cgroup 归属**：传感器从观测到的 cgroup 解析容器和 Pod，工具调用通过命令匹配关联。无需包装工作负载入口，置信度低于内核验证的主动绑定。
- **主动 record 包装**：用 `agentprov record` 包装工作负载入口，由 `internal/record/cgroup_linux.go` 创建专用的 cgroup 叶节点。归属经内核验证，置信度为 `1.0`，与当时的虚拟机路径一致。

## 配置类型

| 配置 | 传感器位置 | 归属来源 | 可采集层次 | 当时的新增工作与状态 |
|---|---|---|---|---|
| **local-record**，已有基线 | 本机 | `record` 创建的 cgroup 叶节点 | 系统遥测、应用上下文；模型意图部分覆盖动态 OpenSSL，以及已配置的 Go 请求写入路径 | 作为跨环境对照基线 |
| **k8s-daemonset** | 节点传感器 DaemonSet，配合无特权的归属控制器 | 被动解析 cgroup → 容器 → Pod；也可包装工作负载入口 | 已验证多 Pod 系统遥测；应用上下文沿用已有适配器；模型意图要求能从节点或 rootfs 解析工作负载的 TLS 符号 | **已验证** DaemonSet 部署、标准输出 JSONL 传输、容器与 Pod 元数据到内核 cgroup 的归属、8 个工作负载的图校验，以及 client-go informer 的创建、重启、删除流程。完整 Operator、高可用和集群控制面仍在范围外 |
| **microvm-guest-init** | 计划中的客体初始化服务 | 计划使用主动 record 包装 | **计划中，未验证**；各层覆盖报告为 `none` | 客体镜像集成和销毁前导出证据留待后续，不计入 v0.7 验收 |

传感器已能解析 `docker-<id>.scope`、`cri-containerd-<id>.scope` 和 `kubepods/<id>` 形式的 cgroup，见 `sensor_linux.go` 的 `cgroupResolver.refresh`。这些能力可复用于 Pod 和容器归属。

## 复用已有能力

| 需求 | 复用方式 |
|---|---|
| 执行范围绑定 | `correlation.RecordBinding` 写入 `execution_context_bindings`；接口为 `POST /v1/telemetry/bind`。增加 `binding_source` 值，例如 `k8s_cgroup`，并在 `defaultBindingConfidence` 中设置等级，无需改表结构 |
| 事件传输 | 复用 `POST /v1/telemetry/*`、磁盘缓冲、背压和保留策略，见 `internal/daemon`。远端节点或客体将事件发送给本地或中心服务 |
| 后续 microVM 证据持久化 | 客体运行器完成后，可复用取证包导入、导出和签名声明 |
| Pod 与容器归属 | 复用 `internal/sensor/sensor_linux.go` 的 cgroup 解析 |

## 能力说明与验收

- **逐层报告能力**：每个配置说明实际采集了哪些层，尤其是模型意图和 TLS 的覆盖范围；每种绑定来源报告置信等级。配置可用不代表所有层均已覆盖。
- **Dashboard 展示来源**：节点显示证据来源、归属来源和置信度，即 `evidence source`、`scope source`、`confidence`。
- **跨环境一致性验收**：用 `local-record` 和 `k8s-daemonset` 运行相同工作负载，检查证据图语义一致、`verify` 均通过，并保留各自的置信等级。这类检查沿用 `scripts/accept_*.sh` 验收流程。

`scripts/accept_k8s_node_multiworkload.sh` 可重现 K8s 多工作负载验收。脚本构建并部署真实传感器 DaemonSet，启动 N 个 Pod，将容器和 Pod 元数据解析到观测到的内核 cgroup，摄入 DaemonSet 的 JSONL 输出，再校验执行记录。2026-08-05 的 arm64 K3s 基线使用 8 个 Pod，采集 1,140 个事件，图校验错误和警告均为 0。

跨配置比较由 `scripts/accept_k8s_pod_parity.sh` 单独完成。2026-08-05，同样的 `id + ls /` 工作负载在本地和 K8s 中生成的图均通过校验，规范化命令、事件、节点和边的语义一致。比较排除了物理标识和事件数量差异，保留各配置的置信等级。当时计划要求 KVM 增加独立环境验收后，才能从 `planned` 改为 `validated`；后续结果见页首部署指南。

`scripts/accept_k8s_informer_controller.sh` 可重现归属绑定的生命周期验收。2026-08-05 的 K3s 1.36.2 基线先创建绑定；同一 Pod UID 下容器真实重启后，关闭旧绑定并创建新绑定；删除 Pod 后，再关闭替代绑定。最终创建 2 个、关闭 2 个、活动绑定为 0，重试、失败和解析失败均为 0。`client-go v0.32.0` 与仓库当时的 Go 1.23 基线配套。

## 当时安排的后续工作

以下项目不计入 v0.7 发布条件，避免跨框架和跨 TLS 实现的工作阻塞环境配置交付。

### v0.7.x：Agent 框架意图适配器

为 LangChain、OpenAI Assistants 和自定义框架增加轻量格式转换，将框架回调转成 hook 格式，再复用命令匹配关联。未适配框架的工作负载，在支持内核采集的环境中仍可保留系统层溯源。

### 多种 TLS 实现的采集加固

原计划在动态 OpenSSL 和部分 Go 请求写入路径之外，补充 Go `crypto/tls` 响应读取、BoringSSL、静态链接 TLS、移除符号的 Go 程序处理，以及 x86 实机验收，以减少模型意图采集对具体框架和 TLS 实现的依赖。

**2026-07-08 的 K8s DaemonSet 示例曾记录读取侧采集不足。** 即使使用动态 OpenSSL，节点侧也只能间歇生成 `tls_read`，而 `tls_write` 较稳定；窗口内写入与读取事件比例约为 13∶1。当时 `SSL_read` 入口及返回探针挂载正常，丢失发生在 HTTP 响应头重组阶段：如果分块或 HTTP/2 响应头没有落在首次 `SSL_read` 返回中，就会被丢弃。

该次观测中，请求正文和运行环境、进程、网络外发视图较完整；响应正文及 `agent-intent` 的 `llm_call` 图较稀疏，需要采到读取事件后才能补全。请求响应配对本身不是当时定位到的瓶颈：被动采集时，即使 `process_id` 为空，`recentScopedEvent` 也会回退到执行记录范围，所以一次有效 `tls_read` 可生成一个 `llm_call`。当时提出的修复方向是在 HTTP 解析前重组 `SSL_read` 片段。

## 当时的能力矩阵与目标

| 环境 | 系统遥测 | 模型意图 | 应用上下文 | 归属范围 |
|---|---|---|---|---|
| 本地 Linux／虚拟机 | ✅ | ⚠️ 动态 OpenSSL，含 `SSL_*`、`SSL_*_ex`、HTTP/1.1 和 HTTP/2/HPACK；部分 Go 请求写入 | ✅ | 经内核验证的 record 绑定 |
| microVM，Firecracker/Kata | ⬜ 计划中 | ⬜ 计划中 | ⬜ 计划中 | 计划在客体内运行 record |
| K8s Pod | ✅ 节点侧 | ⚠️ 动态 OpenSSL 或 Go 写入路径，要求能从节点或 rootfs 解析符号 | ✅ | 被动 cgroup → Pod，或 record 包装 |
| K8s Job | ✅ 节点侧 | ⚠️ 同上 | ✅ | 另附 Job 和所有者元数据 |
| 裸机／多节点 | ✅ 每个节点分别采集 | ⚠️ 动态 OpenSSL 和部分 Go 请求写入 | ✅ | record 或 cgroup |
| 无内核访问权限的无服务器／托管环境 | ❌ | ❌，除非平台提供相应接口 | ✅ | 仅显式标识 |

无法访问内核时，例如部分无服务器或完全托管环境，只能保留应用上下文。可安装采集器的 Linux 环境具备接入三层数据的基础，但实际覆盖仍受权限、TLS 实现和应用适配器限制。
