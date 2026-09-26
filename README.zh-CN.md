<p align="center">
  <img src="docs/img/agentprovenance-cover-zh-CN.png" alt="AgentProvenance：AI Agent 到底执行了什么？" width="100%">
</p>

<div align="center">

# AgentProvenance

### 看清 AI Agent 的执行过程，追溯每一步的来龙去脉。

将**模型意图、应用上下文和运行时行为**关联起来，形成可查询、可验证的执行证据图。
从一次工具调用，追踪到它启动的进程、读写的文件和访问的网络地址，
用于排查风险、比较执行差异，以及在本地回放已签名的记录。

[![Release](https://img.shields.io/github/v/release/ByteYellow/AgentProvenance?style=flat-square&color=orange&sort=semver)](https://github.com/ByteYellow/AgentProvenance/releases/latest)
[![Go](https://img.shields.io/badge/go-1.23+-00ADD8.svg?style=flat-square)](https://go.dev/)
[![CI](https://img.shields.io/github/actions/workflow/status/ByteYellow/AgentProvenance/ci.yml?branch=main&style=flat-square)](https://github.com/ByteYellow/AgentProvenance/actions/workflows/ci.yml)
[![Sensor](https://img.shields.io/badge/sensor-Linux_amd64_%7C_arm64-2496ED.svg?style=flat-square)](docs/zh-CN/amd64-kvm-k3s.md)
[![SQLite](https://img.shields.io/badge/state-SQLite-003B57.svg?style=flat-square)](https://www.sqlite.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg?style=flat-square)](LICENSE)

**[快速开始](#快速开始)** | **[核心模型](#核心模型)** | **[当前能力](#当前能力)** | **[示例](demo/README.md)** | **[版本与计划](#版本进展与后续计划)**

[English](README.md) | 简体中文

</div>

---

<p align="center">
  <img src="docs/assets/three-axis-observability.svg" alt="模型意图、应用上下文和系统运行记录汇入同一张可验证证据图。" width="100%">
</p>

**Agent 实际做了什么？证据在哪里？**

- 哪个 Agent 的任务委派或协作消息，引发了这次工具调用？
- 哪个进程读取了敏感文件、修改了产物，或连接了外部地址？
- 这些判断依据哪些记录？记录能否离线验证？

**真实案例：恶意依赖如何通过 Agent 之间的协作被安装。**
Hooks 记录任务委派和协作消息，运行时采集记录文件读取与网络连接，
可视化界面将它们关联起来，回放整个执行过程：

<p align="center">
  <img src="docs/img/demo-multiagent-agent-network.gif" alt="多 Agent 执行回放：任务委派、协作消息、工具调用及对应的运行时证据。" width="100%">
</p>

[查看真实场景](demo/multiagent-provenance/README.md) ·
[立即回放](#快速开始) · [v0.8.2-rc.2 版本说明](docs/releases/v0.8.2-rc.2.md)

## 目录

- [快速开始](#快速开始)
- [为什么需要它](#为什么需要它)
- [安全闭环](#安全闭环)
- [核心模型](#核心模型)
  - [证据分层](#证据分层)
  - [运行时事实与关联](#运行时事实与关联)
- [与现有系统的关系](#与现有系统的关系)
- [意图一致性](#意图一致性)
- [部署模式](#部署模式)
- [安全证据命令](#安全证据命令)
- [外部评估器协议](#外部评估器协议)
- [合规证据，而非合规认证](#合规证据而非合规认证)
- [AI 可调用的证据工具](#ai-可调用的证据工具)
- [可视化界面](#可视化界面)
- [证据图命令](#证据图命令)
- [当前能力](#当前能力)
- [核心 Demo 验收](#核心-demo-验收)
- [架构](#架构)
- [运行环境与遥测](#运行环境与遥测)
- [边界](#边界)
- [仓库结构](#仓库结构)
- [版本进展与后续计划](#版本进展与后续计划)
- [开发](#开发)
- [作者与许可](#作者与许可)

## 快速开始

### 下载并回放，无需安装 Go

![本地 Demo 首页：六份签名回放与两个可选评估器指南](docs/img/demo-gallery-zh-CN.png)

在 [**v0.8.2-rc.2 预发布版**](https://github.com/ByteYellow/AgentProvenance/releases/tag/v0.8.2-rc.2)
下载对应平台的压缩包及同名 `.sha256` 校验文件：

| 平台 | 压缩包后缀 |
|---|---|
| Linux / WSL，x86-64 | `linux_amd64.tar.gz` |
| Linux / WSL，ARM64 | `linux_arm64.tar.gz` |
| macOS，Intel | `darwin_amd64.tar.gz` |
| macOS，Apple Silicon | `darwin_arm64.tar.gz` |

以 Linux x86-64 为例，在下载目录执行：

```sh
sha256sum -c agentprov_v0.8.2-rc.2_linux_amd64.tar.gz.sha256
mkdir agentprov-demo
tar -xzf agentprov_v0.8.2-rc.2_linux_amd64.tar.gz -C agentprov-demo
cd agentprov-demo
./agentprov demo
```

macOS 请使用对应的 `darwin` 文件名，并用 `shasum -a 256 -c` 校验。
Windows 用户请在 WSL 中运行对应的 Linux 包。
当前 macOS 二进制尚未经过 Apple Developer ID 签名或公证。
校验和用于检查下载文件的完整性，`build-info.json` 记录构建信息；
这些信息不等同于发布者的数字签名。

运行后，浏览器会打开 **Demo 首页**，其中包含 6 份已签名的执行记录和
2 个可选评估器的使用指南。首页与可视化界面（Dashboard）采用相同的浅色样式：
点击 **Read guide** 阅读带目录、图片、表格和代码复制按钮的本地指南；
点击 **Open replay** 查看执行记录。

选择示例后，程序会自动定位到对应的执行记录（Run）和视图。
带时间信息的视图会自动播放，部署视图则直接展示拓扑。
CLI 会先校验原始签名，再将记录导入独立的临时目录并验证证据图。
按 Ctrl-C 退出时清理临时数据，不影响日常数据目录，也不会重新执行记录中的命令。

```sh
./agentprov demo --list
./agentprov demo multiagent-provenance
./agentprov demo k8s-cross-pod-a2a --no-browser
```

回放这些记录不需要 Go、仓库源码、虚拟机、Docker、Agent 账号或 API Key，
也不需要联网。各示例的原始脚本和说明一并放在压缩包的 `demo/` 目录中。
LLM Judge 和 Jev 是可选的 Python 示例，实际调用评估器仍需按各自指南配置环境。
打开 Demo 首页或阅读指南不会调用模型；离线示例结果也不代表真实模型的评估结论。
详见 [Demo 目录](demo/README.md)。

如果选择从源码构建，则需要 Go 1.23+：

```sh
git clone https://github.com/ByteYellow/AgentProvenance
cd AgentProvenance
go build -o agentprov ./cmd/agentprov
./agentprov demo
```

### 记录你自己的 Agent 执行

在解压目录或源码目录中，启动已经安装并完成登录或认证的 Agent：

```sh
./agentprov doctor -- claude
./agentprov launch -- claude
```

`doctor` 会在不启动 Agent 的情况下，检查命令是否可用、Hook 接入情况、
cgroup 和传感器权限，以及可视化界面的端口。`launch` 随后为本次命令及其子进程
创建执行范围（作用域）、启动可视化界面，并为 Claude 注入仅对本次运行生效的
Hooks 配置，不修改 `~/.claude`。

Linux 内核事件采集需要受支持的内核、可用的 cgroup，以及 root 或相应的
BPF/perf 权限。macOS 可以记录进程、文件变化，并接入应用 Hooks 和会话记录，
**但不提供 Linux 内核传感器**。预检和最终报告会说明本次实际采集了哪些层次的证据。
其他 Agent 能否提供应用上下文，取决于是否有对应的 Hook 或会话记录适配器。

程序退出时会封存证据图。**如需签名，必须显式传入 `--sign-key <private-key-file>`，
默认不会自动签名。**如需比较工作区在执行前后的文件变化，添加 `--file-diff`。

节点级采集请参阅 [KVM 虚拟机与 K3s 部署指南](docs/zh-CN/amd64-kvm-k3s.md)和
[Kubernetes 事件归属指南](docs/design-k8s-auto-attribution.md)。
传感器运行在 KVM 虚拟机内部或 Kubernetes 节点上，两种环境共用同一套证据模型。

### 记录普通命令

```sh
mkdir -p /tmp/agentprov-record-demo
./agentprov record --run run-record-demo --workdir /tmp/agentprov-record-demo -- \
  sh -c 'echo artifact > artifact.txt'
./agentprov observe summary --run run-record-demo
./agentprov graph explain --run run-record-demo --file artifact.txt
```

回放、本地 `record` 和可视化界面都不需要 Docker；只有基于 Docker 的执行功能
需要它。进阶用法见：[证据图命令](docs/zh-CN/graph-commands.md)、
[部署模式](docs/zh-CN/deployment-modes.md)、[遥测数据格式](docs/zh-CN/telemetry-schema.md)和
[开发与测试](#开发)。

## 为什么需要它

一次 Agent 任务往往涉及多步操作：修改文件、运行测试、生成产物、启动子进程，
以及访问外部系统。日志、调用链、指标和沙箱事件分别记录了其中一部分，
但要回答“哪次工具调用造成了这个变化”，还需要将这些记录关联起来。

AgentProvenance 将执行上下文与运行时记录组织成证据图，
用类似 Git 的查询方式追溯变化的来源：

```text
base state                    基线状态
  -> execution scope              执行作用域
  -> execution context            执行上下文
  -> tool_call                    工具调用
  -> process / child process      进程 / 子进程
  -> runtime_event                运行时事件
  -> file_diff / artifact         文件差异 / 产物
  -> baseline feature / risk signal   基线特征 / 风险信号
  -> taint / response action      污点标记 / 响应动作
  -> replay / forensics / audit manifest   回放 / 取证 / 审计清单
```

项目的核心是**记录并解释 Agent 的执行过程**。它输出结构化的执行轨迹和
偏差信号，供调试、安全分析、外部评估器或训练流水线使用。

在强化学习（RL）场景中，这些证据可以帮助判断：Agent 做了什么、访问了哪些
文件和进程、产生了哪些网络行为，以及是否偏离任务要求或安全约束。
奖励、惩罚、轨迹筛选和人工复核的规则由外部系统决定。

## 安全闭环

安全分析围绕以下链路展开：

```text
application context   应用上下文
  run / trajectory / execution_scope / tool_call / user / task / workspace

system telemetry      系统遥测
  process / file / network / resource / sandbox / eBPF event

correlation           关联
  container_id / cgroup_id / pid / ppid / cwd / timestamp / file diff

security analysis     安全分析
  behavior baseline / suspicious event / taint lineage / risk decision

response              响应
  audit / deny / kill / quarantine / taint / forensics / 飞书或钉钉通知
```

传统主机监控关注“这个进程做了什么”。AgentProvenance 在此基础上补充
Agent、任务和工具调用的上下文，进一步回答：“这次行为属于哪个任务？
改变了什么？判断依据是什么？是否需要响应？”

当前已实现证据图、运行时关联、diff/blame、遥测批次清单、策略判定、
风险与基线偏差信号、响应记录、污点标记、隔离、取证导出和原生 eBPF 传感器。
飞书、钉钉等通知适配器仍属于后续计划；Falco、Tetragon 接收器保留兼容性维护。

## 核心模型

<p align="center">
  <img src="docs/assets/evidence-dag.svg" alt="执行证据图：模型意图、工具调用、进程、事件、风险、响应、产物及其校验关系。" width="100%">
</p>

证据采用内容寻址存储，通过哈希校验完整性，并支持可选的数字签名。
这里的 **Git-like 执行溯源**，指的是对执行记录进行比较、追溯和回放；
不包含 Git 分支合并、检出，也不支持撤销已经发生的外部操作。

最基本的用法，是用 `record` 启动你原本就要运行的命令：

```sh
agentprov record -- <agent command>
```

`record` 记录执行前后的文件状态，运行命令并采样进程树，将这些证据写入
有向无环图（DAG），无需在应用中接入 SDK。
在此基础上，可以通过受支持的 Hook、会话记录适配器或自定义上下文来源补充
应用信息；内核事件则由运行中的传感器采集。可用的证据会汇入同一份执行记录。

### 证据分层

| 证据层 | 来源 | 能说明什么及其限制 |
|---|---|---|
| 运行时事实 | `record` 的进程采样与文件差异、原生 eBPF 传感器、兼容的 JSONL 接收器 | 记录观测到的进程、文件和网络行为，按运行身份与采集时间关联。可信程度取决于采集器和宿主机的可信程度。 |
| 应用上下文 | Agent 运行框架的 Hooks（`hooks bridge`）、MCP 上下文写入（`bind_scope` / `record_tool_call`），以及显式提交的任务和工具调用标识 | 补充 Agent 身份、任务委派、协作消息和拒绝执行等信息。模型通过上下文写入接口提交的信息标记为 `binding_source=ai_asserted`，置信度上限为 `0.5`，不能覆盖内核事实。 |
| 模型意图 | 受支持的会话记录适配器、TLS 明文探针，以及 HTTP/1.1、HTTP/2/HPACK 解析 | 记录请求、响应和模型声明的工具操作，不代表读取模型内部推理。无法采集的部分会作为覆盖缺口保留。 |

运行时证据说明“实际发生了什么”，应用上下文帮助回答“属于哪个 Agent、
哪次工具调用、什么任务”。例如，编排器的 `agent_spawn`、`agent_message`
关系，以及模型拒绝执行某个动作，都无法仅靠系统调用推断出来。

应用上下文是可选的补充。运行框架可以通过 Hooks 或 MCP 接口提供这些信息，
并关联到同一次执行；缺少这类信息时，已有的运行时记录仍可独立查询。

### 运行时事实与关联

关联引擎根据以下运行信息，将事件归属到相应的执行上下文：

```text
root process / process tree / cwd / timestamp / container_id / cgroup_id
  / file diff / artifact refs
```

内核事件通常只包含 PID、cgroup、命名空间、容器 ID、时间戳和进程树信息，
无需携带应用侧的 `tool_call_id`。AgentProvenance 使用这些关联信息，
将系统事件与任务、执行作用域和工具调用连接起来。

也可以通过 CLI 显式建立绑定：

```sh
agentprov telemetry bind --run <run_id> --substrate-scope <substrate_scope_id> \
  --execution-scope <execution_scope_id> --tool-call <tool_call_id> --process <process_id> \
  --container-id <container_id> --cgroup-id <cgroup_id> --pid <pid>
```

建立绑定后，即可导入不含 `tool_call_id` 的原始事件：

```sh
agentprov telemetry ingest --raw-event raw-execve-1 --pid <pid> \
  --timestamp <event_time> --source tetragon_jsonl --type execve \
  --payload '{"argv":["./async_child.sh"]}'
agentprov telemetry ingest-jsonl --format tetragon --file tetragon-events.jsonl
agentprov telemetry ingest-jsonl --format native --file agentprov-sensor-events.jsonl
agentprov telemetry ingest-falco --file falco-events.jsonl
```

`ingest-jsonl` 会生成遥测批次清单，记录输入文件哈希、映射后的事件 ID 及其哈希、
接收摘要和逐行处理结果，便于追溯一批数据的来源与处理过程。
默认还会对导入的事件执行策略评估：访问云元数据地址、内网地址或敏感路径等事件，
可产生 `policy_decisions`、`risk_signals`、`response_actions` 及相应的图关系和时间线记录。
如果只需规范化和存储事件，可使用 `--no-policy`。

原生 eBPF 传感器（`cmd/agentprov-sensor`，`source="agentprov_ebpf"`）输出的
`native` 格式会被自动识别。它采集的进程执行、网络连接和文件访问事件，
与第三方遥测共用关联、策略、风险和统一信号处理流程。
文件事件可以保留宿主机上的绝对路径，例如 `/home/agent/.aws/credentials`，
并接受路径规则检查；工作区文件节点则使用相对路径。
`scripts/accept_native_sensor_risk.sh` 验证了从原生采集到 `security` 信号的完整链路。

已有 Falco 的主机也可使用 `ingest-falco`，将 Falco 的 JSON/stdout 输出接入
同一流程。用法见 [Falco 接收器说明](docs/zh-CN/falco-receiver.md)。

## 与现有系统的关系

AgentProvenance 可以接收系统可观测性工具和沙箱提供的数据，也可以与
LLM 调用追踪平台配合使用。各自关注的重点如下：

| 系统类别 | 主要职责 | AgentProvenance 补充的能力 |
|---|---|---|
| 系统可观测性工具 | 采集系统事件，观察进程及其运行行为 | 将事件关联到 Agent 任务与工具调用，支持变化追溯、污点传播分析、风险判定和取证 |
| OpenTelemetry / LLM 调用追踪平台 | 记录调用链、日志、指标、模型与工具调用，以及延迟和成本 | 追溯文件和产物的来源，关联沙箱内的实际行为，并提供可验证的执行记录 |
| HIDS / EDR / 运行时安全系统 | 检测主机、进程、文件和网络行为，并执行防护策略 | 补充 Agent 身份、任务上下文、文件变化和执行归属，说明风险与哪次任务相关 |
| 沙箱运行时 | 执行进程、容器或虚拟机，提供文件系统和网络隔离 | 使用沙箱身份与遥测构建证据；不替代 Docker、OpenSandbox、gVisor、Firecracker、Kata 或 Kubernetes |

核心链路是：

```text
系统运行记录 + Agent 应用上下文
  -> 可验证的执行证据图
  -> 安全分析与风险判定
  -> 响应记录与审计追溯
```

## 意图一致性

意图一致性分析比较**声明要执行的操作**与**实际观测到的行为**。
除了关联“哪个模型调用引发了这次操作”，它还检查行为是否超出声明范围，
以及被拒绝的动作是否仍然发生。

```sh
agentprov intent diff --run <run_id>
```

每份 **IntentContract（意图契约）**记录一次工具调用、Agent 间消息或拒绝决策
所允许和禁止的行为。系统将它与归属到同一作用域的 **RuntimeEffects（运行时行为）**
进行比较，输出以下结果：

| 判定 | 含义 |
|---|---|
| `declared_vs_effect_mismatch` | 实际行为超出声明范围，例如安装依赖时读取无关凭证并连接云元数据地址 |
| `peer_message_intent_mismatch` | 超出声明范围的行为源于另一个 Agent 发来的消息 |
| `refused_but_runtime_happened` | 模型已拒绝该动作，但仍观测到对应行为 |
| `decided_and_executed` | 观测到声明中的行为，且未发现违反该契约的情况 |
| `intent_coverage_gap` | 观测到敏感行为，但缺少对应的意图记录，无法完成比较 |

判定以**具体操作的声明范围**为依据。例如，网络连接可能超出只读文件工具的职责，
却属于 `bash` 的可用能力；读取未声明的敏感凭证也可能构成偏差。
Agent 正常读取自身凭证的情况，则由同一套策略引擎中的相应规则识别。

结果写入统一信号模型的 `intent_conformance` 维度，可影响 `launch` 的最终判断，
并在 **Conformance · declared vs actual** 视图中展示“声明 → 判定 → 观测行为”。
[多 Agent 示例](demo/multiagent-provenance/README.md)中，`alice` 诱导 `bob`
安装恶意依赖，相关偏差被标记为 `peer_message_intent_mismatch`。

## 部署模式

目前可以使用单机 CLI 或本地服务两种部署方式；中心化证据服务还处于设计阶段。
本地开发、基准测试、评估器和 RL 流水线通常可以从 CLI 开始。
需要持续接收事件、共享本机查询接口时，再使用本地服务。

<p align="center">
  <img src="docs/assets/deployment-modes.svg" alt="AgentProvenance 的 CLI、本地服务与中心化服务部署方式。" width="920">
</p>

| 模式 | 形态 | 适用场景 | 使用成本与限制 |
|---|---|---|---|
| 库 / 单机 CLI | 一个 `agentprov` 可执行文件，可选 Python 辅助库，本地 SQLite 与对象存储 | 评估任务、基准测试、CI、RL 流水线、本地红队测试 | 上手简单，不提供集中查询或跨主机汇聚 |
| Sidecar / 本地服务 | 在任务执行节点或沙箱主机上运行 `agentprov daemon serve`，CLI 和评估器通过它读写数据 | 持续采集、CI 执行节点、本地安全分析 | 需维护一个本地服务，提供磁盘缓冲、背压和查询 API |
| 中心化证据服务（仅设计） | 规划中的共享接收与查询服务，包含对象存储、保留策略、认证和 UI/API | 跨节点调查、审计、SRE 和事件复盘 | 尚未实现；多租户、计费和集群控制平面不在本版范围内 |

本地服务的磁盘缓冲队列（spool）同时限制批次数、总字节数和单批大小，
并通过 `telemetry producer-health` 报告背压、丢弃和关联覆盖情况。
`scripts/accept_telemetry_100k_pressure.sh` 生成包含吞吐量、延迟、资源占用、
队列状态和覆盖率的机器可读报告。参考测试接收了全部 10 万条事件，没有失败或
丢弃的批次，健康检查和分页事件查询也能正常响应。
这是单节点 SQLite 基准，不代表生产环境 SLA。具体范围见
[收尾标准](docs/zh-CN/project-closeout.md)和[中心化服务设计](docs/zh-CN/central-evidence-service-design.md)。

Kubernetes 验收会部署特权传感器 DaemonSet，启动多个独立 Pod，
将 Pod、容器身份与内核 cgroup 对应起来，再导入并验证采集结果。
2026-08-05 的 ARM64 K3s 实验使用了 8 个 BusyBox Pod，识别到 8 个独立 cgroup，
记录 1,140 条事件，`graph verify` 无错误、无告警。
该结果验证了单个节点传感器同时观测多个工作负载的能力，不是集群吞吐量测试。

同一负载还通过了**不同采集模式的语义一致性验收**：主动启动的 `local-record`
与被动采集的 `k8s-daemonset` 均通过证据校验，且记录了相同的负载命令、`execve`
证据、运行时事件节点和“进程 → 事件”关系。比较不要求 PID、cgroup、容器标识
或事件数量相同，各模式的关联置信度也分别保留。

可通过 `agentprov sandbox profiles`（支持 `--json`）查看采集模式及其验证状态。
标记为 `planned` 的模式在通过真实环境验收前，作用域置信度和采集覆盖率均为零。

另一个轻量 DaemonSet 运行 `agentprov sandbox watch`，负责维护事件归属：
它使用 `client-go` informer 监听本节点 Pod，将运行中的容器映射到内核遥测使用的
cgroup inode，并在容器重启、Pod 删除后更新绑定。所需 RBAC 权限仅为 Pod 的
`get/list/watch`，事件采集仍由独立传感器负责。
K3s 生命周期验收记录了 1 次重启、2 次绑定创建和 2 次绑定关闭，
结束时无活跃绑定残留或解析失败。这验证了节点内的绑定维护，不代表完整的
Kubernetes Operator 或集群控制能力。

```sh
AGENTPROV=/path/to/linux/agentprov \
SENSOR=/path/to/linux/agentprov-sensor \
AGENTPROV_MULTIWORKLOAD_REPORT=/tmp/agentprov-k8s-multiworkload.json \
  ./scripts/accept_k8s_node_multiworkload.sh

AGENTPROV=/path/to/linux/agentprov \
AGENTPROV_K8S_INFORMER_REPORT=/tmp/agentprov-k8s-informer.json \
  ./scripts/accept_k8s_informer_controller.sh
```

RL 和评估流水线可以采用轻量的离线工作流：

- **安装**：下载一个可执行文件；需要 Python 接口时再安装辅助库。
- **接入**：用 `record` 启动已有命令。受支持的 `launch` 配置、Hook 和会话记录
  适配器可补充应用上下文；自定义集成也可通过 MCP 写入上下文。
- **批量处理**：每条轨迹都有 `run_id`、证据清单和评估上下文，查询接口支持分页。
- **采集范围**：默认记录进程、文件变化、产物、退出状态和资源信息；
  更详细的 eBPF 或第三方遥测按需启用。
- **职责划分**：AgentProvenance 提供证据、偏差、风险和轨迹信号；
  奖励、排序、数据集管理和轨迹筛选由 RL 系统决定。
- **安全策略**：拒绝、终止和隔离属于可选控制。离线评估可以在执行结束后，
  直接读取 `EvalContext` JSONL，不要求启用这些控制。

`EvalContext`、`EvalSignal` 协议及 Python 自定义规则的用法，见
[外部评估器协议](#外部评估器协议)。

## 安全证据命令

以下命令用于查看一次执行中的证据、风险和响应。
查询结果支持 `--json`，并提供相应的结果集或分页完整性信息：

```sh
./agentprov observe summary --run <run_id>       # 覆盖率：应用上下文、遥测、风险、响应
./agentprov observe flow --run <run_id>          # 运行时事件 -> 风险 -> 策略 -> 响应
./agentprov timeline --run <run_id> --view causality
./agentprov security risks --run <run_id>        # 另有：deviations / responses
./agentprov baseline learn --template <t> --run <run_id>   # 然后：baseline check
./agentprov policy test examples/events/metadata-egress.jsonl
./agentprov forensics export <run_id>            # 带哈希、可选签名的审计包
```

- `observe summary/coverage/scopes/event/process/flow`：查看执行概况，或按作用域、
  事件、进程进一步排查。
- `evidence manifest` / `telemetry correlations`：查看带哈希索引的证据目录，
  以及每条事件的归属依据。
- `security risks/deviations/responses` + `baseline learn/check`：基于关联后的证据
  查看风险、基线偏差和响应记录。
- `policy test/decisions`：测试策略规则、查看策略判定。
- `forensics export[-batch]`：导出可审计的证据包。

完整命令列表及每条命令的用途：
[docs/security-commands.md](docs/zh-CN/security-commands.md)。

## 外部评估器协议

AgentProvenance 为外部评分系统提供证据，奖励函数、排序和数据集策略仍由
外部系统管理。

```sh
./agentprov signal context --run <run_id> > eval-context.json

./agentprov signal run --run <run_id> \
  --external "PYTHONPATH=python python3 examples/evaluators/python_signal_eval.py" \
  --json

./agentprov signal import --run <run_id> --file external-signals.json --json
```

协议包含以下内容：

- `EvalContext` 包含轨迹、文件变更、运行时事件、风险信号和响应动作。
- 外部评估器从 stdin 读取 `EvalContext`，返回 `{ "signals": [...] }`。
- `EvalSignal` 可以表示奖励特征、惩罚、数据集标签或质量信号。
- `signal import-batch` 接受 JSONL 格式的 EvalReport 记录，这样 RL 流水线
  可以一次导入多条轨迹的离线评估结果。

基准测试、RL、红队测试和数据筛选流程可以自行决定，如何根据这些证据评分、
拒绝结果或发起人工复核。

可选参考实现：[LLM 安全评估示例](demo/llm-judge/)和
[Jev 结构化评估器](demo/jev-judge/)。模型服务调用、规则对比和复核页面由这些
外部示例提供，采集、回放和主可视化界面都不依赖它们。
分析结果通过已有的信号接口写回。

### 用 Python 写自定义规则

<details>
<summary>展开完整的 Python 规则示例</summary>

`python/agentprov_eval`（可通过 `import agentprov` 使用）是基于 CLI 的轻量辅助库，
不内置奖励函数。自定义规则就是读取 `EvalContext` 并返回信号的普通 Python 函数；
采集、关联、证据清单和完整性校验仍由 Go 程序负责。
下面的例子通过一个函数完成“批量记录 → 执行评估规则 → 导入信号”的本地离线流程：

```python
from agentprov import Registry, Signal, run_batch_pipeline

registry = Registry(name="rl-reward-signals")

@registry.rule("file_change_reward")
def file_change_reward(ctx):
    return Signal.reward_feature(
        "file_change_reward",
        float(len(ctx.file_changes())),
        "reward feature from file state changes",
    )

@registry.rule("metadata_penalty")
def metadata_penalty(ctx):
    if ctx.has_event_type("metadata_ip"):
        return Signal.penalty("metadata_ip", -1.0, "metadata service access")
    return None

result = run_batch_pipeline(
    [
        {"run_id": "traj-0001", "workdir": "/tmp/job1", "command": ["pytest", "-q"]},
        {"run_id": "traj-0002", "workdir": "/tmp/job2", "command": ["pytest", "-q"]},
    ],
    registry,
    binary="./agentprov",
    data_dir=".agentprov-rl",
    engine="rl-reward-signals",
    import_signals=True,
    include_forensics=True,
)

print(result.batch_id, result.signal_count)
```

如果已有流水线负责调度或分片，也可以分别调用各个步骤：

```python
from agentprov import Client, evaluate_batch

client = Client(binary="./agentprov", data_dir=".agentprov-batch")
batch = client.record_batch(
    [
        {"run_id": "traj-0001", "workdir": "/tmp/job1", "command": ["pytest", "-q"]},
        {"run_id": "traj-0002", "workdir": "/tmp/job2", "command": ["pytest", "-q"]},
    ],
)
contexts = client.batch_eval_contexts(batch_id=batch["batch_id"])
reports = evaluate_batch(contexts, registry=registry)
client.import_signal_reports(reports, engine=registry.name)
```

结果写入本地存储后，可按批次、分片、任务或单次执行查询：

```sh
./agentprov evidence batch-summary --latest --json
./agentprov evidence batch-summary --shard shard-0 --json
./agentprov evidence batch-summary --run traj-0001 --json
./agentprov signal batch-context --shard shard-0 --latest > eval-contexts.jsonl
./agentprov forensics export-batch --latest --json
```

</details>

### 本地服务（Daemon）模式

运行本地服务时，也可以通过 HTTP API 使用同一套协议：

```text
GET  /v1/signal/context?run=<run_id>
POST /v1/signal/run
POST /v1/signal/import
```

本地服务不提供执行任意 Shell 命令的 HTTP 接口。
客户端应先获取 `EvalContext`，在自己的进程中运行评估器，
再将结果提交给服务校验。CLI 设置 `--daemon-url` 后也采用这一流程。

## 合规证据，而非合规认证

一次执行的证据可以映射到安全框架中的检查项，例如 OWASP Agentic Security
和 NIST AI Agent 安全评估要求，用于开展**有证据支撑的自评**。
这些报告不构成认证或法律意见，也不能替代第三方审计：

```sh
./agentprov compliance map --framework owasp-asi --run <run_id>
./agentprov compliance gaps --framework owasp-asi --run <run_id>   # 已检测未阻止或尚无规则的待办
```

每个检查项映射到具体检测规则及其在本次执行中的命中记录，报告
`enforced`（已阻止）、`detected`（已检测但未阻止）、`not_triggered`（未触发）或
`no_rule`（尚无规则），同时给出 `evidence_refs` 和处理建议。尚无检测器表示覆盖缺口；
规则未触发不等于普遍满足要求。自定义 YAML 目录可增加框架，`--rules` 可加载实际检测规则。

完整命令、检查项含义和 YAML 规则格式，见[合规证据说明](docs/zh-CN/compliance.md)。

## AI 可调用的证据工具

AgentProvenance 将证据查询和部分上下文写入接口封装成 AI 可调用的工具，
供 Agent 运行框架、评估器或辅助复核工具使用：

```sh
./agentprov ai tools --provider generic
./agentprov ai tools --provider openai
./agentprov ai tools --provider anthropic

./agentprov ai call verify_run --input '{"run":"run-demo-bugfix"}'
./agentprov ai call list_events --input '{"run":"run-demo-bugfix","type":"execve","limit":10}'
./agentprov ai call get_timeline --input '{"run":"run-demo-bugfix","view":"causality"}'
./agentprov ai call evaluate_action --input '{"event_type":"execve","args":["python","-m","pytest","-q"]}'
./agentprov ai call evaluate_action --input '{"event_type":"network_connect","dst_ip":"169.254.169.254"}'

./agentprov ai mcp   # 通过 stdio MCP（JSON-RPC 2.0）提供同一份目录
```

工具定义可导出为 generic、OpenAI 或 Anthropic 格式，通过 `ai call` 在本地调用，
也可以由 `ai mcp` 提供给 MCP 客户端。后者使用 stdio JSON-RPC 2.0，
协议版本为 `2025-06-18`。这些入口共用同一份工具定义：

| 工具 | 用途 |
|---|---|
| `verify_run` | 校验一次执行的对象哈希、父子链接，以及策略、风险、响应和信号的完整性 |
| `get_signals` | 查询行为、成本、质量和安全信号 |
| `list_risks` | 查询安全风险与建议动作 |
| `list_events` | 分页查询运行时事件，可按事件类型筛选 |
| `get_timeline` | 查询合并后的应用上下文与运行时事件时间线 |
| `evaluate_action` | 将拟执行的命令、文件操作或网络操作交给策略引擎预检，不执行该操作 |
| `bind_scope` | 注册 `ToolCallScope` 绑定，使系统遥测可关联到对应工具调用；提交信息标记为 `ai_asserted` |
| `record_tool_call` | 记录应用侧声明的工具调用，标记为 `status=asserted`，不执行工具 |

查询工具和 `evaluate_action` 标记为只读；`bind_scope` 与 `record_tool_call`
会写入应用上下文，因此在 MCP 中标记为 `readOnlyHint=false`。
这些写入接口不用于提交原始内核事件或修改签名。模型提供的上下文以应用侧声明
保存，不能当作传感器观测到的事实；动作预检则由策略引擎完成。

### 实例：让 LLM 分析安全证据

外部模型可以读取证据并给出分析，再将结论作为信号写回，而不修改原始记录。
`demo/llm-judge` 提供了一个完整示例：

```sh
python3 demo/llm-judge/judge.py run            # 导入示例证据包并评估
python3 demo/llm-judge/judge.py run --run <id> --data-dir <dir>   # 评估已有的执行记录
```

该示例通过 `EvalContext`、`ai call` 和图查询接口读取已记录的执行轨迹，
不按事件类型预先筛掉证据。模型返回结构化结果 `agentprovenance.llm_judge/v1`，
包括 `benign`、`suspicious` 或 `malicious` 判定，以及引用具体证据 ID 的发现。
结果通过 `signal import` 写回，成为关联在图上的分析信号。

轨迹超过上下文预算时，示例会按时间分块评估，再汇总结果，并记录实际处理的
覆盖情况。评估器本身也运行在 `agentprov record` 下：它的模型请求和响应会被
整理为独立执行记录中的 `llm_call` 节点，便于追溯评估结论的来源。

示例支持兼容 Anthropic 或 OpenAI 协议的模型服务，例如 Claude、DeepSeek、
Qwen，以及本地 vLLM/Ollama 服务。未配置 API Key 时会使用离线测试数据完成
流程验证；这不代表真实模型作出的判断。

<a id="web-dashboard"></a>

## 可视化界面

<p align="center">
  <img src="docs/img/dashboard-overview-zh-CN.png" alt="本地证据界面：执行记录选择、验证状态、时间线、进程树、网络外发、风险信号与关联图。" width="100%">
</p>
<p align="center">
  <img src="docs/assets/dashboard-timeline-process-egress.png" alt="本地证据界面：执行记录选择、验证状态、时间线、进程树、网络外发、风险信号与关联图。" width="100%">
</p>


```sh
./agentprov dashboard serve            # http://127.0.0.1:7396
./agentprov dashboard serve --data-dir <dir> --addr 127.0.0.1:7396
```

Dashboard 是本地运行的只读单页界面，用于浏览和查询证据图。
它与 CLI、AI 工具复用内部查询逻辑，HTML 和 JavaScript 内嵌在可执行文件中，
不依赖外部前端资源。

命令行默认使用英文。添加 `--lang zh-CN` 可查看中文帮助和终端输出，例如：

```sh
./agentprov --lang zh-CN --help
./agentprov --lang zh-CN demo
```

显式指定语言时，打开的网页会采用同一语言；未指定时，由浏览器语言决定。JSON 输出、参数名和原始证据保持原样。

首次访问按浏览器语言显示中文或英文，其他语言回退到英文。页面右上角可以切换语言，手动选择会保留。切换后会保留当前执行记录、图视图、展开层级、选中节点和叠加标记。界面说明随语言切换，命令、路径、ID 和原始证据保留原文。

面对大量事件，界面先展示摘要，再按问题逐步展开。
原始遥测仍可查询，但不会一次性全部绘制成图。

```text
原始遥测事件
  -> 提取关键执行证据，构建溯源图
  -> 补充带依据的派生关系
  -> 按分析主题生成视图
  -> 展示图布局、侧栏和原始证据
```

主要功能：

- **执行概览（Run Overview / Ask）**：从“为什么有风险”“哪些文件被修改”
  “外发前后发生了什么”“产物从哪里来”等问题进入对应的局部视图。
- **图浏览器（Graph Explorer）**：`/api/lens` 与 CLI 的 `graph lens` 共用查询接口，
  提供 12 种视图：默认因果、安全、进程树、文件与产物、网络外发、数据流与污点传播、
  Agent 意图、编排、意图一致性、运行环境、信任来源、沙箱边界。
  支持叠加风险和信任信息，并通过分层 DAG 展示节点关系。
- **细节层级**：`summary` 按进程、事件、文件、风险等分组展示概览；
  `expanded` 展开关键证据并过滤低价值噪声；`raw` 用于查看更完整的局部证据。
  `process_group`、`event_burst`、`file_group`、`risk_group`、`egress_group`、
  `intent_group`、`trust_group` 和 `boundary_group` 等分组均可点击展开，原始记录仍然保留。
- **关系与依据**：派生关系（如 `possible_sensitive_data_flow`）使用虚线，
  并附带规则、置信度和证据引用，以区别于直接记录的关系。
  摘要模式会按进程或工具作用域聚合复杂的数据流关系，保留数量和原始证据引用。
  网络外发按 `risky_egress`、`dns`、`loopback`、`tls`、`network` 分类。
- **局部展开**：选中节点后，可通过 `lineage`、`upstream`、`downstream`、
  `children` 和 `raw events` 查看来源、上下游、子节点和原始事件。
  默认调查路径为“概览 → 问题 → 局部图 → 原始事件”，避免整张图过于拥挤。
- **时间回放（Time-scrubber）**：按记录中的时间顺序回放，例如观察凭证读取
  和后续网络连接依次出现。
- **节点侧栏（Side Panel）**：显示节点 ID、命令、PID、路径、目标地址、
  策略与风险、派生规则、置信度、证据引用及哈希。
  产物预览通过 `/api/artifact` 提供，限制内容长度并进行脱敏。
- **相关证据（Focused Evidence）**：通过 `/api/events` 分页展示当前所选问题、
  分组、信号或节点对应的原始事件。选中对象后才加载，便于核对摘要背后的具体记录。
- **执行时间线（Run Timeline）**：按时间顺序查看整次执行的事件；
  与只展示当前选择依据的 Focused Evidence 配合使用。
- **验证与状态**：展示完整性校验、签名、信号、风险、进程树和网络外发信息，
  并支持实时刷新。

<p align="center">
  <img src="docs/img/dashboard-graph-explorer-taint-zh-CN.png" alt="数据流与污点传播视图：根据敏感文件读取和云元数据地址连接推导关联关系。" width="100%">
</p>
<p align="center">
  <img src="docs/img/dashboard-side-panel-preview-zh-CN.png" alt="节点详情：原始证据字段与命令内容预览。" width="100%">
</p>

### Demo：追溯恶意依赖引发的文件读取与网络连接

一个真实的编程 Agent（Claude Code，使用 DeepSeek 后端）在沙箱中开发贪吃蛇
游戏。安装依赖时，它引入了被投毒的 `pysnake-helper`；包的安装脚本随后读取
预先放置的**模拟凭证**，并尝试连接云元数据地址。

原生 eBPF 传感器记录文件访问和网络连接，**数据流与污点传播视图**根据这些证据
展示可能的“敏感文件读取 → 网络外发”关系。
示例在 Linux/eBPF 实验虚拟机中采集，提供已签名的取证包，可在本地离线回放。
以下命令适用于需要保留调查数据的手动导入流程：

```sh
./agentprov --data-dir /tmp/snake-replay forensics import \
  demo/snake-supply-chain/run-snake-supervised.forensics.json.gz \
  --pub-key demo/snake-supply-chain/attestation.pub        # 先验签，再导入
./agentprov --data-dir /tmp/snake-replay dashboard serve   # 选择执行记录 "run-snake-supervised"
```

<p align="center">
  <img src="docs/img/demo-snake-taint-replay.gif" alt="贪吃蛇示例回放：恶意依赖读取模拟凭证，并尝试连接云元数据地址。" width="100%">
</p>

界面操作见[供应链示例指南](docs/supply-chain-demo.md)，
签名包和采集脚本见 [`demo/snake-supply-chain/`](demo/snake-supply-chain)。

> **凭证访问的判定。** 捕获到的凭证访问会记录为 `secret_path` 事件，
> 其中也可能包含 Agent 启动时对自身凭证的正常读取，如 `~/.claude/.credentials.json`。
> 传感器记录系统调用；是否需要告警由上层策略判断。
> 默认的 `self_credential_access` 规则允许已识别的自身凭证访问，同时保留事件记录。
> 对应路径名单可以配置，原始访问记录不会因此被删除。

### Demo：关联多 Agent 的任务委派、协作消息与系统调用

这个示例记录了一个 Agent 团队：主 Agent 将任务分配给子 Agent，
其中一个子 Agent 发出带有恶意指令的协作消息，另一个执行了恶意依赖的安装操作。
应用侧 Hooks 记录任务分工与消息传递，内核遥测独立记录 `openat` 和 `connect` 等行为。

关联后的签名证据图可以用于追查：**消息由谁发出、哪次工具调用执行了操作、
哪些系统调用记录了实际行为，以及对应的风险和响应是什么。**

```sh
./agentprov --data-dir /tmp/multiagent-replay forensics import \
  demo/multiagent-provenance/run-double-attempt.forensics.json.gz \
  --pub-key demo/multiagent-provenance/attestation.pub
./agentprov --data-dir /tmp/multiagent-replay graph verify --run run-double-attempt
./agentprov --data-dir /tmp/multiagent-replay graph lens --run run-double-attempt --lens orchestration
./agentprov --data-dir /tmp/multiagent-replay dashboard serve
```

<p align="center">
  <img src="docs/img/demo-multiagent-orchestration-zh-CN.png" alt="多 Agent 编排视图：主 Agent、子 Agent、协作消息、工具调用与系统调用归属。" width="100%">
</p>
<p align="center">
  <img src="docs/img/demo-multiagent-risk-path-zh-CN.png" alt="云元数据访问的风险路径：运行时事件、策略判定与响应链路。" width="100%">
</p>
<p align="center">
  <img src="docs/img/demo-multiagent-network-egress-zh-CN.png" alt="网络外发视图：多 Agent 执行中的网络行为证据。" width="100%">
</p>

签名包、回放命令和采集过程见 [`demo/multiagent-provenance/`](demo/multiagent-provenance)。
其中包含两次尝试：显式的恶意请求被模型拒绝；随后通过依赖安装触发的行为，
则被内核遥测记录，并关联回 Agent 协作过程。

### Demo：Kubernetes 跨 Pod 调用与事件归属

这个示例将 `alice` 和 `bob` 放到同一 Kubernetes 节点的两个 Pod 中。
`alice` 通过 Pod 网络调用 `bob`，后者执行恶意安装命令，读取模拟凭证并连接
云元数据地址。节点上的一个 `agentprov-sensor` 观测两个 Pod 的 cgroup，
并结合命名空间、Pod 和容器身份，将事件关联到同一份执行记录。

该示例对应 **`k8s-daemonset` 采集模式**。Kubernetes 提供运行位置和容器身份，
核心证据图仍使用通用模型。验收脚本使用真实 DaemonSet、stdout JSONL、
Pod/容器元数据和宿主机 cgroup，无需在工作负载中接入采集代码。
应用侧委派日志复用了多 Agent 示例；跨 Pod 网络与运行时事件则是在本场景中实测采集的。

<p align="center">
  <img src="docs/assets/k8s-cross-pod-a2a-architecture.png" alt="跨 Pod 调用架构：一个节点传感器观测 Alice 和 Bob，将两个 cgroup 的记录关联到同一张证据图。" width="100%">
</p>

<p align="center">
  <img src="docs/img/demo-k8s-a2a-substrate-dashboard-zh-CN.png" alt="Kubernetes 运行环境视图：Alice 到 Bob 的调用关系、各 Pod 的 cgroup 及相关风险。" width="100%">
</p>

回放包、采集脚本和证据范围说明见
[`demo/k8s-cross-pod-a2a/`](demo/k8s-cross-pod-a2a)。
本次记录中的 `secret_path` 和 `metadata_ip` 事件归属于 Bob 的 Pod/cgroup，
Alice 的 Pod 未出现对应事件；图中也保留了跨 Pod 的 `alice → bob` 调用关系。

<a id="graph-命令"></a>

## 证据图命令

以下命令提供类似 Git 的查询方式，用于追溯、比较和验证执行证据：

```sh
./agentprov graph trace --run <run_id>           # 上下文 + 因果 + 风险，一个视图
./agentprov graph verify --run <run_id>          # 完整性：哈希、父链接、证据链
./agentprov graph diff --run <run_id> --file <path>
./agentprov graph blame --run <run_id> --file <path>
./agentprov graph explain --run <run_id> --file <path>   # 有界、分页的因果解释
./agentprov graph lens --run <run_id> --lens data-flow-taint --overlay risk --json
./agentprov graph trajectories --run <run_id> --json     # 给评估器/RL 的证据包
```

其他命令包括：`refs` / `log` / `objects` 用于查看引用、历史和内容寻址对象；
`materialize` / `materialize-llm` 将已有证据整理成图对象；
`replay` 生成重建计划，不直接重做外部操作。
完整用法见[证据图命令说明](docs/zh-CN/graph-commands.md)。

## 当前能力

**采集与接收**

| 能力 | 说明 |
|---|---|
| 无需 SDK 的命令记录 | `record -- <cmd>` 对工作目录做快照、采样进程树，记录文件变化和运行时信息 |
| 批量记录 | `record batch` 并行记录多个作业，供评估、基准测试和 RL 流水线使用 |
| 原生 eBPF 传感器 | 支持 Linux amd64/arm64 的进程执行与参数、网络连接、文件读写、进程退出、权限变更、文件改名/删除和 DNS；包含内核侧噪声过滤 |
| TLS 明文采集 | 支持 OpenSSL `SSL_write` / `SSL_read` 及 `SSL_write_ex` / `SSL_read_ex`；受支持且保留符号的 Go `crypto/tls` 二进制在 amd64/arm64 上支持写入采集，amd64 Go 1.23–1.26 支持读取采集 |
| 模型请求解析 | 将 TLS 分块重组为 HTTP/1.1 消息（含 Content-Length、chunked 和 SSE）或 HTTP/2 消息（含 HPACK 与多流处理），再解析兼容 Anthropic/OpenAI 格式的模型、工具、调用参数和停止原因 |
| 外部事件接收 | 接收 Falco、Tetragon、LoongCollector JSONL 和原生传感器输出，转换为统一事件；执行格式校验，不接受原始事件载荷中夹带的应用上下文 |

原生节点采集支持有容量上限的持久化批次、重启恢复、等待迟到绑定后重试关联、
事务级去重，以及逐项探针能力报告。
具体系统调用和 TLS 范围见[部署与验收指南](docs/zh-CN/amd64-kvm-k3s.md)，
恢复机制见[原生采集缓冲队列说明](docs/zh-CN/native-capture-spool.md)。

**关联与验证**

| 能力 | 说明 |
|---|---|
| 执行上下文绑定 | 关联执行记录、轨迹、作用域、工具调用，以及 process、container、cgroup、PID 等运行身份 |
| 运行时关系 | 使用 `runtime_*` 图关系连接工具调用、进程树、基线状态、事件和文件 |
| 溯源图 | 基于内容寻址对象，提供 `graph trace / refs / log / materialize / objects / verify / replay` |
| 多 Agent 编排 | `hooks bridge` 记录 Agent 节点、任务委派（`agent_spawn`）、协作消息（`agent_message`）和工具调用；同一进程中的子 Agent 共享 cgroup 时，通过命令匹配推断系统调用归属（`agent_syscall`） |
| 模型调用关联 | `graph materialize-llm` 将消息和请求/响应整理为 `llm_message` 对象与 `llm_call` 节点；仅当执行命令与模型响应中的命令匹配时，建立 `llm_caused` 关系 |
| 图视图 | `graph lens` 提供按分析主题组织的视图与 `summary` / `expanded` / `raw` 细节层级；派生关系附带规则、置信度、数量和证据引用，分组可继续展开 |
| 完整性验证 | `graph verify` 校验对象哈希、父子链接，以及“策略 → 风险 → 响应 → 信号”链路 |
| 归属解释 | `telemetry correlations` 显示事件的原始身份、解析出的上下文、匹配绑定、置信度和时间范围 |

图视图的交互与各主题说明见[可视化界面](#可视化界面)。
命令匹配属于有依据的关联推断，不等于为每个子 Agent 分配独立的内核身份。

**查询与观测**

| 能力 | 说明 |
|---|---|
| 时间线 | `timeline [--view causality] [--json]` 合并应用上下文与系统事件，支持分页和完整性校验信息 |
| 覆盖与排查 | `observe summary / coverage / scopes / event / process / flow` 查看关联覆盖、缺口、作用域及事件到响应的链路 |
| 证据解释 | `graph explain` 按文件、产物、进程、事件、工具调用、作用域或风险查询关联路径，并限制结果规模、支持分页 |
| 差异与归属 | `graph diff / blame` 查看文件变化及其执行来源，关联运行时事件和内容对象 |
| 证据清单 | `evidence manifest` 列出一次执行的证据与哈希索引；`--materialize` 可将清单保存为证据对象 |
| 本地可视化界面 | `dashboard serve` 提供执行概览、图视图、相关证据、时间线、验证状态、信号、进程树和网络外发信息 |

**安全与信号**

| 能力 | 说明 |
|---|---|
| 策略、风险与污点传播 | 记录策略判定、风险、隔离与污点传播，检查后续派生对象并判断是否允许响应；`self_credential_access` 规则保留自身凭证访问记录，但不为匹配该规则的行为告警 |
| 历史策略重评估 | `policy rules` 导出可编辑的 YAML 规则；`security reevaluate --run [--rules]` 对已有事件重新评估，支持幂等执行，不修改原始事件 |
| 行为基线 | `baseline learn / check` 比较进程、文件、网络和资源特征，将偏差记录为风险信号 |
| 统一信号 | `signals` 表将行为、成本、质量和安全分析结果关联到图；目前安全与质量分析已有相应的信号来源 |
| 合规映射 | `compliance` 根据 OWASP Agentic 和 NIST AI 相关检查项，报告证据覆盖与缺口 |
| 证据签名 | `forensics export --sign-key` 使用 in-toto/DSSE 和 Ed25519 签名，供后续检测证据是否被篡改 |
| 取证包 | `forensics export[-batch]` 导出包含完整证据集和哈希的审计包 |

**接口与集成**

| 能力 | 说明 |
|---|---|
| CLI / JSON | 面向查询与集成的命令提供 `--json` 输出，并包含相应的结果集或分页完整性信息 |
| 本地服务 API | `daemon serve` 通过 HTTP 提供绑定、事件接收、查询、验证、记录、取证和信号接口，可启用 Bearer Token 认证 |
| AI 工具与 MCP | 通过 `ai call` 和 stdio MCP（`ai mcp`）提供查询、`evaluate_action` 预检和上下文写入 |
| 评估器与 RL | `signal context / import`、轨迹清单与 Python SDK 支持离线批量评估或在执行流程中评分；奖励策略由外部系统定义 |
| 运行环境信息 | 记录 Docker/本地进程元数据、cgroup/PID、文件系统状态、时间范围和保留策略；事件缓冲与查询已有 10 万事件规模的单节点测试 |

## 核心 Demo 验收

核心验收覆盖以下行为：

- 多个执行作用域可以基于同一个初始状态进行比较。
- 原始遥测不需要 `tool_call_id`。
- 分页的 `graph objects` 和 `graph explain` 响应提供稳定的 `result_set_id`
  和每页的 `page_hash` 完整性元数据。
- PID、cgroup、容器和时间窗绑定能够解析出执行上下文。
- 证据图保留 `tool_call -> process -> runtime_event` 的运行时关联链路。
- PID/PPID/TGID 遥测能创建进程树因果边。
- 运行时观测到的 `file_write` 能出现在产生了某个文件差异的同一条轨迹里。
- 运行时观测到的文件事件会创建 `workspace_file/<path>` 图节点，
  并能结合 diff/blame 追溯文件变化。
- 无需 SDK 的进程采样能够识别根进程退出后仍在运行的子进程，
  并保留相应的生命周期记录和策略判定。
- Timeline JSON 展示进程采样产生的 `process_observed` 事件，含 PID、PPID、命令、
  首次/末次出现时间戳、`outlived_root` 和作用域边界元数据。
- 风险事件能生成污点和响应记录；第一阶段不负责最终奖励或轨迹筛选决策。
- `graph diff` 支持统一差异格式（unified diff）和 JSON 输出。
- `graph blame` 说明文件的创建、修改、删除或未变状态及其归属。
- `graph trajectories --json` 为外部评估器输出结构化证据包。

运行：

```sh
./scripts/demo_telemetry_jsonl.sh
./scripts/accept_phase1.sh
./scripts/accept_zero_sdk_realistic.sh
```

## 架构

<p align="center">
  <img src="docs/assets/evidence-flow.svg" alt="AgentProvenance 证据处理流程。" width="920">
</p>

<p align="center">
  <img src="docs/assets/producer-profile-architecture.svg" alt="本地 Linux、KVM 虚拟机与 Kubernetes 共用同一套证据核心和调查界面。" width="100%">
</p>

<p align="center">
  <img src="docs/assets/agentprovenance-architecture.svg" alt="模型意图、应用上下文与系统遥测经过校验和接收处理，形成可验证的溯源图。" width="100%">
</p>

<p align="center">
  <img src="docs/assets/architecture-overview.svg" alt="AgentProvenance 架构总览。" width="920">
</p>

```mermaid
flowchart TD
    Agent["Agent / 运行框架 / 基准测试 / 红队 / RL 流水线"] --> CLI["agentprov CLI"]
    Agent --> ModelIntent["模型意图\n会话记录 / TLS 模型调用 / 拒绝 / 评估"]
    Agent --> Enrich["应用上下文补充\nhooks bridge / MCP 上下文写入"]
    Agent --> Recorder["无需 SDK 的记录器\nagentprov record -- <cmd>"]

    CLI --> Boundary
    ModelIntent --> Boundary
    Enrich --> Boundary
    Recorder --> Boundary
    RuntimeTelemetry["运行时遥测\n原生 eBPF / Falco / Tetragon / auditd"] --> Boundary
    SandboxIdentity["沙箱身份与运行信息\ncontainer / cgroup / PID / cwd / 时间"] --> Boundary
    AppContext["应用上下文\nrun / trajectory / execution_scope / tool_call"] --> Boundary
    ExternalSignals["外部评估信号\n奖励特征 / 惩罚 / 标签 / 质量"] --> Boundary

    subgraph Boundary["API 与事件接收"]
        Daemon["本地服务 API\n控制与查询"]
        Validation["校验与格式统一\n数据结构 / 身份 / 脱敏"]
        Spool["磁盘缓冲 / 背压 / 保留策略"]
    end

    Daemon --> Validation
    Validation --> Spool
    Spool --> Core

    subgraph Core["执行观测与溯源核心"]
        Intent["意图模型\n契约 / 拒绝 / 协作消息 / 模型调用"]
        Correlation["工具调用作用域关联\nPID / cgroup / 容器 / 时间范围"]
        Timeline["执行时间线\n应用上下文与运行时事件"]
        IntentDiff["意图与实际行为比较\n声明 / 偏差 / 覆盖缺口"]
        Causality["运行时关联图\n进程 / 文件 / 网络 / 事件"]
        Provenance["类 Git 溯源图\nrefs / objects / diff / blame"]
        Derivation["关系推导\n派生关系 / 污点传播 / 来源 / 偏差"]
        Lens["图视图\n意图 / 安全 / 进程 / 文件 / 外发 / 污点"]
        Evidence["证据清单\n内容寻址引用 / 哈希"]
    end

    Core --> Intent
    Intent --> Correlation
    Correlation --> Timeline
    Timeline --> IntentDiff
    IntentDiff --> Causality
    Causality --> Provenance
    Provenance --> Derivation
    Derivation --> Lens
    Lens --> Evidence
    Evidence --> Query["证据查询接口\nobserve / timeline / explain / verify / audit"]
    Evidence --> Security["安全分析\n基线 / 策略 / 风险 / 响应 / 取证"]
```

**使用功能前，先检查运行环境实际提供的能力。** 上层功能应根据身份识别、
文件系统、遥测、隔离和恢复能力决定可用范围。例如，只有 Docker 文件系统证据时，
就只提供相应的目录和文件溯源，不能据此声称支持虚拟机内存恢复。

命令记录器、应用上下文、遥测接收器、沙箱适配器和外部评估器结果，均从 API
或事件接收入口进入系统，经过校验、格式统一、身份绑定、脱敏，以及适用的
缓冲、背压和保留处理后，再写入核心证据图。

<a id="基质与遥测"></a>

## 运行环境与遥测

证据模型与具体运行环境分离。不同来源的数据先转换为
[统一遥测格式](docs/zh-CN/telemetry-schema.md)，再参与关联与图构建。
适配新环境时，应优先让采集器输出已有格式和关联信息，复用核心处理流程。

需要区分三个方面：

- **执行环境**：Agent 进程实际运行在哪里。已验证的位置包括本地 Linux、
  KVM 虚拟机内部和容器；AgentProvenance 负责观测，不负责创建这些运行环境。
- **任务编排**：工作负载由谁调度，例如 Kubernetes、Ray、批处理或云平台。
  具体平台能否接入，仍取决于其可提供的身份信息与事件来源。
- **事件来源**：内核与行为数据从哪里获取。主要来源是原生 Linux eBPF 传感器
  （`agentprov sensor stream`）；已有 Falco、Tetragon、LoongCollector 或 auditd
  的主机，也可通过 `telemetry ingest-jsonl` / `ingest-falco` 接收受支持格式的数据，
  并保留包含哈希的批次清单。详见[Falco 接收器说明](docs/zh-CN/falco-receiver.md)。

适配时遵循两项原则：

- **按实际能力报告覆盖范围。** 内核和权限满足要求时才启用对应探针；
  无法采集的路径和降级原因应明确记录。
- **通过关联标识确定事件归属。** cgroup ID、PID、执行记录或作用域 ID 是重要依据。
  在 Linux 上，为每个执行作用域分配独立 cgroup 后，`record` 可将进程子树的
  事件归属到同一次执行，无需原始事件携带 `tool_call_id`。
  缺少精确标识时，只能使用现有证据进行有限关联，并反映相应的置信度或缺口。

这些集成的价值，是把进程、文件和网络行为关联到任务上下文，
为差异比较、来源追溯、污点分析和审计提供依据。

## 边界

项目范围如下：

- 不实现通用沙箱，也不替代 Kubernetes、Ray、OpenSandbox、Firecracker、
  gVisor、Kata 等运行或编排系统。
- 可使用现有事件来源，不要求用原生传感器替换 Falco、Tetragon 或 LoongCollector。
- 不提供模型网关、通用 LLM 调用管理或完整的可观测性平台。
- 第一阶段不提供内存快照、虚拟机瞬时克隆或任意分支的自动合并。
- 不撤销已发生的外部操作。这类动作可以被记录、接受策略检查，或按需关联补偿 Hook。
- 不替 RL 流水线决定奖励、惩罚和轨迹筛选规则，只提供可供评估的行为证据与偏差信号。

产品方向见[产品说明](docs/zh-CN/product.md)，部署方式见
[部署模式](docs/zh-CN/deployment-modes.md)，与其他系统的职责划分见
[项目对比](docs/zh-CN/comparisons.md)。

## 仓库结构

```text
cmd/agentprov/          CLI 入口
cmd/agentprov-sensor/   原生 eBPF 传感器（Linux）
internal/cli/           命令解析与输出
internal/launch/        一键启动入口：执行作用域、可视化界面、临时 Hooks 配置、传感器与降级报告

internal/record/        无需 SDK 的命令执行记录
internal/sensor/        Linux amd64/arm64 eBPF 传感器：进程、网络、文件、权限、TLS 与 DNS
internal/producer/      采集模式定义、cgroup 事件归属与 Kubernetes informer
internal/tlsintent/     TLS 分块与 HTTP 消息重组，模型请求和响应解析
internal/telemetry/     统一事件格式、JSONL 接收、TLS/HTTP 元数据与关联输入
internal/correlation/   ToolCallScope 与运行身份的绑定
internal/provenance/    时间线、溯源图、引用与对象、差异比较、来源追溯、校验、回放与视图
internal/evidence/      精简证据记录与外部操作信息
internal/effects/       外部操作与数据外发记录
internal/redact/        写入存储、生成证据对象和导出前的敏感信息脱敏
internal/security/      策略判定、风险信号、基线偏差与响应动作
internal/signals/       关联到图的统一信号模型：行为、成本、质量与安全
internal/signal/        评估上下文、批量导入与外部评估结果
internal/intent/        意图契约与声明、实际行为之间的差异判定
internal/observability/ observe 查询及其完整性信息
internal/compliance/    OWASP Agentic 与 NIST AI 检查项映射、覆盖率与缺口报告
internal/cost/          资源遥测、Docker stats 采样与指定时间范围内的资源记录
internal/baseline/      行为基线学习与偏差记录
internal/attest/        in-toto/DSSE Ed25519 证据签名与验证
internal/forensics/     证据包导出与可选签名
internal/aitools/       AI 工具定义：证据查询、动作预检与上下文写入
internal/hooksbridge/   Hooks 到 Agent 编排图的映射与命令匹配归属；支持 claude/kimi/codex/grok
internal/mcpserver/     基于统一工具定义的 stdio MCP（JSON-RPC 2.0）服务
internal/daemon/        HTTP /v1 服务与客户端，以及用于提示多进程同时写入的锁文件
internal/dashboard/     本地只读可视化界面，前端资源内嵌于程序

internal/substrate/     运行环境信息与兼容适配器
internal/adapter/       运行环境适配器及其能力注册
internal/control/       供兼容功能使用的运行环境作用域处理
internal/computerapi/   供兼容示例使用的文件与工具 API
internal/envtemplate/   任务与运行环境模板的构建和检查
internal/ports/         本地预览代理

internal/store/         SQLite 表结构与数据访问层
internal/ids/           带前缀的标识符生成
examples/               事件、遥测、策略与集成示例
scripts/                示例脚本与验收工具
docs/                   产品、部署、接口、验收与设计文档
```

核心功能集中在 `record`、`telemetry`、`correlation`、`provenance`、
`evidence`、`security`、`signals`、`cost`、`baseline`、`attest` 和 `forensics`。
`substrate` 包负责表示可供核心使用的运行环境信息。

<a id="roadmap"></a>

## 版本进展与后续计划

**v0.8.2-rc.2 提供开箱即用的回放体验（预发布）。** 下载 Linux/macOS 的
amd64/arm64 包后，直接运行 `agentprov demo`，即可浏览六个回放示例和两个
评估器指南。Demo 首页与阅读页采用与 Dashboard 一致的样式。
详见 [v0.8.2-rc.2 发布说明](docs/releases/v0.8.2-rc.2.md)。

**v0.8.1 增加了可选的外部评估器示例。** [Jev 示例](demo/jev-judge/)通过已有
证据和信号接口展示结构化分析、规则对比与人工复核，不改变核心采集流程。
详见 [v0.8.1 发布说明](docs/releases/v0.8.1.md)。

**v0.8.0 完善了跨环境采集与可靠性。** 增加原生 amd64 支持、KVM 虚拟机部署、
K3s 验收、容器 TLS 自动发现，以及受支持 amd64 Go 二进制的 TLS 响应采集；
改进迟到事件关联、持久化采集恢复、升级测试、数据库就绪检查和事件/证据原子写入。
验证结果及适用范围见[发布说明](docs/releases/v0.8.0.md)和
[部署指南](docs/zh-CN/amd64-kvm-k3s.md)。

后续方向与尚未完成的工作：

- **扩大采集范围**：ARM64 Go TLS 响应、BoringSSL、已移除符号信息或其他尚不支持的
  TLS 二进制，以及更广的网络协议覆盖。OpenSSL `SSL_*` / `SSL_*_ex`、
  HTTP/1.1 和 HTTP/2/HPACK 已实现。
- **持续运行验证**：更长时间的负载测试、真实磁盘故障测试，以及单次执行的覆盖报告。
  现有 10 万事件报告属于单节点基准，不代表生产 SLA。
- **加强证据可信性**：考虑由独立主机签名或在采集时签名。当前哈希和本地签名可相对
  可信检查点检测后续改动，但无法证明已被攻陷的宿主机完整、如实地记录了所有事件。
- **中心化证据服务**：目前[只有设计](docs/zh-CN/central-evidence-service-design.md)。
  多租户、计费、集群调度及 Operator 高可用不在本版范围内。

[v0.7 设计](docs/roadmap-v0.7.md)保留为历史背景，不是当前待办清单。
[收尾标准](docs/zh-CN/project-closeout.md)说明本版单节点功能的交付范围。

## 开发

```sh
go test -race ./...
go vet ./...
gofmt -l internal cmd

# 可在本地运行的端到端证据与验证冒烟测试。
./scripts/accept_phase1.sh
```

[CI](.github/workflows/ci.yml)运行上述检查，并验证 Linux amd64/arm64 静态构建、
原生 eBPF 绑定文件是否与源代码一致、本地服务在故障时的就绪状态，以及
Go 1.23–1.26 下的 amd64 系统调用、OpenSSL 和 Go TLS 采集。
ARM64 实机与 KVM/K3s 实验环境的验收结果另有报告，不等同于托管 CI 的覆盖范围。

各验收脚本的环境要求不同。部分脚本需要 root、会创建 Pod 或安装服务，
请勿直接批量执行全部 `scripts/accept_*.sh`。
环境测试请按 [KVM/K3s 部署指南](docs/zh-CN/amd64-kvm-k3s.md)操作，
单节点压力测试见[收尾指南](docs/zh-CN/project-closeout.md)。

## 作者与许可

由 [ByteYellow](https://github.com/ByteYellow) 开发和维护。

采用 Apache License 2.0 许可证，详见 [LICENSE](LICENSE)。
Copyright 2026 ByteYellow。

---

> 本文为 [README.md](README.md) 的中文说明；如有内容差异，以英文版为准。
