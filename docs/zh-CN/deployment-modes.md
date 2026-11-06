# 部署方式

[English](../deployment-modes.md) · 简体中文

AgentProvenance 可以从本地命令开始使用，无需先部署一套平台。现有实现支持命令行记录和本地服务；中心化服务目前只有设计。

## 首次体验：下载后回放

[v0.9.0 版本](releases/v0.9.0.md)提供 Linux 和 macOS 的 amd64、arm64 命令行压缩包。运行 `agentprov demo` 可打开本地示例首页，其中包括七份经过验证的签名记录和两个可选评估器指南。阅读页与 Dashboard 使用相同的视觉风格，支持目录、图片、表格和代码复制。

具体步骤见[快速开始](../../README.zh-CN.md#快速开始)和[示例目录](../../demo/README.zh-CN.md)。网页首次访问跟随浏览器语言，其他语言回退到英文；手动选择后会记住偏好。终端默认英文，使用 `--lang zh-CN` 可选择中文。

回放使用独立的临时数据目录，不会重新执行记录中的操作。实际运行评估器或 Linux 传感器仍需满足各自的环境要求。四个平台的发行包验收检查回放和清理，不代表增加了实时传感器覆盖，也不代表完成了长期运行测试。

## 1. 仅用命令行记录

适用于强化学习（RL）、基准测试、离线评估、CI 和本地红队测试。流程如下：

```text
Agent / 评估器 / 批处理任务
  → agentprov record -- <command>
  → 本地 SQLite + 内容寻址对象
  → 证据清单 / EvalContext / 执行轨迹信号
```

此模式的功能和使用方式：

- 一个 Go 可执行文件即可运行，无需常驻服务或接入特定 Agent 框架。
- Python 辅助包可选，可在仓库目录通过 `pip install -e .` 安装。
- 默认记录进程、文件差异、产物、退出状态、资源用量和运行摘要。
- Linux 上可配合节点级 `sensor stream` 使用。记录器创建真实 cgroup，子树中的内核事件通过 `cgroup_id` 关联到执行记录。
- 每条执行轨迹可以使用独立的 `run_id`。
- `agentprov record batch --file jobs.jsonl --json` 为一组轨迹生成 `agentprovenance.record_batch/v1` 批次清单。
- `agentprov evidence batch-summary --shard/--job/--run` 查询已保存的批次状态，流水线无需解析终端日志。斜线分隔的参数表示可选查询条件，实际使用时按需指定。
- `agentprov signal batch-context --batch/--shard/--runs` 将选中的轨迹导出为 EvalContext JSONL，供奖励计算、过滤和基准测试使用。
- Python 的 `Registry` 和 `@rule` 支持定义离线评估函数。函数返回 `EvalSignal`，可表示奖励特征、惩罚项、数据集标签或质量信号。
- `run_batch_pipeline(...)` 串联批量记录、导出 EvalContext、运行 Python 规则、导入 EvalSignal、导出批次取证包并返回摘要。
- `agentprov signal import-batch --file reports.jsonl` 校验并导入 JSONL 格式的 EvalReport，避免逐条调用导入命令。
- `agentprov forensics export-batch --batch/--shard/--latest` 导出带 SHA-256 校验的批次审计包，包含批次摘要、各执行记录的取证引用、可选 EvalContext，以及回放和查询命令。
- 输出支持 JSON，便于批处理程序消费。

此模式不提供共享查询、中心化留存或跨主机遥测汇总。调度、奖励、排序和数据集策略仍由使用方的流水线决定。拒绝执行、终止、隔离和污点标记等在线安全控制按需启用，不是 RL 接入的前提。

没有启用传感器时，记录器使用合成作用域标识，并记录进程和文件证据。这是基础记录模式的正常行为；它不具备内核级事件覆盖。

## 2. Sidecar 或本地服务

适用于沙箱工作节点、CI 工作节点、本地安全测试，以及需要本地接收和查询 API 的团队。流程如下：

```text
Agent / 沙箱工作节点 / CLI / SDK
  → 本地 agentprov daemon
  → 磁盘缓冲队列 / 背压 / 保留策略
  → 本地查询 / 图校验 / 取证 API
```

本地服务负责 SQLite、对象存储、关联、策略、风险、响应、图校验、取证导出和遥测缓冲队列。CLI 和 Python 辅助包作为客户端使用。

原生 `sensor stream` 可在节点上与服务或本地存储一起运行，经过同一套标准化和关联流程写入事件。队列分别限制批次数、总字节数和单批字节数。`telemetry producer-health` 报告队列状态、丢弃计数、来源计数和关联覆盖率。本地 API 提供时间线、图解释、安全证据、证据清单、取证导出和信号导入。

Kubernetes 的两项接入能力：

- `accept_k8s_node_multiworkload.sh` 验收实际运行的传感器 DaemonSet。脚本构建并导入镜像，部署传感器，将 Pod、容器元数据对应到内核 cgroup，接收标准输出中的 JSONL，并校验证据图。工作负载数量可配置。
- `agentprov sandbox watch` 使用 `client-go` informer，只列举和监听分配到本节点的 Pod。它在容器重启和 Pod 删除时更新容器到 cgroup 的绑定，仅需要 Pod 的 `get/list/watch` 权限。

这仍是本地优先的部署方式，不是多租户中心服务。工作节点旁可以直接部署，无需 Kubernetes 或中心数据库。现有 K8s 验收覆盖单节点传感器、多工作负载被动归属和 informer 生命周期；完整 Operator、CRD、高可用与主节点选举、升级控制、集群级证据服务尚未实现。

KVM 虚拟机与 K3s 的 systemd 采集服务、节点事件归属配置见[部署指南](amd64-kvm-k3s.md)。KVM 虚拟机使用 `local-record`，传感器观测的是虚拟机内部的内核。

原生采集的重启恢复规则见[持久缓冲队列说明](native-capture-spool.md)。旧版 JSONL/Falco 队列工作进程不因此获得相同的恢复保证。不要让两个采集器将同一批观测重复写入同一个存储。

`/v1/live` 检查 HTTP 服务是否存活；`/v1/ready` 和 `/v1/health` 检查数据库及表结构是否可用。存储失败时，无法读取的计数保持 `null`。服务就绪状态与历史证据覆盖率是两回事，这些接口也不能证明每个后台工作进程都在推进。

### API 鉴权与浏览器访问

`daemon serve` 默认要求 Bearer token。服务复用或生成 `<data-dir>/auth-token`，文件权限为 `0600`；也可以通过 `--auth-token` 或 `AGENTPROV_DAEMON_TOKEN` 指定自管 token。CLI 客户端需要使用相同的 `--data-dir`，或显式设置 `AGENTPROV_DAEMON_TOKEN`。只有 GET `/v1/health`、`/v1/ready`、`/v1/live` 三个健康检查接口允许匿名访问。

带正文的写请求必须使用 `Content-Type: application/json`；空体 DELETE、POST 可以省略该头。浏览器请求的 Origin 必须匹配，写请求的 `Sec-Fetch-Site` 仅接受 `same-origin`、`none` 或缺省。Origin 检查依据直接连接的 HTTP/TLS 状态，不信任请求中的 `X-Forwarded-*` 头。已鉴权的 CLI、SDK 可以通过远程地址或自定义域名访问，无需发送浏览器专用头。

`--insecure-open` 显式关闭鉴权。此时，除健康检查外，所有请求的 Host 都必须是 localhost、IP 字面量或 `--listen` 配置的主机名；读写接口都会拒绝其他域名。此模式仅用于可信的本地开发环境。

物化证据清单使用 `POST /v1/evidence/manifest`，JSON 正文为 `{"run_id":"<run_id>"}`。普通 GET 保持只读。旧的 `GET ...?materialize=1` 形式需要有效 Bearer token；开放模式下应迁移到 POST。CLI 的 `evidence manifest --materialize` 已自动使用新调用方式。

### Docker 会话兼容配置

兼容命令 `lease`、`session`、`api` 使用 Docker 工作区。Linux 和 macOS 上，新建和恢复的会话默认采用 CLI 或后台服务进程的有效 UID:GID，覆盖镜像中的 `USER`。这样既能写入挂载的工作区，也无需恢复 `CAP_DAC_OVERRIDE` 或向所有用户开放工作区写权限。默认的非 root 用户使用容器内的 `HOME=/tmp` 存放缓存；依赖安装到工作区的虚拟环境或项目目录。所有 Linux capability 继续移除，`no-new-privileges` 继续启用。

特殊镜像可在任务 YAML 中设置 `user: "1000:1000"`，也可以使用镜像内的用户名。显式指定用户时保留镜像的 home 环境，该用户的 UID:GID 需要具备工作区访问权限。使用 rootless Docker 或用户命名空间映射时，应选择映射到工作区所有者的容器身份；rootless 服务所有者的文件通常对应 `user: "0:0"`。需要 root 的系统依赖应在构建镜像时安装。

Docker 29.0-29.2 最低要求 API 1.44，当前内置客户端默认最高使用 1.43，详见 [Docker API 版本表](https://docs.docker.com/reference/api/engine/#api-version-matrix)。连接这些服务时，为兼容命令设置 `DOCKER_API_VERSION=1.44`；会话创建、执行和清理已在 Docker 29.1.3 上按此配置验收。该设置会关闭 API 版本协商，只在服务端需要时使用。常规 `record`、`launch` 和回放不使用这个 Docker 会话客户端。

## 3. 中心化证据服务：仅有设计

面向多节点的共享安全调查、审计、SRE、合规和事件复盘。当前版本未实现，组件职责、故障处理、容量指标和信任假设见[中心化服务设计](central-evidence-service-design.md)。

```text
多个工作节点 / Sidecar / 采集器
  → 中心化证据接收
  → 对象存储 / 保留策略 / 授权
  → 查询 API / 界面 / 审计导出
```

设计目标包括共享接收和查询、内容寻址对象与取证包存储、保留策略、认证授权、租户隔离和审计控制。可对接 Falco、Tetragon、LoongCollector、Webhook、飞书、钉钉、CI 及企业安全流程。

它应复用本地模式的证据格式和图约束，但需要单独的产品化工作，不能将本地 CLI 的行为直接视为中心化服务保证。多租户、计费和复杂集群控制平面不在当前实现范围内。

## 共用的数据模型

三种部署形态使用同一套证据模型：

```text
执行上下文
  → 接收证据
  → 运行时因果图
  → Git 风格的溯源有向无环图
  → 证据查询 / 风险分析 / 回放 / 审计
```

部署边界随使用场景变化。RL 和评估任务可以一直使用命令行模式；需要共享运维时，再考虑本地服务或未来的中心化服务。
