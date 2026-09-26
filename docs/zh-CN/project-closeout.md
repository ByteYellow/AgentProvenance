# 当前版本的收尾标准

[English](../project-closeout.md) · 简体中文

本文界定项目当前的工程交付范围，不把虚拟化平台或中心化 SaaS 纳入这一阶段。文中的实测数据来自已保存的实验室验收报告，不表示每次文档更新都重新执行过对应环境测试。

## 首次体验：下载后回放

[v0.8.2-rc.2 预发布版](releases/v0.8.2-rc.2.md)提供 Linux 和 macOS 的 amd64、arm64 命令行包。`agentprov demo` 打开本地示例首页，包含六份经过验证的签名记录和两个可选评估器指南。阅读页支持目录、图片、表格和代码复制，并与 Dashboard 保持一致的视觉风格。

步骤见[快速开始](../../README.zh-CN.md#快速开始)和[示例目录](../../demo/README.zh-CN.md)。回放使用独立临时存储，不执行记录中的操作。运行评估器或实时 Linux 采集仍需满足各自的环境要求。四个平台的压缩包验收检查回放与清理，不代表额外的实时采集覆盖或长期运行验证。

## 已实现的运行环境配置

当前支持本地 Linux、KVM 虚拟机和 Kubernetes Pod，使用 `local-record` 与 `k8s-daemonset`。同一套证据模型既接收包装启动的进程，也接收通过内核 cgroup 身份归属的外部调度 Pod。

KVM 传感器运行在虚拟机内部，观测来宾内核。它不依赖宿主侧虚拟机内省，也不需要另一套证据图模型。

[amd64/KVM/K3s 部署指南](amd64-kvm-k3s.md)和[已保存的实测报告](../benchmarks/amd64-kvm-k3s/README.zh-CN.md)涵盖系统调用与 TLS 采集、虚拟机服务、正常重启、Pod 迟到归属、导出导入、本地与 Pod 的语义一致性，以及升级后的证据保留。这些是有明确环境范围的验收，不是所有内核或虚拟化软件的兼容认证。

## 单节点规模要求

本阶段要求证明：

- 一个节点传感器可以观测多个独立工作负载。
- 队列同时受批次数、总字节数和单批字节数限制。
- 接收支持批处理、持久缓冲、背压和明确的溢出计数。原生采集在达到容量时拒绝新数据；旧版 JSONL 上传队列提供 `reject` 和 `drop_oldest` 策略。
- 生产者健康报告包含已接收、已处理、失败、已丢弃的批次，排队字节数、传感器丢弃数、事件来源计数和关联覆盖率。
- 10 万事件验收生成机器可读报告，包含吞吐量、健康与查询延迟 p50/p95/p99、服务 CPU 和 RSS 峰值、队列状态、丢弃情况、最终事件数及覆盖率。
- 证据查询保持有界，证据图校验结果保持一致。

压力报告是实测基线，不是生产 SLA。不同机器的延迟和吞吐量可能不同。

### 10 万事件基线

2026 年 8 月 4 日在 macOS 开发机上导入 100,000 条合成 Falco 事件，全部写入，失败和丢弃批次均为零。健康查询 p95 为 1.209 毫秒，分页查询 p95 为 9.182 毫秒，服务峰值 RSS 约 55 MiB，队列从接收至处理完成的吞吐量为每秒 134.14 个事件。

该结果满足当时的查询与内存收尾要求。吞吐量表示本地 SQLite 的实际基线，不应表述为生产流式处理能力。简明报告见 [telemetry-100k-macos-arm64.json](../benchmarks/telemetry-100k-macos-arm64.json)。

### 一个传感器观测多个 Pod

最早的 Kubernetes 节点验收于 2026 年 8 月 5 日在 arm64、Ubuntu 6.8 实验虚拟机及单节点 K3s 上完成。脚本构建并部署真实的特权传感器 DaemonSet，接收标准输出 JSONL，将 Pod 和容器身份对应到内核事件中的 cgroup，关联 8 个独立调度的 BusyBox Pod。

当时观测到 8 个不同的 cgroup，写入 1,140 个 Pod 作用域事件，`graph verify` 为零错误、零警告。它验证的是节点级部署形态，不是集群吞吐基准。

amd64 KVM/K3s 验收重复了该流程：8 个工作负载、8 个 cgroup、1,289 个事件，图校验同样为零错误、零警告。[简明报告](../benchmarks/amd64-kvm-k3s/k3s-multiworkload.json)已入库，原始流和大型采集文件保留在 Git 之外。

### 容器绑定生命周期

轻量归属控制器在同一节点、K3s 1.36.2 环境下单独验收。经过节点过滤的 `client-go` informer 建立首个容器绑定，观测同一 Pod UID 下的真实容器重启，关闭旧绑定并建立新绑定，最后在 Pod 删除后关闭新绑定。

最终创建 2 个绑定、关闭 2 个绑定，活跃绑定为 0，发生 1 次重启，重试、失败和解析失败均为 0。这证明节点级生命周期处理有效，不代表 Operator 高可用或多节点共享状态已经实现。

### 本地记录与 Pod 采集的语义一致性

2026 年 8 月 5 日在同一 arm64 K3s 节点上，将 `id + ls /` 工作负载分别放入主动创建的 `local-record` cgroup，以及由 `k8s_cgroup` 被动归属的外部调度 Pod。

两张图的校验均为零错误、零警告。比较的公共语义包括两个工作负载命令、`execve` 事件、`runtime_event` 节点和 `runtime_process_event` 关系。PID、cgroup、容器、时间戳和事件数量等物理差异不参与等价判断。本地绑定置信值保留 1.0/0.9，Kubernetes 绑定保留 0.8。

[amd64 一致性报告](../benchmarks/amd64-kvm-k3s/k3s-parity.json)在 KVM 虚拟机内重复了同一比较。这里的等价是公共工作负载和运行时关系的语义一致，不是整张图完全相同：主动记录比被动 Pod 采集多一些应用上下文。

## 可靠性保证及限制

原生 `sensor stream` 将已接收批次持久化，重试迟到绑定，并恢复中断的处理。[缓冲队列约定](native-capture-spool.md)明确容量、事务去重、文件缺失报告和丢失计数。Falco 专用工作进程的恢复不在该保证内；两条路径共用的单事件接收仍是原子的。

`/v1/live` 报告 HTTP 服务存活状态；`/v1/ready` 和 `/v1/health` 检查存储和表结构。数据库失败返回 503，无法读取的计数为 `null`。历史丢失与数据库就绪分别展示，不能由此推断工作进程正在推进或每次执行证据完整。

实验室验收确认升级和虚拟机正常重启保留了检查范围内的历史证据。宿主突然断电、真实磁盘耗尽和持续多日运行仍属于单独的运维验收，不能由单元测试通过推导出来。

## 中心服务边界

中心化证据服务目前只有[架构设计](central-evidence-service-design.md)，尚未实现：

- 多租户或计费。
- 通用集群控制平面。
- 调度器或沙箱生命周期平台。
- 分布式全序或恰好一次交付。
- 面向生产的对象存储、索引存储部署。

## 验收命令

```sh
go test ./...
./scripts/accept_telemetry_spool_backpressure.sh
AGENTPROV_ACCEPT_100K_REPORT=/tmp/agentprov-100k.json \
  ./scripts/accept_telemetry_100k_pressure.sh

# Linux/Kubernetes 环境验收，默认运行 8 个工作负载。
AGENTPROV=/path/to/agentprov SENSOR=/path/to/agentprov-sensor \
  AGENTPROV_MULTIWORKLOAD_REPORT=/tmp/agentprov-k8s-multiworkload.json \
  ./scripts/accept_k8s_node_multiworkload.sh

# Linux/Kubernetes informer 生命周期验收。
AGENTPROV=/path/to/agentprov \
  AGENTPROV_K8S_INFORMER_REPORT=/tmp/agentprov-k8s-informer.json \
  ./scripts/accept_k8s_informer_controller.sh

# 同一工作负载在本地与 Kubernetes 下的语义一致性验收。
AGENTPROV=/path/to/agentprov SENSOR=/path/to/agentprov-sensor \
  AGENTPROV_K8S_PARITY_REPORT=/tmp/agentprov-local-k8s-parity.json \
  ./scripts/accept_k8s_pod_parity.sh
```

Kubernetes 一致性验收需要实际环境。更新已验证基线时，提交简明且已去除敏感信息的报告；原始采集和凭据留在 Git 之外。原生恢复、TLS 发现和服务故障验收见[部署指南](amd64-kvm-k3s.md)。新的运行环境配置也必须通过等效实机验收，才能标为 `validated`。
