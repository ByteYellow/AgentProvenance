# Kubernetes Pod 自动归属设计

[English](../design-k8s-auto-attribution.md) · 简体中文

单次采集、真实传感器 DaemonSet 和轻量 `client-go` Pod informer 控制器均已实现。控制器的创建、重启和删除绑定流程已在单节点 K3s 验收。完整 Operator、高可用与主节点选举、集群级证据服务尚未实现。

## 要解决的问题

传感器通过 `deploy/k8s/agentprov-sensor-daemonset.yaml` 部署在节点上，输出 JSONL。需要将事件中的内核 cgroup 身份对应到 Pod、容器及执行记录。

`sandbox capture` 将单个 Pod 的采集、绑定和导入合并为一条命令。`sandbox watch` 列举并监听 Pod 元数据，为运行中的容器维护被动归属绑定。`scripts/accept_k8s_node_multiworkload.sh` 则独立验证：一个真实 DaemonSet 观测多个 Pod，将 Kubernetes 身份对应到内核流中的 cgroup，最后在同一执行记录中校验相关证据。

这些流程复用已有实现：

- `internal/sensor/sensor_linux.go` 中的 `cgroupResolver` 从 cgroup 目录解析容器标识，例如 `kubepods/<uid>/…<container-id>`。
- `producer.BindCgroupScope` 和 `correlation.RecordBinding` 写入来源为 `k8s_cgroup`、默认置信值为 0.8 的绑定，无需新增数据模型。
- 服务的 `POST /v1/telemetry/*` 接口接收遥测事件。
- `bind-cgroup` 将 Pod 元数据记录为上下文事件。

剩余的平台化工作主要是高可用、升级编排和多节点共享状态，不属于此节点级控制器。

## 第一阶段：单次采集

`agentprov sandbox capture` 为一个正在运行的 Pod 完成有限时间的采集，需显式提供传感器路径：

```sh
agentprov sandbox capture --pod <name> --namespace <ns> \
  --sensor /path/to/agentprov-sensor \
  [--run <id>] [--seconds 45] [--kubectl "k3s kubectl"]
```

方括号表示可选参数，实际命令中不要输入方括号。

执行步骤：

1. 扫描 `/proc/*/cgroup` 查找 Pod 进程，或使用 `--pid` 指定进程。根据 cgroup 目录 inode 获取内核关联标识，并通过 kubectl 读取命名空间、UID、节点、容器、镜像、ServiceAccount、标签和 Pod IP。
2. 启动独立传感器，在 `--seconds` 指定的时间内将节点事件写入文件，然后按目标 Pod 的 cgroup 过滤。当前命令不复用既有 DaemonSet 的队列。
3. 写入 cgroup 绑定和 Pod 元数据，将过滤后的事件导入指定执行记录。
4. 输出采集数量、导入数量、执行标识和归属置信值。

这将原先的多步手工流程收敛为一条命令，不需要改动 eBPF 探针。

## 第二阶段：持续维护绑定

`agentprov sandbox watch` 是与传感器配合的节点级控制器：

1. 使用经过节点过滤的 `client-go` informer，只 List/Watch 调度到本节点的 Pod；可增加标签选择条件，仅需 Pod 的 `get/list/watch` 权限。
2. 根据 Pod UID 和容器标识解析宿主 cgroup 树，使用同一套 `BindCgroupScope` 和元数据补充流程建立绑定。
3. 传感器事件携带 `cgroup_id`，独立的接收流程据绑定将事件归入对应执行记录。

自动归属需要传感器、控制器和使用同一证据存储的接收流程配合。只部署传感器 DaemonSet 不会自动启动全部流程。节点部署方式见[amd64/KVM/K3s 指南](amd64-kvm-k3s.md)。

Pod 注解 `agentprov.io/run: <id>` 可选择目标执行记录；没有注解时，控制器默认使用 Pod UID 生成带 `auto-` 前缀的执行标识。

控制器使用 cgroup inode 作为内核关联键，PID 作为补充证据。容器重启时关闭准确的旧绑定并建立新绑定，Pod 删除时关闭剩余绑定。旧版 kubectl 轮询实现保留为隐藏命令 `sandbox watch-poll`，仅用于诊断和兼容。

仓库的 Go 基线为 1.23，依赖 `client-go v0.32.0`。Pod core/v1 List/Watch 路径已在 K3s 1.36.2 实测；这只是一个经过验证的兼容点，不代表所有 Kubernetes 次版本均已覆盖。

## 范围

- 复用核心、图和数据格式。
- 负责观测后的归属，不承担调度或运行前阻止。
- TLS 模型意图采集是独立能力，其挂载范围与限制见[传感器说明](ebpf-sensor-plan.md)。

## 验收依据

- 单次采集：没有经过 `record` 启动的 Pod 也能被归属，图校验错误数为零。
- 节点 DaemonSet：`accept_k8s_node_multiworkload.sh` 默认启动 8 个 Pod，将元数据对应到内核 cgroup，并要求图校验零错误、零警告。最早的 arm64 参考结果为 8 个 cgroup、1,140 个事件；amd64 结果见[已保存报告](../benchmarks/amd64-kvm-k3s/k3s-multiworkload.json)。
- informer 生命周期：`accept_k8s_informer_controller.sh` 部署控制器，创建带注解 Pod，强制同一 Pod UID 下的容器重启，最后删除 Pod。参考结果创建 2 个绑定并全部关闭，记录 1 次重启，活跃绑定为零，重试、失败和解析失败均为零。
- Pod 事件先于绑定到达时的暂存和重试属于原生接收流程，具体限制见[持久缓冲队列](native-capture-spool.md)。
