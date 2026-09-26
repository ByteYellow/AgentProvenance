# amd64／KVM／K3s 验收记录

[English](README.md) | 中文

这些报告于 2026-09-19（Asia/Shanghai）在基于 `fc2e626` 的本地工作分支上生成，记录两个指定内核上的实机验证。它们不能代替托管 CI 结果，也不代表所有 Linux、内核和 TLS 组合均已通过。

- `sensor-live-wsl.json`、`sensor-live.json`：WSL 和 KVM 客体上的 26 项检查；测试暂停用户态读取期间，内核探针仍继续工作。
- `kvm-service.json`、`kvm-after-reboot.json`：限定范围的服务摄入、图校验，以及导出后导入全新存储。两份报告的启动标识不同。
- `k3s-continuous.json`、`k3s-after-reboot.json`：Pod 事件通过 informer 绑定进入共用节点存储；删除 Pod 后关闭绑定。
- `k3s-multiworkload.json`：一个真实传感器 DaemonSet 观测 8 个独立调度的工作负载，并通过图校验。
- `k3s-parity.json`：本地 record 和 Pod 的规范化执行、图语义一致，同时保留不同的归属置信等级。
- `k3s-informer.json`：容器重启后重新绑定，删除 Pod 后两代绑定均关闭。
- `environment.json`：记录基线提交、分支、KVM 实际启用情况、二进制哈希，以及未改动的 ARM64 对象哈希。

本地交付目录另保留测试用 JSONL、导出包和校验日志。虚拟机私钥及 cloud-init 凭据未提交到仓库。复现步骤与限制见[部署指南](../../zh-CN/amd64-kvm-k3s.md)。

## 原生采集与容器 TLS 的后续加固

以下报告来自同一适配分支的后续工作，前述报告仍保留原始基线：

- `sensor-live-hardening-wsl.json`、`sensor-live-hardening-kvm.json`：27 项实机检查，含暂停用户态读取时的 Go TLS 响应明文采集。
- `container-tls.json`：三种容器各重建一次，共两代实例，完成 30 项检查。自动发现能为每个容器采集恰好一个请求和响应，覆盖 Go、OpenSSL 旧接口和 OpenSSL `_ex`，包括共享 overlay 库。
- `node-capture.json`：立即退出的 Pod 先于 informer 绑定产生事件；两次采集器崩溃检查持久化恢复、已关闭区间的历史归属、图校验、执行记录隔离和事件标识稳定性。
- `kvm-service-hardening.json`、`k3s-continuous-hardening.json`、`k3s-informer-hardening.json`：升级已安装的采集器和控制器，检查证据导入导出，以及容器重启、Pod 删除的生命周期。
- `upgrade-hardening.json`：使用 `3093335` 构建并冻结的存储从格式版本 15 升级到 16，导入的历史证据行保持不变；同时记录采集器存活、队列状态和二进制哈希。另一份在线快照比较未能得出结论：制作快照时，旧采集器仍在插入和删除未关联行。

这些验收不能证明多日持续运行稳定，也不能证明探针挂载前已采集到 TLS 明文。TLS 测试工作负载会等待 6 秒，供自动发现完成挂载。WSL 还使用 Go 1.23.12 和 Go 1.26 检查了 TLS Read 并发和栈增长：32 条连接的返回字节完全一致，测试后未残留上下文。

## 正确性与可靠性收尾

以下报告来自下一轮正确性检查。Falco 的旧导入器和 worker 保持原样；原生采集的恢复保证不能直接套用于该兼容路径。

- `node-capture-completion.json`：格式版本 17 和事务内关联的 13 项迟到归属／崩溃恢复检查全部再次通过。
- `daemon-readiness-completion.json`：11 项真实 HTTP 检查，包含不兼容格式、缺表、恢复、无需认证的健康接口、受保护的普通路由，以及存在历史丢失但数据库当前可用的情况。
- `upgrade-completion.json`：先停止全部写入者，再制作格式版本 16 的快照。升级到 17 后，9,500 行历史事件全部一致；客体正常完整重启后再次一致。报告包含两次启动标识和已安装二进制的哈希，不模拟宿主机突然断电。
- `kvm-completion.json`、`kvm-reboot-completion.json`：重启前后检查已安装服务的采集、图校验和证据包导入导出。
- `k3s-completion.json`、`k3s-reboot-completion.json`：跨重启检查 Pod 被动归属、事件摄入、绑定关闭和图校验。
- `informer-completion.json`：重启创建第二个绑定，删除后两个绑定均关闭；保存的状态中，重试和协调失败均为 0。

当时完整的 `go test -race -p 4 ./...`、`go vet ./...`、格式检查和第一阶段验收均通过。独立的就绪检查已纳入 CI。这些是本地验收结果；托管 CI 状态和产物由 GitHub Actions 另行报告。

本地还使用 Go 1.24.0 和 1.25.0 测试 TLS Read：各自 32 条并发连接、71 个片段的返回字节完全一致，没有丢弃或残留上下文。结合此前的 1.23.12／1.26 结果，覆盖了声明支持的四个次版本，不代表每个补丁版本都已验证。

## 实现与回归依据

| 问题 | 实现 | 回归检查 |
|---|---|---|
| 混合时间格式按字符串排序 | `correlation.resolveWindow` 解析候选时刻，并保留证据中的原始字符串 | `TestResolveWindowComparesInstantsWithoutRewritingEvidence` |
| 同一批次内的退出事件无法被后续关联读取 | `NativeStream.processBatch` 和严格摄入路径使用证据事务解析归属 | `TestNativeBatchObservesItsOwnProcessExit` |
| 数据库状态未知却报告正常 | `daemon.health` 返回 503，未知计数为 null；`/v1/live` 单独报告存活 | `TestHealthFailsWhenDatabaseUnavailable`、`TestHealthFailsWhenRequiredTableMissing`、HTTP 就绪验收 |
| 已接收的采集文件丢失后被静默遗忘 | 区分 `initializing` 和 `capturing`，保留并报告文件缺失的采集元数据 | `TestNativeMissingCaptureFileIsNotSilentlyForgotten`、`TestNativeUninitializedBatchRecoveryAcceptsNewCapture` |
| 规范化后产生过大、无法重放的行 | 接收前检查规范化后的编码大小，持久保存超限丢弃计数 | `TestNativeNormalizationCannotCreateAnUnreplayableRow` |
| 清理失败阻塞采集器重启 | 将已完成载荷的清理留到运行中的有界扫描，继续计入容量 | `TestNativeRestartDefersCleanupFailureWithoutBlockingCapture` |
| 旧程序修改不支持的较新数据库 | 执行迁移 DDL 前拒绝打开较新格式 | `TestNewerSchemaIsRejectedBeforeMigrationWrites` |
