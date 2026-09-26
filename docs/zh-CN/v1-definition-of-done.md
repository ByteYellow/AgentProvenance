# AgentProvenance Infra v1 完成标准

[English](../v1-definition-of-done.md) | 中文

> 本文保留历史发布范围和验收结论。范围于 2026-06-27 确定，状态表于 2026-08-05 结合仓库检查和已完成验收更新。它将当时 `north-star-three-pillars.md` 的设想转为可检查清单，不代表当前正式版的发布验收。当前交付边界见[项目收尾标准](project-closeout.md)，中文适配进度见[中文适配与正式版验收](localization.md)。
>
> 状态分为已完成（`DONE`）、部分完成（`PARTIAL`）和延后（`DEFERRED`）。延后项目明确移出 v1，列入 v2。

## 0. v1 的核心取舍

项目的核心价值是将**关联能力转化为可校验、可查询的证据图**。v1 面向已有用户的两种部署方式：库／CLI 和边车服务。工作重点是加固现有实现并准确说明边界。当时，证据图涉及的存储、摄入、关联、观测、溯源、风险和取证能力已有实现，并经过实际二进制运行验证。

### 完整性声明的边界

v1 声明的是**完整性校验能力**。`graph verify` 从本地 SQLite 重新计算哈希，能够发现意外损坏、对象哈希不匹配和父链断裂。但拥有宿主机 root 权限的攻击者可以修改数据库并重算链，因此不能据此声称能识别此类攻击者的全部篡改。

要在采集时建立主机外的可信锚点，需要 KMS、TPM 或透明日志等机制。这属于第 3 节的 v2 工作。v1 不应宣传为能抵御恶意宿主机 root 的防篡改证据系统。

## 1. v1 包含的能力

下表源于 2026-06-27 的检查，并按页首所述日期更新。代码路径在未注明时相对于 `internal/`。

| 编号 | 领域 | 当时状态 | 依据：文件或符号 |
|---|---|---|---|
| 1 | 数据接收：磁盘缓冲、背压、丢弃 | 已完成 | `telemetry/spool.go` 限制批次数、总字节数及单批字节数；支持 `reject\|drop_oldest` 和 HTTP 429；`telemetry producer-health`；压力与缓冲验收脚本 |
| 1 | 采集器进程独立 | 延至 v2 | `cmd/agentprov-sensor` 是独立生产者；部署方式 1、2 的摄入仍在服务进程内。完整的进程级数据接收隔离随部署方式 3 处理 |
| 2 | 服务端处理关联、策略、风险、响应和校验 | 已完成 | `daemon/server.go` 的 `/v1` 路由 |
| 2 | CLI 作为服务客户端 | 延至 v2 | 查询可经过服务端，部分本地优先的写入仍在进程内执行。WAL 和服务锁明确了部署方式 1、2 的并发边界；仅允许服务端写入属于部署方式 3 |
| 2 | 稳定的 JSON 格式 | 满足 v1 范围 | 核心 JSON 接口有版本化响应契约；统一所有响应外层结构会改变现有格式，留待 v2 |
| 2 | 身份认证 | 已完成 | `withAuth` 支持 Bearer Token 和常量时间比较；默认不启用认证 |
| 2 | 授权与权限范围 | 延后 | 没有角色或权限范围划分；单个令牌获得全部权限。随部署方式 3 纳入 v2 |
| 3 | 存储：所有连接启用 WAL 和等待超时 | 已完成 | `store/store.go` 的 DSN 包含 `_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)` |
| 3 | 原始事件保留策略 | 已完成 | `telemetry/retention.go` 的 `PruneRawEvents`；由 CLI 手动触发，无定时调度器 |
| 3 | 10 秒／60 秒窗口 | 已完成 | `telemetry/windows.go`；10 秒窗口的补充断言见第 2 节 |
| 3 | 内容寻址对象 | 已完成 | `provenance/objects.go` 的 `MaterializeRun`；取证与回放清单 |
| 3 | 图校验：对象哈希、父对象和链 | 已完成 | `provenance/verify.go` 的 `verifyObjects`、`verifyRiskAndResponses` |
| 4 | Falco 摄入 | 已完成 | `IngestFalco`；`accept_falco_risk_realistic.sh` |
| 4 | Tetragon 摄入 | 已完成 | `mapTetragon`、单元测试和示例；补充验收脚本见第 2 节 |
| 4 | 原生 eBPF 传感器接收端 | 已完成 | `mapNative` 原生格式；`accept_native_sensor_risk.sh`；2026-06-27 虚拟机端到端验证 |
| 4 | 原生 eBPF 采集程序构建 | 已完成 | 仓库已提交 bpf2go 绑定 `internal/sensor/sensorbpf_{x86,arm64}_bpfel.go/.o`；Linux 新检出后可直接 `go build ./cmd/agentprov-sensor`，无需 clang；`scripts/regen-sensor.sh --check` 和 CI 检查生成文件是否一致 |
| 4 | 原始事件无需提供 `tool_call_id` | 已完成 | `telemetry/service.go` 的 `IngestFiltered` 回退到 `correlation.Resolve` |
| 4 | 按容器、cgroup、PID 和时间关联 | 已完成 | 当时 `correlation/binding.go` 的匹配等级：process `1.0`、cgroup `0.98`、container `0.92`、pid `0.85`；这些是历史记录，非当前配置说明 |
| 4 | 子进程、异步和迟到事件归入原范围 | 已完成 | 时间窗口中的开放绑定、`root_pid` 和容器／cgroup 共同归属，不依赖 PPID 祖先链；受监督的 `record` 可为每个范围创建真实 cgroup |
| 5 | 应用与运行时联合时间线 | 已完成 | `provenance/timeline.go` 的 `BuildTimeline`，包含泳道和 `correlation_status` |
| 5 | observe 的 summary、coverage、scopes、event、process、flow 查询 | 已完成 | `cli/observe_cmd.go`，6 项均已实现 |
| 5 | graph explain 的 event、process、tool_call、file、risk、artifact 查询 | 已完成 | `provenance/explain.go`；另支持执行范围和 run；`attempt` 保留为存储兼容别名 |
| 5 | 核心查询的 JSON 与 `schema_version` | 已完成 | 各命令的 `--json` |
| 6 | record 基础状态、变更文件与进程观测 | 已完成 | `record/service.go`；2026-06-27 修复自递归问题，物理表仍保留 snapshot 兼容命名 |
| 6 | diff、四状态 blame、artifact 哈希／来源／父对象、replay | 已完成 | `provenance/diff.go`、`objects.go`、`replay.go` |
| 7 | metadata_ip、private_cidr、secret_path → 风险 → 响应 | 已完成 | `security/policy.go` 的 `DefaultRules`、`EvaluateRuntimeEvent` |
| 7 | policy → risk → response → 统一安全信号校验 | 已完成 | `verify.go` 的 `verifyRiskAndResponses`，要求存在统一信号 |
| 7 | quarantine／kill／deny 的记录级处置 | 已完成 | 修改记录状态，不等于实际拦截；这在当时 v1 范围内可接受 |
| 7 | 飞书、钉钉、Webhook 通知 | 延后 | 尚未实现，列入 v2 |
| 8 | 取证包导出与 SHA-256 | 已完成 | `forensics/export.go` 的 `ExportBundle` |
| 8 | 取证包内容：事件、策略、风险、响应、关系、清单和成本 | 已完成 | `export.go` 的包映射；`accept_forensics_bundle.sh` |
| 8 | 签名与离线校验：哈希及格式 | 已完成 | `attest/` 的 in-toto、DSSE、ed25519；`VerifyBundleAttestation` |
| 8 | graph verify 检查执行链完整性 | 已完成 | 仅证明所检查数据的完整性，见第 0 节 |
| 9 | 10 万事件摄入期间可查询 | 已完成；实测基线，非 SLA | 检查有界分页和健康接口；脚本输出吞吐、查询及健康接口的 p50/p95/p99、服务 CPU/RSS、队列与丢弃状态、覆盖范围 JSON |
| 9 | record 与 ingest 并发时保持一致 | 已完成 | WAL 串行化写入；`record.TestConcurrentRecordPreservesGraphConsistency` 检查并发写入的图逻辑一致性 |
| 9 | 原始事件清理有效 | 已完成 | `accept_daemon_evidence_api.sh` 的 prune 检查 |
| 9 | 分页与游标 | 已完成 | `ListEventsPage` 的不透明游标 |
| 9 | 正常、风险、高压及损坏链场景 | 已完成 | 对应验收覆盖正常、风险和高压；`accept_evidence_tamper_detection.sh` 检查对象文件和库内记录清单被修改后能否发现不一致 |
| 10 | 部署方式 1：库／CLI | 已完成 | 单个二进制加 Python 辅助工具；`accept_deploy1_batch_pipeline.sh` |
| 10 | 部署方式 2：边车／本地服务 | 已完成 | `daemon serve`、REST 和 Bearer 认证 |
| 10 | 部署方式 3：中心证据服务 | 延后 | 尚无对象存储、多租户和 mTLS，列入 v2 |

## 2. 当时必须收尾的项目

以下六项在 2026-06-27 的收尾记录中均标为完成，范围是加固已有能力和校正文案：

1. **record 自递归崩溃**：`CopyDirFiltered` 排除目标子树和 `.agentprov`，提交 `28700d4`。
2. **区分置信来源**：`telemetry.CorrelationClass` 分为 `self_observed`、`context_asserted`、`kernel_correlated`、`uncorrelated`，在遥测列表和事件解释 JSON 中展示，提交 `4e1a6f7`。
3. **并发写入提醒**：`daemon serve` 持有 `.daemon.lock` 建议锁；CLI 通过 `daemon.WarnIfDaemonActive` 提醒用户改用 `--daemon-url`。WAL 负责文件层面的写入安全，提交 `9f2204a`。
4. **eBPF 传感器可重复构建**：提交 bpf2go 绑定后，新检出的 Linux 仓库无需 clang 即可执行 `go build ./cmd/agentprov-sensor`；`scripts/regen-sensor.sh` 及其 `--check` 模式和两项 CI 检查负责构建与生成文件一致性，提交 `50f1106`。
5. **异常与覆盖测试**：`scripts/accept_evidence_tamper_detection.sh` 检查对象文件及库内清单修改，预期 `object_hash_mismatch` 或 `record_manifest_mismatch`，提交 `6692c62`；并发写入图一致性检查见 `record.TestConcurrentRecord...`，提交 `d84812a`；子进程 PID 不同仍可通过容器关联、Tetragon 摄入脚本 `scripts/accept_tetragon_ingest.sh` 和 10 秒窗口断言见提交 `f7f2a6b`。10 万事件延迟使用保存的实测报告，不设跨机器统一 SLA。
6. **健康接口契约**：服务 `health` 补充 `schema_version`，提交 `2f2b4d7`；其他报告处理器已有版本字段。所有响应共用一个外层结构会改变现有数据格式，仍留待 v2。

这份历史清单中的 v1 加固工作已结束；当时排除的项目列在下一节。后续版本的完成情况应查阅相应发行说明和验收记录。

## 3. 明确延至 v2 的项目

这些范围决定作于 2026-06-27：

- **采集时建立主机外防篡改锚点**：KMS、TPM 或透明日志。在此之前，v1 仅声明完整性校验，见第 0 节。当时的总体设计将此列为安全用户所需的 Tier B 能力和 v2 重点。
- **中心证据服务**：即部署方式 3，包括其所需的进程级数据接收隔离、授权与权限范围、对象存储、多租户和 mTLS。部署方式 2 已服务单节点安全接入；延后的是横向扩展。是否推进应参考部署方式 1、2 的实际使用情况。
- **仅由服务端写入的 API 与统一 JSON 外层结构**：部署方式 1 保持本地优先；改动全部写入路径和响应格式应随部署方式 3 的 API 边界一起处理。
- **通知适配器**：飞书、钉钉和 Webhook 响应通知。
- **其他扩展**：跨主机身份与时钟偏差关联（A2）、auditd 及其他运行环境、无 root 容器的 cgroup 委派验收、更广泛的多架构传感器加固。

## 4. 当时的 v1 验收条件

第 1 节纳入的项目全部完成，第 3 节明确列出排除项，第 2 节所有问题关闭，同时完整验收通过：`go vet/test ./...`、全部 `scripts/accept_*.sh`，以及 gofmt、非 ASCII 检查和 `git diff --check`。这里保留当时的验收条件，不替代当前发布流程。
