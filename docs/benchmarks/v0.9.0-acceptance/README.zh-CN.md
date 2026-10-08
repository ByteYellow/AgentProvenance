# v0.9.0 验收记录 — 2026-10-08

[English](README.md) | 中文

已确定的 A1～A4、B1 通过下列验收。代码基于
`186e6c7ce889df0c414fd01c65bf504b44273c58`，包含本次发现并修复的问题。
[report.json](report.json) 保存各项检查、数量、程序与探针校验值，以及初次失败的原因。
这里记录的是验收结果，正式版尚未发布。

| 验收项目 | 结果 |
| --- | --- |
| 已有适配器、DeepSeek、绑定与恢复、配置历史、覆盖报告 | Go 1.23.12、1.26.0 全部包通过；静态检查与竞态测试通过 |
| 真实 DeepSeek 签名记录 | 原始签名、2,532 行数据、正文、图谱关联、重复导入与 API 错误场景通过 |
| 六份 v0.8.2 历史签名包 | 保留 47,997 行原始数据，144 组图查询一致，数据库 17→19 升级与重复导入通过 |
| 真实回放页面 | DeepSeek 71 项；历史示例 313 项，包括 144 次图谱视图渲染 |
| 合成页面边界用例 | 会话、配置、覆盖报告 83 项；文件预览 18 项，实际翻过 135 页并读到超过 8 MiB 的文件末尾 |
| KVM Linux 6.8.0-139 x86_64 | 43 项传感器实测通过；常驻服务、记录、关联、图校验、导出与回放通过 |
| 进程生命周期持久化 | 真实 fork、cgroup 迁移与 clone3 事件进入磁盘缓冲后，仍归属正确的进程和 Run |
| K3s v1.36.4+k3s1 | Pod 采集、删除后关闭绑定、本机/Pod 语义对齐、一个 DaemonSet 采集八个工作负载、informer 重启与重新绑定通过 |
| 短命 Pod 与崩溃恢复 | 13 项通过：无提前绑定、强杀前落盘、迟到补关联、关闭时间窗口、Run 隔离、再次重启不重复入库 |
| 容器 TLS 自动发现 | 30 项通过，覆盖 OpenSSL、Go 和容器重建，未手动指定目标库或程序路径 |
| Go TLS 并发与栈增长 | WSL x86_64 上 32 路连接、71 个分块逐字节匹配，零丢失、零残留上下文 |
| 数据库与存储故障 | 11 项健康检查通过，包含不可用状态、未知计数与故障恢复 |
| Linux amd64 便携包 | 不依赖 Go，七份签名回放、九个双语指南、上下文展示与退出清理通过 |

合成页面用例专门覆盖长内容、配置缺失与空值、历史边界、多个保存版本、切换语言、
API 失败及阅读位置保持，不把它们当作真实模型执行。Claude/Codex 的真实会话依据仍为
[上下文指南](../../zh-CN/agent-context.md#原生格式兼容性)记录的 Mac 验证；本轮复跑格式样本和自动化回归。

## 本轮修复

- C 源码与 ARM64 探针已有子进程出生 cgroup 修复，amd64 预编译探针却仍是旧版本。
  使用 KVM 内核 BTF 重新生成后，原先失败的 `clone-child:birth_cgroup` 通过。ARM64 文件未改动。
- 日志较多时，就绪检查提前关闭管道，出现 `kubectl=141`、`grep=0`，误报探针未就绪。
  KVM 安装器和 DaemonSet 验收现在读完日志，并匹配完整的就绪行。
- 时间测试改为在单调时钟采样前后分别取墙上时钟，避免繁忙环境的调度延迟影响预期值。
- review 分支原先进入发布步骤，并查找不存在的 review 专用发行说明。
  现在 review 只验收和构建，构建前检查发布规则与说明文件；release 分支的 PR 也执行验证。
- 旧版验收补齐四个平台的 v0.8.2 官方程序校验值。CI 先校验压缩包和程序，再测试真实旧数据库升级
  与六份原始签名包，不修改或重新签署历史证据。

## 复跑方式

使用本分支构建 CLI 与传感器。旧版兼容测试使用对应平台的 v0.8.2 官方程序，先按
`scripts/testdata/v0.8.2-bundles.json` 核对压缩包和程序校验值，然后运行：

```sh
python3 scripts/accept_legacy_context.py --binary /path/to/new/agentprov \
  --baseline-binary /path/to/v0.8.2/agentprov \
  --manifest scripts/testdata/v0.8.2-bundles.json --evidence-root . \
  --output /tmp/new-legacy-acceptance
python3 scripts/accept_deepseek_context.py --binary /path/to/new/agentprov \
  --output /tmp/new-deepseek-acceptance
python3 -m unittest discover -s scripts -p test_release_plan.py -v
go vet ./...
go test -race -p 2 ./...
```

KVM/K3s 环境要求见[部署指南](../../zh-CN/amd64-kvm-k3s.md)。传感器实测需带上
`--require-cgroup-lifecycle --pause-drain 1.5`，再将生成的 `.events.jsonl` 通过
`AGENTPROV_LIVE_LIFECYCLE_EVENTS` 交给 `TestNativeLiveLifecycleAttribution`。
在同一实验环境运行 `accept_node_capture.py`、`accept_container_tls.py` 和三个 K8s
能力对齐、多工作负载、informer 脚本。本轮因 Docker Hub 拉取超时，通过已有的
`--image`/`IMAGE` 选项使用节点缓存的 Rancher BusyBox 1.37.0 镜像，未修改宿主机代理。

按已确定范围，本轮不重做 ARM 实机验收，也不开展 24 小时长稳测试。TLS 轮询与格式限制
继续由能力报告明确展示。四平台发布构建在基线提交已通过，本次提交的远端 CI 结果与这份
本地验收报告分别记录。
