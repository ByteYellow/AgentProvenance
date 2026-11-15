# v1.0 候选版验收与交接

[English](README.md) | 中文

本目录用于在另一台机器继续验收 `feature/v1.0-portable-evidence`。
内容包括当前状态、可复现入口、经过检查的只读记录和机器可读结果索引。
它与正式发行包、默认 Demo 目录分开维护。

## 版本与边界

| 内容 | 提交 |
| --- | --- |
| 本轮 ARM64 重采与完整测试使用的运行时代码 | `c22c065f5a91fd275529787558ebe9a82e4a1426` |
| 候选版文档与 Mac 发行包 | `cbd3205af40b9557636271ec3b423c179aaa7cbe` |
| 接续分支 | `feature/v1.0-portable-evidence` |

第二个提交只调整文档、内嵌文档路由和一项文档回归测试。
采集、关联、存储和导出仍使用第一个提交的实现。
后续添加本目录的提交只整理交接材料。另一台机器验收时，记录实际检出的 SHA 和二进制哈希。

```sh
git fetch origin
git switch feature/v1.0-portable-evidence
git pull --ff-only origin feature/v1.0-portable-evidence
git status --short
git rev-parse HEAD
```

切分支前先保留本地修改。后续继续在该功能分支工作；合并 main、创建 tag、发版和部署 GitHub Pages 单独审核。

## Mac 与 Linux ARM64 已完成什么

| 需求 | 已有结果 | 剩余验收或审核 |
| --- | --- | --- |
| CS-01～05 | 原生调用身份、并发独立命令、显式重执行、回执丢失恢复、采集收尾及持久交付 | Linux amd64 实测 |
| CS-06、07 | 双向执行关联 API、完整及选择性离线索引、原生来源引用 | 审核后接入正式页面 |
| CS-08 | 开发阶段实测 Mac 外部调用端及容器调用端；末轮重采了容器内原生并发调用 | 最终跨环境复核 |
| RT-01 | 来源限定身份、采集清单、能力变化历史、被动 Pod 归属及 JSONL 回执 | amd64 实测矩阵 |
| RT-02 | 固定版本 gVisor SecCheck 接收、持久化、故障恢复及签名交付 | amd64 运行时复测 |
| RT-03 | guest 镜像及内核构建方案；真实 ARM64 systemd 启动就绪、停止封包与回执 | Firecracker 实际启动及控制端回收 |
| RT-04 | runsc 真实内存恢复及两个克隆；外部身份、密钥重新授权；旧 spool 去重 | 在 amd64 重跑选定方案 |
| APP-01、02 | 真实 Claude Browser／Notebook 任务；basic／detailed；原生 ID、附件和离线阅读 | 审核后接入阅读器 |
| DEMO-01～06 | 分类本地预览、重新采集、历史兼容、中英文源码预览说明 | 最终页面审核、截图和站点装配 |
| DEMO-07 | 沿用现有静态发布链路，完成本地检查 | 发布授权及线上回读 |

Mac、Linux ARM64 的完整 Go 测试、vet、race 和八项前端回归通过。
最终性能结果通过原定的 18 项 Sensor、5 项十万事件摄取、68 项上下文存储与导出门槛。
这些数值用于指定环境与负载的性能回归。

最新实录包括：两个原生会话与三个独立执行尝试、DeepSeek 修复前后调查，以及四次独立 Browser／Notebook 任务。
Grok 继续作为历史记录保留。[结果索引](report.json)列出源码、哈希、命令、结果与保留的失败记录。
早期验收继续绑定其原提交。

## 直接阅读记录

在本目录执行 Linux 的 `sha256sum -c SHA256SUMS`，或 macOS 的
`shasum -a 256 -c SHA256SUMS`，核对[校验清单](SHA256SUMS)。
将 `replays/` 内任意 ZIP 解压到新目录，通过 `file://` 打开其中的 `index.html`。
无需启动 Daemon，也无需原工作目录。

| 文件 | 内容 |
| --- | --- |
| `native-matrix.zip` | 两个 Claude 会话、三个远端执行尝试，以及回执丢失后的恢复 |
| `native-case-a.zip` | 只包含第一个会话及两次执行，排除第二个会话 |
| `task-investigation.zip` | DeepSeek 配置修复前后的调查记录 |
| `investigation-session.zip` | 修复任务中选定的子会话 |
| `browser-detailed.zip`、`browser-basic.zip` | 分别执行的两次浏览器任务 |
| `notebook-detailed.zip`、`notebook-basic.zip` | 分别执行的两次 Notebook 任务 |

ZIP 是带文件哈希的未签名阅读副本。原签名 Bundle 的摘要单独记录。
Browser／Notebook 采用应用上下文入口，原生 Sensor 关闭；其他实录保留实际采集缺口。
阅读器将保存的命令和正文作为数据展示。

## Linux amd64 接续顺序

### 1. 检查环境与构建

使用 Linux x86_64 即可，无需 Windows 主机。
记录 `uname -a`、CPU／内存、剩余磁盘、`go version`、Python／Node 版本、BTF、cgroup v2、权限和 `/dev/kvm`。
Firecracker 需要 `/dev/kvm`；runsc `systrap` 和普通 Linux 项目可独立推进。
产物放在仓库外的新建私有目录。ARM64 Linux 使用 Go 1.26.4；需要做可比复测时，保持编译器和构建参数一致。

```sh
OUT=$(mktemp -d "${TMPDIR:-/tmp}/agentprov-v1-amd64.XXXXXX")
export OUT
go test -count=1 -p 2 -timeout 20m ./...
go vet ./...
go test -race -count=1 -p 2 -timeout 20m ./...
python3 -m unittest discover -s scripts -p 'test_*.py' -v
python3 scripts/check_localized_docs.py
python3 scripts/build-release.py --version v1.0.0-candidate \
  --os linux --arch amd64 --output "$OUT/release"
python3 scripts/accept_release.py \
  "$OUT/release/agentprov_v1.0.0-candidate_linux_amd64.tar.gz"
```

另执行 [CI](../../../.github/workflows/ci.yml) 中 `dashboard-display` 的八条命令。
逐条保存退出码和日志；依赖权限的实机用例使用文档指定的 live 模式，跳过项单独记录。

### 2. 验证真实采集与交付

| 项目 | 已有入口与说明 |
| --- | --- |
| Sensor、TLS、namespace、syscall 和审计 | [CI](../../../.github/workflows/ci.yml) 的 `sensor-live-amd64`，包含相邻 seccomp 调用和混合访问控制用例 |
| 原生并发调用及故障恢复 | [执行交接指南](../../zh-CN/execution-handoff.md)；`scripts/accept_execution_native_matrix.py prepare/run/verify` |
| K3s 被动归属及重启 | `scripts/accept_node_capture.py --agentprov BINARY --report REPORT --artifacts NEW_DIRECTORY`；必要时显式选用环境可获取的镜像 |
| gVisor 接收、故障及恢复 | [固定版本指南](../../zh-CN/gvisor-seccheck.md)；`accept_seccheck.py`、`accept_seccheck_faults.py`、`accept_seccheck_restore.py` |
| Browser／Notebook | [Browser](../../browser-context.zh-CN.md) 和 [Notebook](../../zh-CN/notebook-context.md) 的依赖与入口；`accept_browser.py`、`accept_notebook.py --attachments`；真实模型任务使用 `accept_*_agent.py`，凭据由操作方私下配置 |
| 硬件启动前的 guest 服务 | `sudo python3 scripts/accept_execution_seal.py --native --binary BINARY --output NEW_DIRECTORY --guest-service-dir "$PWD/deploy/microvm"` |

并发命令使用独立工作目录和原生采集。用例会核对执行屏障、原生调用 ID、独立 cgroup、一次显式重执行，
以及回执持久化后丢弃响应的恢复。停止执行端、移走原工作目录后，再执行 `verify`。
新主机的模型 API 凭据单独提供，交接材料不含凭据。

性能按[测量指南](../../zh-CN/performance-validation.md)执行。
先在 amd64 环境冻结基线，再测候选版；不要将 ARM64 的时间预算直接用于另一台机器。
负载输入、编译参数和测量脚本保持一致。

### 3. 完成硬件相关的 guest 验收

沿用[guest 方案](../../execution-handoff.md#guest-service-and-image)固定的 Firecracker v1.18.0、
Amazon Linux 6.18.62 内核源码和 Ubuntu 24.04 rootfs。
使用 `scripts/build_microvm_kernel.py`、`scripts/build_microvm_rootfs.py` 构建，保留内核生效配置、BTF、镜像清单和二进制哈希。

实际启动 guest，分别挂载 root、只读配置和持久证据卷。
验证自动启动、探针就绪、外部分配的实例与代次、一条真实派发命令，以及进程和文件证据。
停止派发、接收回执、停止 guest 服务，再在接收端验证最终封包。
控制端只在所需回执齐全后执行回收；结果不完整或失败时保留证据卷。
宿主 systemd 路径已实跑，这一步补齐真正的 guest 启动与回收。

### 4. 返回结果复核

返回结果索引：检出 SHA、工作区状态、环境、工具版本、二进制／镜像哈希、完整命令、退出码、产物摘要、失败和跳过项。
完整日志留在私有验收包；公开提交只保留审阅后的摘要和合成业务样本。
重试前保留首次失败证据。

余下的共同审核是正式页面接入、非作者按指南上手、跨环境结果汇总和发布。
这些在 x86 结果及维护者审核之后收尾。本轮不扩展 Windows／移动端采集、沙箱调度器或新控制面。
