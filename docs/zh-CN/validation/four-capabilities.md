# 可移植证据验收

[English](../../validation/four-capabilities.md) | 中文

本文交接 `feature/v1.0-portable-evidence` 分支的四项能力：受控工作区、证据交付、
运行时适配和 Browser 分层证据。正式 Dashboard 保持现有布局，页面调整仍保留在局部预览。
[验收结果](../../benchmarks/v1.0-four-capabilities/README.zh-CN.md)分别记录固定源码复测、
历史采集和剩余环境验收项。

## 当前范围

| 任务 | 已有实现 | 剩余验收 |
| --- | --- | --- |
| C-01 | 观测层、范围、策略对象、能力时间区间和运行时身份投影 | 在选定 x86 部署中核对新增运行时观测 |
| W-01 | 远端权威工作区、版本/摘要冲突检测、CLI 和 stdio MCP | 用最终 x86 构建与 Sensor 复测，再组合 Kata |
| E-01/E-02 | 阅读副本、选定内容签名、完整原件、接收方信任、独立验证器及已修正的签名状态提示 | 最终同源码安装包和阅读流程复测；Dashboard 控件等待预览确认 |
| R-01 | 分开定义平台、执行和采集，保留 native 默认行为 | 新平台集成矩阵 |
| R-02 | Sentry 出生身份、子进程归属、持久化采集水位和签名命令证据 | 实机命令及接收端／执行端故障矩阵已通过；保留最终候选回归 |
| R-03 | Kata/QEMU Guest 绑定与有界验收脚本 | 在 Kubernetes 上固定 `kata-qemu-runtime-rs` 组合，核对 Guest Sensor 权限并实跑 |
| B-01 | 持久 accept/result、重启查询、接收方控制的回执核验 | 原生采集和 SIGKILL 恢复已通过；最终候选复测待完成 |
| B-02 | 按原生 ID 建立 Browser 分层关系，保存规则版本与引用 | Linux context/tab、重定向、iframe/worker、后台请求和下载矩阵已通过 |
| B-03 | 显式运行时托管关系与内核进程生命周期检查 | 实际启动身份、原生进程范围和选择性导出已通过 |
| Q-01 | 回归脚本、独立交付检查、有界 soak 采样器 | 有时限的资源测试和最终构建复测待完成；24 小时长测由维护者暂缓 |

[x86 收尾结果](../../benchmarks/v1.0-x86-completion/README.zh-CN.md)收录了原生采集下的
Workspace、Browser 案例，以及 runsc 的命令和故障矩阵。runsc 在放行前绑定 Sentry PID
及出生身份，沿原生记录追踪子进程，等待专用完成标记写入接收端数据库后封存。
接收端中断时，原命令保留采集缺口；取消和执行器重启保留未知结果，并阻止该
generation 继续执行。重复提交和查询均复用已保存的执行尝试。

此前的工作区案例在 ARM Linux VM 内，使用 Claude Code 2.1.293 和已有 DeepSeek 配置，
通过 `agentprov_workspace` 完成 Inspect、Read、Edit、Write、Bash 和最终 Read。
一次实际命令生成了预期文件；该轮 Sensor 关闭。完整原件、生产者签名和导出者签名
已通过接收方独立核验；离线 Chrome 检查了 99 次查询、36 个视图、12 条正文，外部请求为 0。

本地 Browser 案例使用真实 Chrome、stdio MCP 和受控回环站点。
bridge 重启后可查询已完成结果，中断操作保留 `unknown`，查询没有重复动作。
Linux OS 关联单独验收。

## 准备源码

拉取功能分支，保持与 `main` 分离。产物放在仓库之外的新私有目录。
先记录源码版本、工作区状态和环境：

```sh
git fetch origin feature/v1.0-portable-evidence
git switch feature/v1.0-portable-evidence
git pull --ff-only origin feature/v1.0-portable-evidence
git status --short
git rev-parse HEAD
go version
uname -a
```

将 `OUT` 设置为新的绝对路径，用同一源码构建执行器和独立验证器：

```sh
mkdir -m 700 "$OUT"
go build -trimpath -o "$OUT/agentprov" ./cmd/agentprov
go build -trimpath -o "$OUT/agentprov-verify" ./cmd/agentprov-verify
sha256sum "$OUT/agentprov" "$OUT/agentprov-verify"
go test ./...
go vet ./...
go test -race -p 2 -timeout 20m ./...
```

Kata 的版本锁还要求二进制写入 `internal/buildinfo.Version` 和
`internal/buildinfo.Commit`，构建方式见专门指南。Python 依赖按各接入指南安装；
工作区 MCP 已使用 MCP 2.3.0 验收。Browser 需要 Playwright 及已安装的 Chrome/Chromium。
本地 Browser 测试站点、工作区契约测试均不使用模型 API。

## 受控工作区

以下命令在拥有工作区的机器内执行，Harness 和 stdio bridge 整体运行在该机器，
文件使用一份权威副本：

```sh
PYTHONPATH=python python3 -m unittest discover -s python/tests -p test_workspace_mcp.py
python3 scripts/accept_workspace.py --agentprov "$OUT/agentprov" \
  --python-package "$PWD/python" --output "$OUT/workspace-contract"
```

真实 Harness 验收使用已有认证配置的 Claude Code wrapper：

```sh
python3 scripts/accept_workspace.py --agentprov "$OUT/agentprov" \
  --python-package "$PWD/python" --claude /absolute/claude-wrapper \
  --output "$OUT/workspace-harness"
```

脚本检查已连接的 MCP 工具清单和实际 `tool_use` 记录。server 名为
`agentprov_workspace`。模型凭据继续由操作者环境管理。九项契约检查包括旧版本、
并发修改、重启查询、路径边界、generation 变化和证据归属。
配置及工具字段见[受控远端工作区](../workspace.md)。

Linux 已具备授权的 BPF 权限和可写 cgroup v2 子树时，加上 `--sensor`。
脚本为每个证据库管理独立采集器，检查探针就绪、停止并排空采集，然后核对原生事件
与 Bash record 的 cgroup、工作区回执。它不创建 sudo 策略或系统服务：

```sh
python3 scripts/accept_workspace.py --agentprov "$OUT/agentprov" \
  --python-package "$PWD/python" --claude /absolute/claude-wrapper \
  --sensor --sensor-placement local_kernel --output "$OUT/workspace-sensor"
```

Kata 使用 Guest 采集位置和操作者提供的 Target 文件。按 [Kata 指南](kata-qemu.md)
启用可选工作区案例，将同一 Read/Edit/Write/Bash 任务和签名交付纳入该组合。

## Browser 回执与原生关系

```sh
PYTHONPATH=python python3 python/tests/test_browser_receipts_live.py \
  --channel chrome --output "$OUT/browser-live"
python3 scripts/accept_browser_owned_import.py --agentprov "$OUT/agentprov" \
  --artifacts "$OUT/browser-live" --output "$OUT/browser-import" \
  --approve-fixture-pin
go test ./internal/agentcontext ./internal/browserlink ./internal/provenance \
  ./internal/dashboard -run 'TestBrowser' -count=1
```

这里的 pin 确认仅用于测试产生的受控采集副本。真实导入使用独立批准、位于采集目录外的
接收方配置，固定 Run、bridge、placement 和 manifest 摘要。回执或包内内容不参与授权配置。

测试生成两份证据库：`browser-import/data` 是初次导入，`browser-import/received`
是签名 Bundle 回导后的接收库。对两者分别导出，使用不同文件名；Run 均为
`browser-owned-acceptance`：

```sh
"$OUT/agentprov" --data-dir "$OUT/browser-import/data" dashboard export \
  --run browser-owned-acceptance --output "$OUT/browser-source-reader.zip"
"$OUT/agentprov" --data-dir "$OUT/browser-import/received" dashboard export \
  --run browser-owned-acceptance --output "$OUT/browser-received-reader.zip"
PLAYWRIGHT_CHANNEL=chrome AGENTPROV_REPLAY_SEARCH_QUERY=/pending \
  node scripts/accept_offline_replay.cjs "$OUT/browser-source-reader.zip"
PLAYWRIGHT_CHANNEL=chrome AGENTPROV_REPLAY_SEARCH_QUERY=/pending \
  node scripts/accept_offline_replay.cjs "$OUT/browser-received-reader.zip"
```

分别离线打开两份阅读副本，核对保存的 scope、回执与原生引用。这两份测试库的
Sensor 关闭；下面的 B-03 检查改用包含实际 Sensor 事件和操作者运行时映射的证据库。
`/pending` 来自该案例实际保留的 URL，basic 模式也可检索。
使用 Playwright 安装的 Chromium 时，去掉 `PLAYWRIGHT_CHANNEL` 即可。

B-03 需同时保存完整 Browser scope、操作者观测到的进程生命周期和 Sensor 证据，
包含 host/boot、进程出生身份、采集范围、支撑事件 ID。按实际粒度核对 context 到进程、
进程到系统行为的关系。覆盖并发 tab、redirect、后台请求、下载、重启和缺证据。
可用入口及 Sensor-on 验收项见 [Browser 指南](../../browser-context.zh-CN.md)。

将 Browser 记录与原生事件导入同一证据库后，按指南准备外部映射配置。
显式执行下列检查；缺少输入时，前面的通用测试命令会跳过这项：

```sh
AGENTPROV_BROWSER_CUSTODY_CONFIG="$CUSTODY" AGENTPROV_BROWSER_DATA_DIR="$DATA" \
  go test ./internal/provenance -run '^TestBrowserLayerOperatorIngress$' -count=1 -v
"$OUT/agentprov" --data-dir "$DATA" graph lens --run "$RUN" --detail raw \
  --browser-custody-config "$CUSTODY" --json
"$OUT/agentprov" --data-dir "$DATA" dashboard export --run "$RUN" \
  --browser-custody-config "$CUSTODY" --output "$OUT/browser-reader.zip"
```

实测检查要求 `matched_native_process_observations > 0`。核对进程、文件和网络关系的
支撑引用，再用选择性导出排除一条支持该映射的 Browser 记录，确认阅读副本同步移除
对应运行时映射。配置文件留在采集目录和导出包之外。

## 运行时与 Kata

先按[运行时适配](../runtime-adapters.md)运行可选的
`TestRunscLiveExecutionIdentityEvidence`，保留精确 SecCheck 身份字段。
再对已配置的 handoff daemon 检查重复准入、查询不重执行、错代拒绝、receiver 断连/重启、
executor 重启，以及两侧范围的证据交付。

在已授权的独立命名空间执行 [Kata/QEMU 验收](kata-qemu.md)。先将实测版本和摘要
填入私有 lock。脚本核对 Guest BTF/探针/cgroup、Pod/container/Guest 身份、并发命令、
采集恢复、Pod 重建及离线交付。运行时安装和集群策略由操作者准备。
带上独立 verifier 选项，同轮检查签名阅读副本。

## 交付与断网阅读

```sh
python3 scripts/accept_derived_view.py --agentprov "$OUT/agentprov" \
  --verifier "$OUT/agentprov-verify" --out "$OUT/delivery"
```

脚本覆盖可信/未知/角色错误的签名者、阅读内容及原件篡改、选择边界和包内策略替换。
浏览器验收使用实际 ZIP，搜索词选择该案例已保存的内容：

```sh
PLAYWRIGHT_CHANNEL=chrome AGENTPROV_REPLAY_SEARCH_QUERY=result.txt \
  node scripts/accept_offline_replay.cjs /absolute/workspace-originals.zip
"$OUT/agentprov-verify" --trust-policy /absolute/recipient-policy.json \
  /absolute/workspace-originals.zip
```

浏览器使用断网 `file://`，检查选择范围、正文索引、图谱、搜索、Compare 和手机横向溢出。
目前签名模式沿用的阅读器仍有“未签名副本”旧文案，随页面预览确认后处理。
本轮签名验收读取独立验证器的完整性、生产者签名、导出者签名和信任字段。

## 长时间运行与结果回传

ARM Linux 已用独立的真实 daemon 完成 60 秒短测：30 次健康检查成功、6 次命令完成，
RSS 从 46.5 增至 57.9 MiB，健康接口延迟 p95 为 33.3 ms。该配置关闭了采集；
24 小时时长和采集故障恢复继续列为待验收。

使用操作者单独配置的回环 daemon、已知 PID 和外部 token 文件。先短测，再跑完整时长：

```sh
python3 scripts/accept_execution_soak.py --url http://127.0.0.1:8787 \
  --config /absolute/execution.json --token-file /absolute/daemon.token \
  --daemon-pid "$DAEMON_PID" --agentprov "$OUT/agentprov" \
  --output "$OUT/soak-24h" --duration-seconds 86400
```

采样器有界记录资源、积压、丢失、延迟和恢复观测，不重启已有服务。
短测保留 24 小时门禁为待验收；完整运行后再复核趋势与故障恢复，缺失指标保留未知。

回传源码 SHA、工作区状态、二进制哈希、平台/运行时 lock、命令、退出码、报告和产物摘要。
跳过项保留原因；每次复测使用新目录并保留旧报告。公钥经可信渠道单独提供。
私钥、token、模型原始日志和个人采集内容留在私有目录，不整体上传产物目录。

下一步是维护者验收。本交接不创建 PR，不合并、打 tag、发布 Release 或部署在线站点。
