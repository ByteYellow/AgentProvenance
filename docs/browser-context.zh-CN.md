# 浏览器上下文

[English](browser-context.md) | 中文

通过可选的 Playwright 入口记录独立 Chromium context，保存操作、页面、frame、请求、重定向、Service Worker 流量、下载摘要、截图和隐私过滤后的 HAR。记录使用现有上下文接口导入，沿用签名 Bundle 和离线阅读副本。

## 为什么需要浏览器上下文

一次网页研究可能包含打开页面、读取正文和截图，而同一批浏览器进程还在处理其他页面。
系统遥测记录进程及其网络、文件活动；页面、frame 和操作 ID 则补充任务级上下文，
用于逐项查看操作及保存的结果。

Playwright 入口在浏览器侧记录这些原生身份。调查“打开、读取、截图”这类任务时，
可以从 Agent 工具结果进入对应操作，再查看页面、正文或图片。
请求、重定向和后台 worker 保留各自引用，供调查时核对它们与操作的关系。

已有工具可以使用 Python 入口；需要直接连接 Agent 时，可使用内置 stdio MCP 服务。
需要进程、文件和网络证据时，再按[部署指南](zh-CN/deployment-modes.md#再按内核边界选择采集器)
配置 Linux 系统采集。

## 安装

使用 Python 3.12 或更新版本，创建独立环境：

```sh
python3 -m venv .venv-browser
.venv-browser/bin/python -m pip install -r python/browser-requirements.txt
.venv-browser/bin/python -m playwright install chromium
```

Linux 需要浏览器的系统依赖时，使用该环境的 `python -m playwright install-deps chromium`，按环境要求取得软件包管理权限。依赖文件固定 Playwright 1.65.2 及其配套浏览器，采集记录保存实际浏览器版本。

## 记录任务

将 `PYTHONPATH` 指向仓库的 `python` 目录，在异步工具处理函数中调用：

```python
from agentprov.browser import Browser

placement = {
    "producer_id": "node-a", "namespace": "research",
    "instance_id": "sandbox-42", "generation": "launch-1",
}
async with Browser("browser.jsonl", placement) as browser:
    page = browser.first_page
    await browser.operation(page, "navigate", "https://example.com/")
    result = await browser.operation(page, "read_text")
    await browser.operation(page, "screenshot")
```

`new_page()` 创建页面；`operation(page, "click", selector)` 使用 Playwright locator 点击元素。同一页面的操作串行，不同页面可并发。返回值包含作用域、页面和操作 ID。未完成的操作保留 `unknown`，不自动重试。

入口自行管理全新浏览器 profile/context，启用 Chromium 沙箱，使用仅本机可访问的调试连接和最小进程环境，退出时清理 profile。Linux 需要允许该浏览器创建用户命名空间。受限的 Ubuntu 环境可按 [Chromium 指南](https://chromium.googlesource.com/chromium/src/+/main/docs/security/apparmor-userns-restrictions.md) 配置限定浏览器路径的规则。沙箱不可用时启动失败，不自动降级。工作负载的文件、网络权限由部署环境限制。

## 阅读和分享

### 通过 MCP 接入 Agent

可选的 stdio 服务管理同一个带采集能力的浏览器。在 Agent 的 MCP 配置中使用绝对路径，并指定一个新的私有采集目录：

```json
{
  "mcpServers": {
    "browser": {
      "command": "/path/to/.venv-browser/bin/python",
      "args": ["-m", "agentprov.browser_mcp", "--capture-dir", "/private/captures/task-1",
        "--producer-id", "node-a", "--namespace", "research",
        "--instance-id", "sandbox-42", "--generation", "launch-1"],
      "env": {"PYTHONPATH": "/path/to/AgentProvenance/python"}
    }
  }
}
```

先用 `browser_pages` 获取默认页面，用 `browser_new_page` 创建其他页面，再调用 `browser_execute(page_id, action, value)` 执行操作。等待超时后，用 `browser_result(operation_id)` 查询原操作，不要重新发起。等待、执行和采集各有状态字段。调用方取消时停止等待；服务关闭时取消待处理任务并关闭自身浏览器。

bridge 重启后复用原私有采集目录，`browser_result` 可从持久日志恢复原 receipt，无需启动浏览器或执行动作。缺少结果时保持 `unknown`，历史 receipt 保留原 scope 和 generation；查询限制在当前 producer／namespace／instance 的历史内，ID 冲突或日志损坏返回明确缺口。动作派发前先持久记录受理事件。入口使用 stdio，不开放 HTTP 端口或会话续接协议。

通过 `agentprov launch` 或已支持的 hooks／会话适配记录 Agent。将 `CAPTURE_DIR/browser.jsonl` 导入同一个 Run 后生成关联：

```sh
agentprov context import --run RUN --harness browser --file CAPTURE_DIR/browser.jsonl
agentprov context project --run RUN
agentprov context links --run RUN --entry AGENT_RESULT_ENTRY_ID
```

工具结果中的 `browser_operation` 在正文筛选前提取，basic 模式也保留。完整作用域、页面、操作 ID 和动作类型共同匹配原生记录。hooks 和会话文件中的同一次调用均可跳转；多个调用争用同一操作时，保留 `browser_operation_unresolved`。关联依据为 `source_asserted_native_identity`，规则版本为 `browser-mcp/v1`。查询结果不新增执行关系，网络请求继续保留自己的原生作用域。

签名导入保留这些引用。离线副本排除支撑操作时移除相应跳转，调用方原始引用仍保留。每个服务最多记录 1,024 次操作，同时待处理上限为 32 次，单次结果最多返回 32 KiB 页面文字。`--no-screenshots`、`--no-har` 在采集端关闭对应内容。页面文字、URL 和工具输入可能包含私密数据，分享前需同时检查 Agent 上下文与浏览器附件。

### 导入独立采集记录

```sh
agentprov context import --run research --harness browser --file browser.jsonl --capture detailed
agentprov context project --run research
agentprov context list --run research
agentprov dashboard export --run research --output research.zip
```

`--capture basic` 保留身份与操作摘要，省略可选的原始记录、结果正文、截图和 HAR。`--capture-attachments=false` 可独立关闭附件存储。采集端的 `screenshots=False` 跳过像素获取，`har=False` 跳过 HAR 构建，原生网络事件仍保留。使用 `context attachment` 分页读取附件，使用 `dashboard export --exclude-attachment REF` 从分享副本中排除其字节内容。

### Receiver 固定摘要的本地可信导入

本地 operator 使用现有 `context import` 同步导入，复用原证据存储。支持 Linux 和 macOS：

```sh
agentprov context import --run RUN --harness browser --capture basic \
  --browser-owned-config /private/receiver/browser-import.json \
  --browser-receipts /private/captures/task-1/receipts.json
```

`receipts.json` 是 JSON 数组，元素为 `browser_execute` 或 `browser_result` 返回的原始 `browser_receipt`。此入口拒绝 `--file`、`--session`、`--agent` 和非零 `--after-line` 来源覆盖参数。普通 `--file` 导入和 transcript 中的 `action_result` receipt 保留 `unverified` 来源等级。

Receiver operator 在**采集目录之外**提供配置：

```json
{
  "directory": "/private/captures/task-1",
  "manifest_name": "browser-owned.json",
  "manifest_sha256": "sha256:<receiver-approved manifest digest>",
  "run_id": "RUN",
  "placement": {
    "producer_id": "node-a", "namespace": "research",
    "instance_id": "sandbox-42", "generation": "launch-1"
  },
  "bridge_id": "research-browser-bridge",
  "bridge_config_digest": "sha256:<receiver-approved bridge configuration digest>"
}
```

摘要占位符应替换为 `sha256:` 加 64 位小写十六进制字符串。Operator 通过可信 launcher／collector 通道取得 manifest pin、预期 placement 和 bridge 配置。导入器不从传入 artifact 自动生成授信 pin；artifact 自带 manifest、复制的配置、transcript 认证字段和私有文件权限均作为数据处理。与 Agent 共用 UID 的部署需要独立保护 operator 配置通道。

被 pin 固定的 manifest 指定完整 JSONL 行组成的精确前缀：

```json
{
  "schema_version": "agentprovenance.browser_owned_capture/v1",
  "run_id": "RUN",
  "placement": {
    "producer_id": "node-a", "namespace": "research",
    "instance_id": "sandbox-42", "generation": "launch-1"
  },
  "bridge_id": "research-browser-bridge",
  "bridge_config_digest": "sha256:<same approved configuration digest>",
  "logs": [{
    "name": "browser.jsonl",
    "scope": {
      "producer_id": "node-a", "namespace": "research",
      "instance_id": "sandbox-42", "generation": "launch-1",
      "browser_id": "<recorded browser id>", "context_id": "<recorded context id>"
    },
    "prefix_bytes": 12345,
    "sha256": "sha256:<digest of those exact prefix bytes>"
  }]
}
```

填写实际前缀长度和原记录 ID。Manifest 摘要覆盖文件原始字节，而非重新序列化后的 JSON。路径必须为无符号链接的规范绝对路径。采集目录、配置目录由当前有效 UID 所有且为私有目录，通常为 `0700`；输入文件为私有普通文件且仅有一个硬链接，通常为 `0600`。读取器拒绝不安全文件、替换、截断、重复 JSON 字段、固定前缀中的损坏行及身份冲突。前缀之后的追加内容忽略，直到 operator 提供新 pin。每份配置绑定一个原始 generation。

全部 receipt 校验完成后，单一事务保存 context 记录和独立 `browser_receipt_binding` 对象。JSON 响应包含 `verified_receipts`、`imports`、`bindings`、稳定的 `binding_refs`。Binding 记录 `basis=local_operator_pinned_capture`、精确 run／scope／bridge、manifest 与 receipt 摘要及已核对的原 source refs。输入和结果摘要由日志中的隐私投影字段重新计算，源行摘要包含换行符。原 receipt 的 `bridge_identity.authentication` 保留 `unverified`。重复导入幂等，校验过程只读。签名 bundle 保存独立 binding 证据；接收端以自己的 operator 配置重新核验后使用本地 bridge 授权。

同步 Go API 为 `LoadBrowserLocalImportConfig`、`LoadBrowserReceiptList`、`Service.ImportOwnedBrowser(ctx, runID, cfg, receipts)`。仅做进程内校验时，调用 `ImportOwnedBrowserCapture` 后使用 `VerifyReceipt`，返回的 opaque `VerifiedBrowserReceipt` 拒绝通过 JSON 反序列化构造。上限为 64 份日志、每份 128 MiB、固定前缀合计 256 MiB，每次导入 1,024 份 receipt／4 MiB。

`unknown` 保持原状态。只有受理记录、没有 `action_start` 的 navigate 缺少 URL 投影，可信入口返回 `browser_import_input_projection_unavailable`；普通恢复仍保留该受理记录。进程、socket、文件归属使用另外采集的运行时身份，不由此 binding 推断。

## HAR 网络记录

选择性导出排除某条请求记录时，包含它的整份 HAR 也会从阅读副本中排除，原因为 `har_request_excluded`。原始附件保持不变。

context 关闭时，采集端生成 HAR 1.2 格式的 `application/har+json` 附件。每条请求在 `_agentprovenance` 中保留 CDP session、target、request ID 和重定向序号。导入端将这些身份与已观测请求核对，再次执行字段过滤后保存。来源与留存内容分别计算 SHA-256 摘要。

HAR 省略 HTTP 头、Cookie、查询参数值以及请求和响应正文，保留路径与方法。请求结果分为 `finished`、`failed`、`redirected` 和 `pending`；context 关闭时仍可能存在未结束请求。

未知阶段耗时使用 `-1`。HAR 的 `time` 是已观测阶段耗时之和，SSL 已包含在 connect 中，不重复计算。`observed_duration_ms` 另行保存有原生起止时间的请求总间隔。阶段全部未知时，总和为零，此时应阅读未知标记，而不是将其作为实际耗时。

每份 HAR 最多包含 4,096 条记录，重定向逐跳计数，大小上限为 8 MiB。超限后标记 `incomplete` 并记录省略条数，原生事件继续按自身限额采集。全部附件共用每个 Run 256 份清单、64 MiB 的留存预算。接口以 JSON/base64 分页返回，阅读时不执行响应内容，也不自动访问记录中的 URL。

## 身份与隐私

- 分别保存原生 context、target、CDP session、frame、loader 和 request ID。重定向序号区分复用的 request ID，部署身份与生命周期代次隔离不同执行。
- 网络请求独立于工具操作记录。Worker 和后台请求保留实际可见的作用域，时间相邻不作为点击归属或 syscall 归属依据。
- 写盘前省略 HTTP 头、Cookie 和 POST 正文，移除 URL 用户信息与 fragment，替换全部查询参数。导入端再次执行相同投影。保留的路径和主动读取的页面文字可能含业务数据，分享前应检查。
- 截图使用静态 PNG 附件，分别保存来源与留存摘要。像素内容不自动脱敏，沿用附件限额、选择性导出和离线阅读机制。包含脚本形式的文字按纯文本显示。
- 上限为 24,000 条事件、128 MiB JSONL、4,096 个请求身份、256 个观测目标、32 个受控页面和下载，以及总计 64 MiB 的 64 张截图。单次下载上限 8 MiB，记录保留其原生 ID、完成状态与摘要。采集失败会记录缺口。

## 集成验收

```sh
PYTHONPATH=python .venv-browser/bin/python scripts/accept_browser.py \
  --output /tmp/browser-check --agentprov /absolute/path/to/agentprov
```

脚本启动两个独立浏览器，每个浏览器有两个并发页面，检查重定向、iframe、Worker、后台请求、下载摘要、截图、HAR 请求集合一致性、隐私标记、两档留存及独立存储中的签名导入，并生成完整、排除全部附件、仅保留 HAR 和排除单条请求的离线 ZIP。该流程使用受控浏览器任务，不需要模型 API Key 或系统 Sensor。

通过真实 stdio MCP 协议验收，无需模型 Key：

```sh
PYTHONPATH=python .venv-browser/bin/python scripts/accept_browser_mcp.py --output /tmp/browser-mcp-check
```

用已有 Chrome live 产物验收真实 owned-import CLI：

```sh
python3 scripts/accept_browser_owned_import.py \
  --agentprov /absolute/path/to/agentprov \
  --artifacts /absolute/path/to/chrome-live-artifacts \
  --output /private/browser-owned-import-check --approve-fixture-pin
```

输入目录包含 `results.json` 中的 `observations[].result.browser_receipt` 和原始 `capture/*.jsonl`。脚本只读这些字节，复制私有快照，并在独立 receiver 目录生成经显式批准的 **fixture pin**，无需启动浏览器。验收覆盖 receipt／source ref／摘要、原 generation、重复导入、错误外部 pin、artifact 自授信、伪造 receipt、跨 generation 拒绝和独立存储中的签名 bundle 往返。报告 `results.json` 明确记录 `fixture_operator_pin=true`：这里检查真实 Chrome 字节的导入路径，生产启动认证使用 receiver 自有的外部 pin。验收签名密钥保留在私有输出目录。

使用现有 Claude Code 服务配置，运行真实 Agent 任务：

```sh
PYTHONPATH=python .venv-browser/bin/python scripts/accept_browser_agent.py \
  --output /private/browser-agent-check --agentprov /absolute/path/to/agentprov \
  --claude /absolute/path/to/claude --capture detailed
```

任务读取本地表格、下载 CSV 并截图。脚本检查 Agent／Browser 原生关联、重复导入、独立存储中的签名导入，以及完整和选择性离线 ZIP。再用 `--capture basic` 检查省略正文后关联是否保留。每次模型调用设有费用上限；日志、采集记录及验收签名密钥留在私有输出目录。本项验收关闭原生 Sensor，专门检查应用操作入口；launch 的进程抽样记录仍单独保留。

参考：[browser context](https://playwright.dev/python/docs/api/class-browsercontext)、[请求生命周期](https://playwright.dev/python/docs/api/class-request)、[Chromium target/session 身份](https://chromedevtools.github.io/devtools-protocol/tot/Target/)。
