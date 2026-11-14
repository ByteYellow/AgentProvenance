# 浏览器上下文

[English](browser-context.md) | 中文

通过可选的 Playwright 入口记录独立 Chromium context，保存操作、页面、frame、请求、重定向、Service Worker 流量、下载摘要和截图。记录使用现有上下文接口导入，沿用签名 Bundle 和离线阅读副本。

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

```sh
agentprov context import --run research --harness browser --file browser.jsonl --capture detailed
agentprov context project --run research
agentprov context list --run research
agentprov dashboard export --run research --output research.zip
```

`--capture basic` 保留身份与操作摘要，省略可选的原始记录、结果正文和截图。`--capture-attachments=false` 可独立关闭截图存储；采集端的 `screenshots=False` 可直接跳过像素获取。使用 `context attachment` 分页读取截图，使用 `dashboard export --exclude-attachment REF` 从分享副本中排除其字节内容。

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

脚本启动两个独立浏览器，每个浏览器有两个并发页面，检查重定向、iframe、Worker、后台请求、下载摘要、截图、隐私标记、两档留存及独立存储中的签名导入，并生成完整与排除截图的离线 ZIP。该流程使用受控浏览器任务，不需要模型 API Key 或系统 Sensor。

参考：[browser context](https://playwright.dev/python/docs/api/class-browsercontext)、[请求生命周期](https://playwright.dev/python/docs/api/class-request)、[Chromium target/session 身份](https://chromedevtools.github.io/devtools-protocol/tot/Target/)。
