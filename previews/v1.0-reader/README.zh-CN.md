# v1.0 阅读界面候选预览

[English](README.md)

这份预览沿用现有 Dashboard，增加折叠的跨环境执行面板、会话内的 Browser /
Notebook 页签、采集记录、附件阅读和恢复指引。数据通过离线回放适配器读取现有
公共接口。**正式 Dashboard 尚未启用这些改动。**

本轮还补入了工作区的输入输出版本、文件变更和操作回执，Browser 的请求、Frame
及关联依据，以及三种交付模式的简短说明，供后续集中审核。

2026-11-16，维护者要求先保留代码与说明，等其余 v1.0 工作完成后再集中审核。
布局选择和正式接入留到那时决定。

## 构建与打开

构建需要 Python 3.12 或更新版本。Linux、macOS 都可以在仓库根目录执行，
输出目录需选择一个尚不存在的路径：

```sh
python3 previews/v1.0-reader/build.py --output /tmp/agentprov-v1-reader
python3 -m http.server 47920 --bind 127.0.0.1 --directory /tmp/agentprov-v1-reader
```

打开 <http://127.0.0.1:47920/>。顶部可切换任务调查、跨环境执行、Workspace、Browser 和
Notebook。语言继续跟随浏览器，也可以手动切换。每个示例的 `index.html`
还可以直接通过 `file://` 打开。

## 审核重点

- 图仍在 Agent 会话上方，会话默认折叠。原有图视图、Compare、时间线和文件
  正文阅读继续保留。
- 跨环境执行可以双向跳转，并定位来源工具调用。执行、采集状态来自保存的
  证据包；交付状态明确标为“封包时的交付状态”，保存的回执单独列出。
- Browser / Notebook 原生记录可以查看身份、正文、截图、静态图片和 HAR。
  附件点击后才读取。
- 工作区页签展示工具返回时保存的版本、输入输出清单、文件变更及对应操作的
  回执。Inspect 携带的上一条回执会与当前操作区分。
- “交付说明”解释 `reading`、`derived`、`originals`，并显示当前副本的状态。
  接收方使用自己的信任策略验证签名。
- 采集记录保留能力变化、发生时间、计数范围和未知值。恢复指引区分重试交付
  与创建新的执行尝试。

任务调查、跨环境执行和 Browser 复用
`docs/benchmarks/v1.0-candidate/replays` 中已整理的候选记录。Notebook 使用本轮
Jupyter 合成验收记录，包含静态图表和 kernel 重启；完整阅读副本保存在
`fixtures/notebook-attachments.zip`。原来的 Claude Notebook 示例仍保留在候选目录。

`fixtures/workspace-contract.zip` 来自 Linux x86 的工作区契约验收，CLI 源码为
`d8a7b60`，采集时启用了原生 Sensor。这个未签名的阅读副本只包含受控案例的
文件和保存结果，SHA-256 为
`4dc4230ee69e8e0f28d86e1671e584201fdb5799a82ee5cf0c34ae7526a2136a`。

构建器在新目录生成预览，保留原始证据记录，加入页面资源，并更新阅读副本的
文件校验清单。`review.json` 列出示例入口；每份清单记录来源 ZIP 的哈希及
待审核状态。阅读副本本身未签名。

阅读器会更新历史回放的图展示：模型消息不再计入产物，没有关联边的调用和产物
仍可查看，调查入口的数量跟随所选会话。保存的证据与归因关系保持原样。采集详情
按本次执行范围展示计数，分别说明 AppArmor/seccomp 状态补采缺失、事件丢失和
待入库情况。

## 检查交互

安装 Node.js、Playwright 及其 Chromium 后执行：

```sh
AGENTPROV_PREVIEW_URL=http://127.0.0.1:47920 \
  node previews/v1.0-reader/check.cjs /tmp/agentprov-v1-reader-check
```

检查覆盖 Run 和会话范围的非零图跳转、采集详情、双向执行跳转、来源命令定位、
会话默认折叠、Compare 保留、工作区版本及回执、交付模式说明、Browser 和
Notebook 正文及图片阅读、脚本报错和意外网络请求。截图和 JSON 报告写入指定目录。

检查五个示例的浏览器语言选择、中英文移动端排版和断网阅读：

```sh
node previews/v1.0-reader/check-portable.cjs /tmp/agentprov-v1-reader /tmp/agentprov-v1-mobile-check
```

审阅真实 Workspace 选择性导出时，可用 `--workspace-archive /path/to/selected.zip`
构建另一份预览。输入须为未签名的 `reading` 副本，也支持最终候选包的共享图存储格式。
随后运行 `check-selection.cjs BUILD_DIR EXCLUDED_CONTEXT_ID CHECK_DIR`，检查被排除的
记录已移除、保留的正文仍能断网打开。[验收结果](../../docs/benchmarks/v1.0-x86-completion/preview-final.json)
收录桌面、移动端、语言和选择性导出检查，以及截图摘要。

正式接入时，需要把确认后的设计移入 Dashboard 共用资源，移除预览用的会话
导航包装，并补齐本地页面、静态回放和选择性导出的回归。当前预览使用独立的
有界正文弹窗；最终阅读器放在哪里，也留在本次界面审核中决定。
