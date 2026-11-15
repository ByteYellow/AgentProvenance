# v1.0 阅读界面候选预览

[English](README.md)

这份预览沿用现有 Dashboard，增加折叠的跨环境执行面板、会话内的 Browser /
Notebook 页签、采集记录、附件阅读和恢复指引。数据通过离线回放适配器读取现有
公共接口。**正式 Dashboard 尚未启用这些改动。**

2026-11-16，维护者要求先保留代码与说明，等其余 v1.0 工作完成后再集中审核。
布局选择和正式接入留到那时决定。

## 构建与打开

构建需要 Python 3.12 或更新版本。Linux、macOS 都可以在仓库根目录执行，
输出目录需选择一个尚不存在的路径：

```sh
python3 previews/v1.0-reader/build.py --output /tmp/agentprov-v1-reader
python3 -m http.server 47920 --bind 127.0.0.1 --directory /tmp/agentprov-v1-reader
```

打开 <http://127.0.0.1:47920/>。顶部可切换任务调查、跨环境执行、Browser 和
Notebook。语言继续跟随浏览器，也可以手动切换。每个示例的 `index.html`
还可以直接通过 `file://` 打开。

## 审核重点

- 图仍在 Agent 会话上方，会话默认折叠。原有图视图、Compare、时间线和文件
  正文阅读继续保留。
- 跨环境执行可以双向跳转，并定位来源工具调用。执行、采集状态来自保存的
  证据包；交付状态明确标为“封包时的交付状态”，保存的回执单独列出。
- Browser / Notebook 原生记录可以查看身份、正文、截图、静态图片和 HAR。
  附件点击后才读取。
- 采集记录保留能力变化、发生时间、计数范围和未知值。恢复指引区分重试交付
  与创建新的执行尝试。

任务调查、跨环境执行和 Browser 复用
`docs/benchmarks/v1.0-candidate/replays` 中已整理的候选记录。Notebook 使用本轮
Jupyter 合成验收记录，包含静态图表和 kernel 重启；完整阅读副本保存在
`fixtures/notebook-attachments.zip`。原来的 Claude Notebook 示例仍保留在候选目录。

构建器在新目录生成预览，保留原始证据记录，加入页面资源，并更新阅读副本的
文件校验清单。`review.json` 列出示例入口；每份清单记录来源 ZIP 的哈希及
待审核状态。阅读副本本身未签名。

## 检查交互

安装 Node.js、Playwright 及其 Chromium 后执行：

```sh
AGENTPROV_PREVIEW_URL=http://127.0.0.1:47920 \
  node previews/v1.0-reader/check.cjs /tmp/agentprov-v1-reader-check
```

检查覆盖双向执行跳转、来源命令定位、会话默认折叠、Compare 保留、Browser 和
Notebook 正文及图片阅读、脚本报错和意外网络请求。截图和 JSON 报告写入指定目录。

正式接入时，需要把确认后的设计移入 Dashboard 共用资源，移除预览用的会话
导航包装，并补齐本地页面、静态回放和选择性导出的回归。当前预览使用独立的
有界正文弹窗；最终阅读器放在哪里，也留在本次界面审核中决定。
