# v1.0 阅读器构建

[English](README.md)

本目录用于从打包好的未签名阅读副本组装 v1.0 独立证据工作台（任务调查、跨环境执行、
Workspace、Browser 与 Notebook）。统一证据工作台由正式 Dashboard 与离线导出直接共用，
源文件为 `internal/dashboard/workbench.js`、`workbench.css` 及 `reader.js` 内的纯引擎模块。

## 构建与打开

构建需要 Python 3.12 或更新版本。Linux、macOS 都可以在仓库根目录执行，输出目录需选择一个尚不存在的路径：

```sh
python3 previews/v1.0-reader/build.py --output /tmp/agentprov-v1-reader
python3 -m http.server 47920 --bind 127.0.0.1 --directory /tmp/agentprov-v1-reader
```

打开 <http://127.0.0.1:47920/>，每个示例的 `index.html` 也可直接通过 `file://` 离线打开。

## 样例与组装说明

- 任务调查、跨环境执行和 Browser 复用 `docs/benchmarks/v1.0-candidate/replays` 中的候选实录；
- `fixtures/notebook-attachments.zip` 保存带静态图表与 kernel 重启的合成 Jupyter 验收记录；
- `fixtures/workspace-contract.zip` 保存 Linux x86 工作区契约验收的未签名阅读副本（SHA-256 `4dc4230ee69e8e0f28d86e1671e584201fdb5799a82ee5cf0c34ae7526a2136a`）；
- `compose.py` 与 `graph_navigation.py` 在不改动原始证据的前提下刷新工作台资源、清理历史旧脚本、更新图投影并重算 `export-inventory.json`。

## 验收

正式 Dashboard 内嵌同一套工作台资源。站点构建通过 `--production` 链接回示例库；下载后以 `file://` 打开时隐藏站点导航，保留图谱、搜索、对比与正文阅读能力。完整站点验收通过 `scripts/accept_demo_site.py` 与 `previews/v1.0-home/check-redesign.cjs` 执行，历史验收摘要见 [preview-final.json](../../docs/benchmarks/v1.0-x86-completion/preview-final.json)。
