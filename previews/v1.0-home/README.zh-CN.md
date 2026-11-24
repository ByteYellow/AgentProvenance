# 示例首页

[English](README.md) | 中文

本目录保存 v1.0 单源示例首页（`index.html`、`home.css`、`home.js`）、构建期真实分片提取器
（`featured_cards.py`、`workspace_card.py`、`replay_card_source.py`）以及 Playwright 验收脚本
（`check-redesign.cjs`）。四张精选卡片直接从真实回放分片提取摘要，其余案例按任务分类。
报表修复入口直接打开预选 A/B 的对比窗口，10 月、11 月两次复现各自成对。

## 构建

需要 Node.js、Python 3、Playwright Chromium，以及从当前源码构建的 `agentprov`。
以下命令只读取仓库内的公开记录，生成本地预览文件。

```sh
go build -tags agentprov_tools -o /tmp/agentprov-review ./cmd/agentprov
/tmp/agentprov-review demo export --output output/home-review-archive
npm ci --prefix previews/v1.0-home
npm ci --prefix previews/v1.0-tour --ignore-scripts
previews/v1.0-home/node_modules/.bin/playwright install chromium
python3 scripts/build_demo_site.py \
  --archive output/home-review-archive \
  --output output/home-review
python3 -m http.server 58729 --bind 127.0.0.1 --protocol HTTP/1.1 --directory output/home-review
```

打开 `http://127.0.0.1:58729/?lang=zh-CN`。重建时使用新目录；端口被占用时换一个端口。
已有预览与原始签名包保留。构建时更新未签名阅读副本的文件清单，并在本地渲染 Mermaid，
生成后的页面无需连接外部绘图服务。

## 检查

```sh
python3 previews/v1.0-home/test_workspace_card.py -v
node previews/v1.0-home/check-redesign.cjs \
  http://127.0.0.1:58729/ output/playwright/home-review.json output/home-review --extended
```

检查覆盖中英文、桌面/平板/手机响应式布局、精选卡片与目标实录的数据一致性、显式校验状态、
成对对比、返回阅读现场、可选页面导览以及脱离 `localStorage` 的离线 `file://` 阅读包验证。
`media/` 仅保留协作图谱缩略图（`team-en.png`、`team-zh-CN.png`），Browser 卡片截图在构建期直接从真实回放包中提取。
打开案例只读取证据，不执行 Agent 或调用模型接口。

## 正式站点构建

发布工作流先验证签名回放目录，再组合确认后的首页和当前阅读器，生成供 Pages 使用的产物。
以下命令在本地执行相同构建和检查，不会部署线上：

```sh
export NODE_PATH="$PWD/previews/v1.0-home/node_modules"
npm ci --prefix previews/v1.0-tour --ignore-scripts
python3 scripts/accept_static_demo.py --binary /tmp/agentprov-review --site output/site-base
python3 scripts/build_demo_site.py --archive output/site-base --output output/site
python3 scripts/accept_demo_site.py --archive output/site-base --site output/site
python3 -m http.server 58730 --bind 127.0.0.1 --protocol HTTP/1.1 --directory output/site
```

打开 `http://127.0.0.1:58730/`。原有 `/en/` 和 `/zh-CN/` 下的阅读器、指南及下载链接继续有效。
之前的完整案例目录保存在 `en/library.html` 和 `zh-CN/library.html`。
`downloads/reading/` 提供包含当前阅读器及新文件清单的阅读副本，原始下载文件保持逐字节一致。
首页及所有执行记录页均提供[页面导览](../v1.0-tour/README.zh-CN.md)，包括七份 Linux x86 实录。独立下载的回放无需加载站点的导览资源。

验收脚本检查中英文四档宽度、档案弹窗、链接、架构图、对比、图谱跳转和附件，
并实际下载工作区阅读包后断网打开。设置 `PLAYWRIGHT_CHANNEL=chrome` 可改用本机 Chrome。
构建保留已有目录，每次重建请使用新路径。

只改首页或阅读器时，可复用已验证的 `output/site-base`，用新输出目录执行站点构建和验收。
实录、随归档导出的文档或证据索引发生变化时，再重新执行完整导出。更新站点界面会从源码重建阅读器，原始 ZIP 保持不变。
