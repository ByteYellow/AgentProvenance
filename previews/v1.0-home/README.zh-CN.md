# 示例首页预览

[English](README.md) | 中文

本目录保存共用首页资源，并保留之前的本地审核构建。
首页保留四张带图卡片，其余案例按具体任务分类。
报表修复入口直接打开预选 A/B 的对比窗口，10 月、11 月两次复现各自成对。
标题末尾不加句号，说明文字保留正常标点。

## 构建

需要 Node.js、Python 3、Playwright Chromium，以及从当前源码构建的 `agentprov`。
以下命令只读取仓库内的公开记录，生成本地预览文件。

```sh
go build -tags agentprov_tools -o /tmp/agentprov-review ./cmd/agentprov
/tmp/agentprov-review demo export --output output/home-review-archive
npm ci --prefix previews/v1.0-home
previews/v1.0-home/node_modules/.bin/playwright install chromium
python3 previews/v1.0-home/build.py \
  --archive output/home-review-archive \
  --output output/home-review
python3 -m http.server 58729 --bind 127.0.0.1 --protocol HTTP/1.1 --directory output/home-review
```

打开 `http://127.0.0.1:58729/?lang=zh-CN`。重建时使用新目录；端口被占用时换一个端口。
已有预览与原始签名包保留。构建时更新未签名阅读副本的文件清单，并在本地渲染 Mermaid，
生成后的页面无需连接外部绘图服务。

## 检查

```sh
node previews/v1.0-home/check.cjs http://127.0.0.1:58729/ output/playwright/home-review output/home-review
```

检查覆盖中英文、桌面和手机、全部档案章节、指南链接、独立图标、标题标点、成对对比、
返回阅读现场、架构图缩放和下载回放文件。最后一个参数可选，用于断网 `file://` 验证。
无效配对等对比组件检查另有
`scripts/test_dashboard_compare_completeness.mjs` 回归。

`media/` 是已保存案例的界面截图。重新截图时，向 `capture-thumbnails.cjs` 传入预览地址
和新的图片目录。可用 `--screenshots` 指定案例弹窗中的大图目录。
打开案例只读取证据，不执行 Agent 或调用模型接口。

2026-11-17 已确认[精修版首页](refined/README.zh-CN.md)与阅读器一起接入，本版保留用于对比。

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
