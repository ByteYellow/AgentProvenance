# 示例首页预览

[English](README.md) | 中文

本目录用于本地审核，与正式示例首页和阅读器分开。
首页保留四张带图卡片，其余案例按具体任务分类。
报表修复入口直接打开预选 A/B 的对比窗口，10 月、11 月两次复现各自成对。
标题末尾不加句号，说明文字保留正常标点。

## 构建

需要 Node.js、Python 3、Chrome，以及从当前源码构建的 `agentprov`。
以下命令只读取仓库内的公开记录，生成本地预览文件。

```sh
go build -o /tmp/agentprov-review ./cmd/agentprov
/tmp/agentprov-review demo export --output output/home-review-archive
npm ci --prefix previews/v1.0-home
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

2026-11-17 已选定[精修版首页](refined/README.zh-CN.md)，本版保留用于对比。
首页与阅读器的正式接入另行处理。本构建不替换正式 Dashboard，不发布版本，也不部署 GitHub Pages。
