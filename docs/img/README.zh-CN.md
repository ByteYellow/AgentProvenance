# Dashboard 与示例截图

[English](README.md) | 简体中文

本目录保存项目首页和指南使用的截图与回放动画。示例库和阅读页通过 `agentprov demo` 打开；证据图来自贪吃蛇、多 Agent 及 Kubernetes 示例中的签名证据包。

文件名带 `-zh-CN` 的图片来自中文界面。截图中的命令、路径、ID 和原始证据仍保留原文。现有英文截图和历史回放动画继续保留，中文动画尚未补齐。

## 示例页面

| 文件 | 内容 |
|---|---|
| `demo-gallery.png`、`demo-gallery-zh-CN.png` | `/demos/` 中的全部八个入口 |
| `demo-guide.png`、`demo-guide-zh-CN.png` | LLM Judge 阅读页，包含目录和代码复制按钮 |

启动 `./agentprov demo`，打开输出地址，在 1440 像素宽的浏览器窗口中截图。中文页面可以通过右上角语言按钮打开，也可以在 URL 中指定 `lang=zh-CN`。

## 证据图与详情

| 文件 | 内容 |
|---|---|
| `dashboard-overview-zh-CN.png` | 多 Agent 执行记录的中文概览 |
| `dashboard-graph-explorer-taint.png`、`dashboard-graph-explorer-taint-zh-CN.png` | `run-snake-supervised` 的数据流与污点传播视图；红色虚线表示推断关系 |
| `dashboard-side-panel-preview.png` | 英文节点详情与产物预览 |
| `dashboard-side-panel-preview-zh-CN.png` | 中文节点详情与原始命令预览 |
| `dashboard-mobile-zh-CN.png` | 390 像素宽度下的中文首页 |
| `demo-multiagent-overview.png` | 多 Agent 执行记录的英文概览、风险与时间线 |
| `demo-multiagent-orchestration.png`、`demo-multiagent-orchestration-zh-CN.png` | 主 Agent、子 Agent、协作消息、工具调用及系统调用归属 |
| `demo-multiagent-risk-path.png`、`demo-multiagent-risk-path-zh-CN.png` | 聚焦云元数据访问风险及其关联证据 |
| `demo-multiagent-network-egress.png`、`demo-multiagent-network-egress-zh-CN.png` | 多 Agent 执行中的网络外发证据 |
| `demo-k8s-a2a-substrate-dashboard.png`、`demo-k8s-a2a-substrate-dashboard-zh-CN.png` | 节点传感器、Pod 与 cgroup 关系、Alice 到 Bob 的影响路径及风险归属 |

这些图片均为真实界面截图。图中的关系由证据查询生成；不要用手工绘制或生成图片替代验收截图。

## 回放动画与帧

| 文件 | 内容 |
|---|---|
| `demo-snake-taint-replay.png` | 贪吃蛇示例的时间回放帧，展示敏感文件读取与后续网络行为 |
| `demo-snake-taint-replay.gif` | 数据流视图的短回放动画 |
| `demo-multiagent-agent-network.gif` | 使用 Dashboard 播放按钮录制的协作视图动画 |
| `demo-multiagent-agent-network-01-start.png` | 播放开始前的原始帧 |
| `demo-multiagent-agent-network-02-play.png` 至 `demo-multiagent-agent-network-07-play.png` | 播放过程中的原始帧 |

## 重新采集截图

`agentprov demo` 可以直接导入内置签名记录并打开示例库。也可以单独导入一份证据包，然后启动 Dashboard：

```sh
./agentprov --data-dir /tmp/snake-replay forensics import \
  demo/snake-supply-chain/run-snake-supervised.forensics.json.gz \
  --pub-key demo/snake-supply-chain/attestation.pub
./agentprov --data-dir /tmp/snake-replay dashboard serve   # http://127.0.0.1:7396
```

选择对应执行记录和图视图，再按需展开节点或启动播放。截取详情时等待内容预览加载完成；截图应说明选中的对象，不能将命令预览标成文件产物预览。
