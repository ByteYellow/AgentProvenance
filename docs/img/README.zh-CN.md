# Dashboard 与示例截图

[English](README.md) | 简体中文

本目录保存项目首页和指南使用的截图与回放动画。示例库和阅读页通过 `agentprov demo` 打开；证据图来自 DeepSeek、贪吃蛇、多 Agent 及 Kubernetes 示例中的签名证据包。

文件名带 `-zh-CN` 的图片来自中文界面。截图中的命令、路径、ID 和原始证据仍保留原文。中文回放动画通过 Dashboard 播放按钮录制；英文素材继续保留。

## Agent 上下文截图

v0.9.0 界面截图于 2026-10-08 拍摄，使用签名 DeepSeek 记录
`run-dbc2adf273d4`。截图展示当前界面读取 2026-09-28 的原始证据，
不是新调用模型生成的数据。每张均有英文和 `-zh-CN` 中文版本，
放在 [DeepSeek 指南](../../demo/deepseek-context/README.zh-CN.md)同目录，
随 CLI 内嵌供离线阅读。

| `demo/deepseek-context/` 中的文件 | 内容 |
|---|---|
| `dashboard-session.png` / `dashboard-session-zh-CN.png` | 对话与工具中的测试命令及返回结果 |
| `dashboard-configuration.png` / `dashboard-configuration-zh-CN.png` | 权限预设、沙箱模式与审批策略 |
| `dashboard-tests.png` / `dashboard-tests-zh-CN.png` | 放大正文查看器中的七项测试输出 |
| `dashboard-file.png` / `dashboard-file-zh-CN.png` | 会话收起时查看最终 `test_report.py` 正文 |
| `dashboard-coverage.png` / `dashboard-coverage-zh-CN.png` | 分别报告会话采集、工具关联和运行时完整性 |

窗口为 1440 × 1060。切换 Agent 会话的标签并在面板内滚动；
测试输入和结果位于第 2 页，对应来源记录 #56、#57。
文件视图选择“文件与产物”，展开源码分组后选中 `test_report.py`。
不要为截图修改证据或隐藏采集告警。

## 示例页面

示例首页中英文截图已在同一版本刷新，包含七份签名回放和两个评估器指南。
下文的历史证据图与播放动画保留原来的示例内容。

| 文件 | 内容 |
|---|---|
| `demo-gallery.png`、`demo-gallery-zh-CN.png` | `/demos/` 中的签名回放与可选评估器指南 |
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
| `demo-snake-taint-replay.gif`、`demo-snake-taint-replay-zh-CN.gif` | 数据流视图的中英文回放片段 |
| `demo-multiagent-agent-network.gif`、`demo-multiagent-agent-network-zh-CN.gif` | 使用 Dashboard 播放按钮录制的中英文协作视图片段 |
| `demo-snake-taint-replay-zh-CN.png`、`demo-multiagent-agent-network-zh-CN.png` | 两段中文动画的结束帧 |
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
