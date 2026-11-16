# 按问题选择示例

[English](../demo-library.md) | 中文

先选择要调查的问题，再打开对应记录。下表沿用现有示例名称，将修复前后作为同一故事的不同章节。

## 推荐阅读路线

| 想回答的问题 | 从这里开始 | 接着查看 |
| --- | --- | --- |
| 检查和修复之间发生了什么变化？ | [证据归因](../../demo/evidence-attribution/README.zh-CN.md) | 原始任务、工具调用级意图、访问控制决策、保留的 TLS 正文、文件变化和修复后的 Run |
| 任务如何在 Agent 和工作负载之间传递？ | [多 Agent 协作](../../demo/multiagent-provenance/README.zh-CN.md) | 委派、消息和拒绝，再通过[跨 Pod 记录](../../demo/k8s-cross-pod-a2a/README.zh-CN.md)查看实际执行位置 |
| 浏览器或 Notebook 具体做了什么？ | [浏览器采集](../browser-context.zh-CN.md)和 [Notebook 采集](notebook-context.md) | 原生操作／请求身份、输出、截图、HAR、保存正文及离线回放 |

浏览器和 Notebook 指南通过可选的本地入口采集自己的任务，与内置历史实录分开展示。浏览器请求与工具操作各自保留原生身份；Notebook 的延迟输出和重启前后记录沿用对应请求的归属。

远端独立命令参见[执行交接指南](execution-handoff.md)。Sentry 事件采集参见 [gVisor 指南](gvisor-seccheck.md)。

## v1.0 候选示例看什么

[本地阅读器预览](../../previews/v1.0-reader/README.zh-CN.md)提供四个入口。
先了解每个案例发生了什么，再沿着对应证据阅读：

| 入口 | 案例经过 | 阅读顺序 |
| --- | --- | --- |
| 任务调查 | DeepSeek 在配置修复前后分别执行调查任务 | 先读任务和工具结果，再通过 Compare 查看两次 Run 的配置及文件变化 |
| 跨环境执行 | 两个 Claude 会话产生三个远端执行尝试，并演练回执响应丢失后的恢复 | 选中来源 Tool Call，进入目标 Run 与执行尝试，分别查看执行、采集、交付状态，再返回原调用 |
| Browser | Agent 通过记录式浏览器入口执行网页任务 | 展开 Agent 会话，进入 Browser／Notebook，查看操作的原生引用、正文、截图及相关请求记录 |
| Notebook | 合成 Jupyter 记录包含图表和一次 kernel 重启 | 查看请求与父消息引用，打开图表，对照重启前后的 kernel 身份 |

前三项使用候选版执行实录。Notebook 展示使用合成样本；此前真实 Claude Notebook
记录保留在[候选验收档案](../benchmarks/v1.0-candidate/README.zh-CN.md)中。
打开页面是在阅读已保存的观测，不会重新执行任务。预览保留现有图谱，补充局部阅读入口；
这些入口与下方已发布的 `agentprov demo` 目录分开。

## 故事章节与保留的入口

| 故事 | 现有入口名称 | 独有证据 |
| --- | --- | --- |
| 任务调查与修复 | `evidence-attribution`、`evidence-attribution-repaired` | 11 月的两份记录，包含工具调用级意图、审计和 TLS 归因详情 |
| 任务调查与修复 | `investigation-workflow`、`investigation-repaired` | 10 月的两份记录，包含审阅者、被拒绝的诊断、修复和对比 |
| 任务调查与修复 | `deepseek-context` | 9 月开发任务，包含七项测试记录、工具结果、配置和最终文件 |
| 协作与执行位置 | `multiagent-provenance` | 逻辑委派、同伴影响、拒绝和后续执行 |
| 协作与执行位置 | `k8s-cross-pod-a2a`、`k8s-substrate` | 跨 Pod 运行时事件和部署身份；A2A 指南单独标出回放的应用 hooks |
| 供应链调查 | `snake-supply-chain` | 恶意安装钩子、植入的测试凭据、网络尝试和制品历史 |
| 关联语义 | `endpoint-attribution` | 已签名的合成样本，展示正文命中、源读取候选和未确定的执行身份 |
| 外部评估器 | `llm-judge`、`jev-judge` | 可选的证据消费和人工复核示例；配置接入与回放分开进行 |
| Grok 历史调查 | `grok-codebase-exfil`、`grok-3routes` | 两份带日期的记录，各自保留 Run 和签名密钥 |

使用 `agentprov demo <入口名称>` 直接打开原记录。两组修复案例会一起载入对应的前后 Run，便于比较。旧 Run ID、签名和证据引用继续指向原来的记录。

## 记录类型

- **执行实录**：保存某次执行的观测结果。指南列出已记录的采集环境、来源和日期。
- **混合来源**：应用上下文和运行时事件来自不同采集过程。K8s A2A 示例分别标注两者来源。
- **合成样本**：用构造的输入解释关联语义。外发归因示例使用公开标记。
- **评估器接入**：消费已有证据。无密钥 fixture 用于验证接入流程；在线研判需要指南列出的凭据。

## Grok 历史记录

Grok 原场景当前无法复现。两份原记录继续支持签名校验、导入、调查和离线回放。[历史指南](../../demo/grok-codebase-exfil/README.zh-CN.md)分别说明已观察到的模型请求正文、厂商遥测和第三方分析请求。

新版阅读器展示历史记录时，保留原采集日期、证据和签名。重新采集的示例使用新的 Run ID 和独立签名包。

## 分享调查结果

在 Dashboard 的导出预览中选择 Run、会话和保存的记录。生成的只读目录可以脱离原始工作区打开。选择性阅读副本与原始签名证据包分别交付；需要校验签名时，同时保留原包和公钥。

## 加载记录

静态站点先读取轻量目录，再加载所选 Run 的索引和证据。比较两次运行或查看关联会话时，按需读取另一份记录。历史档案在打开前保持未加载状态。

旧回放链接和原始签名包继续保留。阅读器也支持使用单一清单的旧站点，以及自包含的离线导出目录。

在同一台机器上比较两份导出站点，可安装 Playwright 依赖后运行 `node scripts/bench_static_replay.cjs BEFORE_DIRECTORY AFTER_DIRECTORY`。设置 `PLAYWRIGHT_CHANNEL=chrome` 可使用已安装的 Chrome。JSON 报告分别记录冷、热缓存下的传输字节数、图谱可用时间和保留的 JavaScript 堆内存，并附上浏览器、CPU 与源码提交。

返回[示例命令目录](../../demo/README.zh-CN.md)或[项目快速开始](../../README.zh-CN.md#快速开始)。
