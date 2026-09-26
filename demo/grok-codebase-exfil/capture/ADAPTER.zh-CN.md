# Grok 端点适配器设计草案

[English](ADAPTER.md) | 中文

本文记录早期端点适配器设计。最终实现位于 `internal/provenance/endpoint.go` 的 `IngestEndpointDump`，通过 `graph ingest-endpoint` 使用。采集结果见[示例指南](../README.zh-CN.md)。

## 要解决的问题

将受控端点记录的流量（fake-xai 转储目录或 mitmproxy 流）与本地会话存储接入已有图模型，复用现有视图和意图分析。Grok 适配器负责格式转换；受控端点采集模型流量的方式，也可用于 libssl 探针无法读取明文的其他 rustls／Rust Agent。

## 原计划的请求分类

按请求路径分类，生成对应的图节点和内容对象：

| 路径 | 含义 | 计划生成的证据 |
|---|---|---|
| `/v1/chat/completions` | 模型轮次，包含 Grok 系统提示词和 `<user_query>`；响应为 SSE 流 | 请求和响应对象组成 `llm_call`。如果响应只有文本、没有 `tool_calls`，捕获到的声明也只有文本 |
| `/responses` | 会话标题生成等辅助模型调用 | 辅助 `llm_call`，或按用途跳过 |
| `/v1/upload/storage`、`/v1/traces` | 原草案计划检查的源码包／会话轨迹外发 | `data_egress`：正文按内容寻址，检查 `# v2 git bundle` 标记，并匹配测试仓库中的识别字符串 |
| `api.mixpanel.com/track` | 产品分析 | 标为分析遥测的 `data_egress`，按载荷内容判定风险 |

## 计划生成的数据

- `/chat` 和 `/responses` 复用 `llm_message` 对象化路径生成 `llm_call`，类似 `MaterializeLLMCalls`，但来源为端点采集。模型没有声明工具调用时，只能建立“捕获到文本声明”的意图约束。
- `/v1/upload|traces` 生成拟议的 `data_egress` 节点，包含对象化载荷、目标主机、大小和测试标记命中情况，用于检查没有对应声明的效果。
- 可选读取 `~/.grok/sessions/<url-encoded-workspace>/` 和 `session_search.sqlite`，补充 Grok 自身的会话视图。

这里保留原草案中的节点命名。当前端点摄入路径将外发内容写成 `endpoint_capture` 来源的 `network_connect` 事件及内容寻址的载荷描述，沿用现有表结构。

## 与意图分析衔接

原设计通过 `intent.Materialize` 比较模型声明与运行时效果：若模型只声明文本，内核却观测到 `.env`、`.aws`、`.claude` 的 `secret_read`，且端点载荷确实包含对应数据，则可以结合两类独立来源检查 `declared_vs_effect_mismatch` 或 `intent_coverage_gap`。

前者表示效果超出声明范围，后者表示缺少对应的意图记录。

## 原计划的接入位置

草案拟新增类似 `internal/hooksbridge` 的 `internal/endpointbridge`，提供 `Ingest(db, dumpDir, run)`：遍历 `*.meta.json` 和 `*.body.bin`，按路径分类、保存正文对象，并生成 `llm_call` 与 `data_egress`。命令拟为 `graph ingest-endpoint --run --dump <dir>`，形式参照 `graph harvest-transcripts`。最终实现位置见页首。

## 当时的实施顺序

- **已有载荷可支持的部分**：先将 `/chat`、`/responses` 接入 `llm_call`，再将传感器下运行 `capture-grok.sh` 所得到的内核事件一起分析。
- **仍依赖真实上传的部分**：源码包外发分析需要实际 `/v1/upload` 或 `/v1/traces` 正文。草案将账号配置和零数据保留（ZDR）视为可能的影响条件，提出模拟允许上传的账号配置，或在授权账号上通过 mitmproxy 观察。

后续实验结果见示例指南。
