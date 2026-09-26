# 使用 LLM 分析执行证据

[English](README.md) | 中文

本示例让外部模型读取一次执行的完整事件轨迹，返回结构化安全结论，再将结论写入 AgentProvenance，作为带证据引用的信号。

评估器自身通过 `agentprov record` 运行。它的模型请求和响应会保存为 `tls_write`、`tls_read` 证据，并生成 `llm_call` 节点，因此可以追溯某条评估结论使用了哪些模型调用。

```text
待分析的执行记录                    评估器的执行记录
全部运行时事件、视图摘要 ────────→ judge.py
风险与验证结果                       ├─ 按预算分段处理轨迹
                                     ├─ 调用外部模型
带证据引用的信号 ←───────────────────┘
                                     └─ 保存请求、响应和哈希
                                        生成评估器自身的 llm_call 节点
```

## 打开指南

下载并解压[预编译版本](https://github.com/ByteYellow/AgentProvenance/releases/tag/v0.8.2-rc.2)，执行：

```sh
./agentprov demo llm-judge
```

此命令只打开离线阅读页，不会运行评估器或请求模型服务。页面首次打开时跟随浏览器语言，未匹配时使用英文；右上角可手动切换，后续访问会保留选择。实际评估需要另行执行下述步骤。

## 界面与命令语言

命令默认使用英文；加上 `--lang zh-CN` 可查看中文帮助、进度、结论标签和错误提示。评估提示词、模型原始回答、请求响应和导出 JSON 保持原样。摘要和发现中的原文会明确标注；离线结果会说明未调用模型。

```sh
python3 demo/llm-judge/judge.py --lang zh-CN --help
AGENTPROV_BIN="$PWD/agentprov" python3 demo/llm-judge/judge.py run --offline --lang zh-CN
```

## 运行示例

在发行包根目录运行不需要密钥的离线流程：

```sh
AGENTPROV_BIN="$PWD/agentprov" python3 demo/llm-judge/judge.py run --offline
```

离线流程使用预设结论，演示从读取证据到导入评估结果的完整过程。

在源码目录中，可进入 `demo/llm-judge/` 执行：

```sh
python3 judge.py run
python3 judge.py run --offline
python3 judge.py run --run <id> --data-dir <dir>
```

将 `<id>` 和 `<dir>` 替换为已有执行记录及其数据目录。脚本仅依赖 Python 标准库；未设置 `AGENTPROV_BIN` 时会构建 CLI。`run` 负责导入证据、在 `record` 下启动 `judge` 子命令、保存模型调用证据，再导入评估信号。

## 配置模型服务

评估器使用 HTTP 接口和项目已有的证据契约。可通过环境变量选择 Anthropic 或 OpenAI 兼容协议；兼容服务仍需实际验证接口行为。脚本自动读取共享示例配置 `~/.agentprov-demo/deepseek-claude.env`。

| 协议 | 服务地址 | 密钥变量 | 使用示例 |
|---|---|---|---|
| `anthropic` | `ANTHROPIC_BASE_URL`，默认 `api.anthropic.com` | `ANTHROPIC_AUTH_TOKEN` 或 `ANTHROPIC_API_KEY` | Claude、Anthropic 兼容代理 |
| `openai` | `OPENAI_BASE_URL`，默认 `api.openai.com` | `OPENAI_API_KEY` | OpenAI、Qwen、Moonshot、vLLM、Ollama |
| `openai`，DeepSeek 配置 | 使用脚本中的 DeepSeek 快捷配置 | `DEEPSEEK_API_KEY` | DeepSeek 原生接口 |

Ollama 可使用本地地址，例如 `http://localhost:11434`。当环境中存在多个密钥时，`AGENTPROV_JUDGE_PROVIDER=anthropic|openai` 用于指定协议，`AGENTPROV_JUDGE_MODEL` 用于选择模型。

不同服务的请求和响应都由评估器保存哈希，并附加到评估器自己的执行记录。未提供凭证时，脚本使用离线预设模式，结论来自已有风险信号，并明确标注来源。

## 事件覆盖与证据来源

### 处理全部事件

脚本序列化 `EvalContext` 中的全部 `runtime_event`，不按事件类型筛选。载荷只做与事件类型无关的压缩整理，因此新增的 `dns_query`、`setuid` 或 TLS 事件也能进入评估输入。

### 按调用预算分段

轨迹超过单次调用预算时，脚本按时间顺序分段，先取得各段观察结果，再汇总最终结论。输出中的 `coverage` 保存事件总数、分段数量和处理模式，便于检查实际覆盖范围。

### 区分应用上报与内核采集

macOS 示例通过 `telemetry ingest-jsonl --format native` 写入评估器的模型交互，属于应用侧上报。Linux 环境中若运行了 eBPF 传感器，并成功挂载对应 SSL uprobe，还可取得独立的运行时证据。是否具有后者取决于实际挂载和采集结果，不能因平台是 Linux 就自动视为内核已验证。

## 使用的公共接口

| 步骤 | 接口 |
|---|---|
| 读取证据 | `signal context --run`、`ai call verify_run/list_risks/get_signals`、`graph lens --json` |
| 写入结论 | `signal import --run --file`，写入 `signals` 表的质量维度 |
| 记录评估器 | `record --json -- python3 judge.py judge ...`、`telemetry ingest-jsonl --format native`、`graph materialize-llm` |

`signal import-batch` 只验证输入，不负责持久化；不要用它替代 `signal import`。

## 当前显示范围

导入的质量信号可通过 `signals list`、`ai call get_signals` 和页面的信号面板查看。安全图视图当前读取 `risk_signals`，不会将这些质量信号直接画成节点。

结论通过 `graph_ref_kind=run` 引用执行记录。它仍然是外部评估器的判断，不能替代原始运行时事件或视为传感器观测事实。
