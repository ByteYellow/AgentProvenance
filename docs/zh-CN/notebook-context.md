# Jupyter 请求与输出上下文

[English](../notebook-context.md) | 中文

记录选定 Jupyter 客户端的原生消息，再导入 AgentProvenance Run。适配器保留
请求与输出，不改变 kernel 的执行和重试行为。

## 接入方式

使用仓库可选 Python 包中的 `agentprov.notebook.Recorder`。记录器本身没有
Jupyter 依赖；真实协议用例使用 `jupyter-client==8.6.3` 和 `ipykernel==6.29.5`。

客户端连接并完成就绪检查后，从 `kernel_info_reply` 读取 kernel session。
由工具入口配置 producer、namespace、实例、生命周期代次、Notebook 和 kernel
资源 ID，传给记录器。完整代码见[英文指南](../notebook-context.md#integration)。

在现有工具收发位置增加记录：

```python
client.shell_channel.send(request)
capture.record("shell", "send", request)

# 在现有接收循环中记录解码后的消息：
capture.record("iopub", "receive", message)
capture.record("shell", "receive", reply)
```

继续沿用工具的接收循环和取消策略。记录器不消费消息队列，不代发请求；一次记录
失败后，需要查询原请求状态，避免盲目重发。每个通道选一个采集点，避免重复保存
广播消息。连接文件、认证密钥和 ZeroMQ 路由帧不进入记录。

输出使用新的 `0600` 文件，包含原始输入输出，按私有日志保存。导入时使用现有
脱敏及正文留存策略：

```bash
agentprov context import --run RUN_ID --harness jupyter --file capture.jsonl --capture detailed
agentprov context project --run RUN_ID
agentprov context list --run RUN_ID
agentprov context coverage --run RUN_ID
```

新 Run 可以选择 `--capture basic`，省略结果正文和来源投影；详细档也可以通过
`--capture-tool-results=false` 排除结果。两档均保留请求及父请求身份。私有采集文件
与已留存证据分开管理，源文件的保留和删除由调用方决定。

## 关联与生命周期

- producer、namespace、实例和代次由启动入口提供，kernel session 来自原生回复。
  本地导入按来源声明保存这些字段，远端身份认证继续使用执行交接契约。
- 来源身份包括 Notebook、kernel 资源及 kernel session。kernel 重启后使用新文件；
  重连同一存活 kernel 沿用原身份。恢复或克隆的执行实例由外部入口分配新代次。
- 请求身份包含来源作用域、客户端 session 和消息 ID。回复、流式输出使用
  `parent_header`，即使另一客户端已经发起新请求，也保留原父请求。执行序号和时间
  只用于展示。
- 缺少父请求的输出留在 kernel 级，并显示缺口。消息 ID 内容冲突或 kernel session
  意外变化时，导入状态为 `ambiguous`，不连接这些记录。
- 只有 shell 通道的 `execute_reply` 提供请求结束结果。流式输出、显示更新、`idle`
  分别保存，不提前关闭调用。共享 kernel 的系统事件沿用进程或作用域级归属。

`context project` 从已保存的上下文显式重建图谱关系，追加导入后可重复执行；它不执行工具输入，
也不改写原记录。`context import` 保持只导入的行为。新增的 `source.notebook`、`entry.notebook`
字段见[上下文 API](../agent-context-api.yaml)，没有增加远端写接口。

## 正文与限额

记录器默认最多 128 MiB、24,998 条消息，单条最多 32 MiB，可调低。超限时追加
`notebook_gap` 并返回错误，导入后显示采集缺口；导入本身继续受已有处理预算限制。

正文投影保留纯文本、以文本阅读的 HTML／Markdown 和 JSON。其他 MIME 内容从
正文和来源投影中省略，在 `omitted_content` 中记录类型及原始 JSON 值的摘要。
`raw_content.reason=notebook_protocol_projection` 标明这是经过筛选的来源投影。
当前记录器拒绝传输二进制 buffers；图片等类型化附件及专用阅读器后续单独接入。

签名 Bundle 保留原生消息头、作用域、留存正文及图谱引用。现有选择性导出按整条
上下文记录应用选择范围。

## 真实协议用例

在独立 Python 环境中，从仓库根目录执行：

```bash
python -m pip install jupyter-client==8.6.3 ipykernel==6.29.5
PYTHONPATH=python python scripts/accept_notebook.py --output /tmp/notebook-acceptance
```

加上 `--agentprov /path/to/agentprov` 可通过公共 CLI 验证两档留存、重复导入、图谱投影、
原生输出关系、签名导入导出，以及移走原存储后的读取。脚本在私有输出目录生成验收专用
签名密钥，结果保存到 `cli-results.json`。

输出目录必须尚不存在。用例启动自己的 kernel，记录两个客户端、后台迟到输出，
随后重启 kernel，将 CSV 求和结果写入 `result.json`；退出时停止自己的 kernel 并
清理连接资源。`first.jsonl`、`restarted.jsonl` 可以导入同一 Run，两个 kernel
生命周期分别保留。`result-manifest.json` 记录实际原生 ID 和版本。这是 Jupyter
接入验收，没有调用模型。

协议依据：[Jupyter 消息协议](https://jupyter-client.readthedocs.io/en/stable/messaging.html)。
