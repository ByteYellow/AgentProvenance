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

正文投影保留纯文本、按文本阅读的 HTML／Markdown 和 JSON。PNG、JPEG 输出保存为
独立的内容寻址附件，base64 图片数据不进入会话正文或来源投影。SVG 等其他 MIME
内容保留省略原因及来源值摘要。`raw_content.reason=notebook_protocol_projection`
标明这是筛选后的来源投影。记录器继续拒绝传输二进制 buffers。

### 图片附件

详细档默认保存图片，基础档默认省略。`--capture-attachments=true|false` 可以独立
覆盖这一选择；没有显式设置时，附件跟随 `--capture-tool-results`。设置在同一 Run
中保持固定，主动省略图片时仍保留原生输出关系。

PNG、JPEG 经过解码和检查后，重新编码为静态 PNG。附件分别记录来源和留存图片的
字节摘要、尺寸及 `transformation: raster_reencode/v1`。重新编码会移除原图元数据
和尾部数据；图中可见内容保持原样，不做 OCR 脱敏，并标注
`privacy: visual_content_unredacted`。分享前应检查图片中的敏感内容。

| 项目 | 限额 |
| --- | --- |
| 来源或留存图片 | 每张各 8 MiB |
| 图片尺寸 | 每边最多 8,192 像素，总计最多 16,777,216 像素 |
| 每条记录附件 | 32 个 |
| 每个 Run 的独立附件 | 256 个，留存图片字节合计 64 MiB |
| 单次读取 | 最多 256 KiB 解码后字节 |

无效或超限图片保留省略原因和来源摘要。Run 限额跨导入累计；重复导入相同输出时
复用附件。原始采集文件继续受导入前的文件与消息大小限制。

从 `context list` 的 `entries[].attachments` 取得引用后，分页读取：

```bash
agentprov context attachment --run RUN_ID --ref sha256:ATTACHMENT_HASH --limit 65536
```

JSON 中的 `data` 为当前页的 base64，`offset` 和 `next_offset` 按解码后的字节计数，
`sha256` 对应整张留存图片。HTTP 接口为
`GET /v1/context/attachment?run=RUN_ID&ref=sha256:ATTACHMENT_HASH`。

签名 Bundle 包含图片清单与分块。只分享文字、排除指定图片时执行：

```bash
agentprov dashboard export --run RUN_ID \
  --exclude-attachment sha256:ATTACHMENT_HASH --output text-replay.zip
```

该参数可以重复指定；本地导出 API 和选择文件使用 `exclude_attachments`。
显式排除某个附件引用，会排除所有已选记录中使用该引用的图片；排除整条记录时，
其他已选记录独立使用的图片继续保留。只读 ZIP 保存排除标记，原证据和签名包保持原样。

## 真实协议用例

在独立 Python 环境中，从仓库根目录执行：

```bash
python -m pip install jupyter-client==8.6.3 ipykernel==6.29.5
PYTHONPATH=python python scripts/accept_notebook.py --output /tmp/notebook-acceptance
```

加上 `--agentprov /path/to/agentprov` 可通过公共 CLI 验证两档留存、重复导入、图谱投影、
原生输出关系、签名导入导出，以及移走原存储后的读取。脚本在私有输出目录生成验收专用
签名密钥，结果保存到 `cli-results.json`。

加上 `--attachments` 会在重启后的 kernel 中根据 CSV 数值生成真实 PNG 图表，
并记录一段按文本读取的 HTML 输出。与 `--agentprov` 一起使用时，还会验证图片分页、
签名往返、详细档关闭图片，并生成包含图片和排除图片的两份回放 ZIP。

输出目录必须尚不存在。用例启动自己的 kernel，记录两个客户端、后台迟到输出，
随后重启 kernel，将 CSV 求和结果写入 `result.json`；退出时停止自己的 kernel 并
清理连接资源。`first.jsonl`、`restarted.jsonl` 可以导入同一 Run，两个 kernel
生命周期分别保留。`result-manifest.json` 记录实际原生 ID 和版本。这是 Jupyter
接入验收，没有调用模型。

协议依据：[Jupyter 消息协议](https://jupyter-client.readthedocs.io/en/stable/messaging.html)。
