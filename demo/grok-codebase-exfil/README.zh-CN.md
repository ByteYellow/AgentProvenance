# Grok 数据外发：两份历史采集记录

[English](README.md) | 中文

本目录保存 `@xai-official/grok` 0.2.93 的两份签名证据包，对应[公开复现项目](https://github.com/cereblab/grok-build-exfil-repro)固定的版本。证据可离线导入和验证。以下结论仅描述记录时的实验，不代表 Grok 当前版本或服务端行为。

| 证据包 | 调查内容 | 证据范围 |
|---|---|---|
| `run-grok-exfil` | 代码仓库及 Git 历史打包上传的历史调查，即路径 ② | 原采集日志记载了被阻断的上传，但该日志已不在手边；已提交证据图仅保留 `/traces` 外发，不能单独证明完整仓库上传 |
| `run-grok-3routes` | 假凭据进入模型请求，以及厂商遥测和第三方分析数据，即路径 ① 等 | 三个标记字符串出现在 `/responses` 请求正文中；读取文件是提示词明确要求的行为 |

## 打开回放

下载并解压[预编译版本](https://github.com/ByteYellow/AgentProvenance/releases/tag/v0.8.2-rc.2)，执行：

```sh
./agentprov demo grok-codebase-exfil
./agentprov demo grok-3routes
```

程序先验证签名，再打开对应的执行记录和视图。数据保存在临时目录，按 Ctrl-C 退出时清理。回放无需 Go、虚拟机、Kubernetes 或 Grok 账号。

运行 `./agentprov demo` 可查看全部示例。页面首次打开时跟随浏览器语言，未匹配时使用英文；右上角可手动切换，后续访问会保留选择。

## 2026 年 7 月的复现情况

2026 年 7 月 15 日，项目使用 0.2.93（构建 `f00f96316d`）进行了约 10 次重新采集，未再观察到代码仓库上传：

- 继续使用 `cli-chat-proxy.grok.com`，确认 `/settings` 中的实验开关改写已生效。
- 使用从未上传过的新工作区，并模拟 `GET /bundle/archive` 返回 404。
- 没有观察到 `POST /storage`；逐请求检查也未发现 Git bundle 从其他端点发出。最大上传是约 47 KB 的模型 `/responses` 请求。
- 客户端 `/sessions/<id>/signals` 中的上传队列计数均为 0，包括 `gcsQueueEnqueued`、`gcsQueueUploaded` 和 `gcsQueuePendingBytes`。

2026 年 7 月 14 日的项目日志曾记录 `/storage` 上传，但原始网络日志已不在手边。当时的摄入逻辑仅在已提交证据图中保存了 `/traces`，因此无法据此逐请求比较两天的差异。

“服务端关闭了相关行为”是一种解释，尚未经厂商确认，也不是这些证据已经证明的事实。不要把历史实验表述为当前仍可复现的漏洞。

`/sessions/<id>/signals` 和 `/sessions/<id>/turn-deltas` 是厂商的使用统计接口，包含轮次、延迟、代码行数和队列状态；接口存在本身不能证明上传了代码仓库。7 月 14 日的包中已有 `/signals`，它不是后来新增的端点。

## 证据包一：代码仓库上传的历史调查

原实验向 Grok 发出的指令仅为：

```text
grok -p "Reply with the single word: ok."
```

模型声明只回复 `ok`，没有声明工具调用。原采集过程另行记录了敏感文件读取、代码仓库打包，以及代理阻断上传的行为。由于原始网络日志已缺失，这段过程说明不能代替当前证据包中实际可查到的内容。

实验还主动修改了服务端返回的开关：该账号原本收到 `trace_upload_enabled=false` 和 `disable_codebase_upload=true`，采集代理在 `/settings` 响应中翻转这些值，并记录原值。因此，这是人为触发客户端既有代码路径的实验，不代表账号默认配置下就会发生上传，也不属于厂商已确认的结论。

## 证据包二：模型请求中的假凭据

第二次实验明确要求 Grok 读取预置文件，包括 `.env`、`SECRET_DO_NOT_READ.md` 和 `.claude/`。三个标记字符串随后出现在 `/responses` 的模型请求正文中，说明这些内容进入了模型上下文。

外发数据视图将这类内容标为 `model_inference / secret / critical`。这是系统的分类结果，不能据此把用户要求的文件读取说成隐蔽窃取。

本次记录还区分了 `/traces` 厂商遥测和 Mixpanel 产品分析。可复现的描述仅对应当时的实验，当前状态需要重新采集确认。

## 采集方式

该版本 Grok 使用 rustls，不能依靠本示例使用的 libssl uprobe 读取明文。采集由三个来源组成：

| 来源 | 记录内容 |
|---|---|
| eBPF 传感器 | Grok 所在 cgroup 的敏感文件读取和进程执行 |
| 受控代理 | 实际上游 `host`、模型请求、外发请求及阻断结果；由 `graph ingest-endpoint` 导入模型调用和外发节点 |
| Grok harness 适配器 | `hooks bridge --harness grok` 读取 `chat_history.jsonl`，保存模型声明的回复及工具调用 |

代理承担实验中的阻断。eBPF 传感器作为独立来源记录运行时行为，不能将两者的作用混为一谈。

## 手动导入与查看

在源码或发行包根目录执行：

```sh
agentprov --data-dir /tmp/grok-view init
agentprov --data-dir /tmp/grok-view forensics import \
  demo/grok-codebase-exfil/run-grok-exfil.forensics.json.gz \
  --pub-key demo/grok-codebase-exfil/attestation.pub
agentprov --data-dir /tmp/grok-view forensics import \
  demo/grok-codebase-exfil/run-grok-3routes.forensics.json.gz \
  --pub-key demo/grok-codebase-exfil/run-grok-3routes.attestation.pub
agentprov --data-dir /tmp/grok-view graph verify --run run-grok-exfil
agentprov --data-dir /tmp/grok-view graph verify --run run-grok-3routes
agentprov --data-dir /tmp/grok-view dashboard serve
```

两次图验证预期返回 `status=ok`、`errors=0`。打开页面后查看外发数据视图（Outbound Data Surfaces）。签名和图验证只能检查保存下来的证据，不能恢复缺失日志。

## 重新采集

需要隔离的虚拟机、Grok CLI 登录状态和 `CAP_BPF` 权限。`capture/` 中包含：

- `make-canary-repo.sh`：生成测试仓库、假凭据和逐文件标记字符串。
- `grok-proxy.py`：转发到 `cli-chat-proxy.grok.com`，使用 Grok 自身的 OAuth Bearer，改写并记录实验开关，记录和阻断 `/storage`、`/traces` 等请求。
- `capture-grok-full.sh`：组织 `record`、传感器、代理和最终封存。

登录入口为 `grok login --device-auth`。路径 ② 在 2026 年 7 月 15 日已无法复现；路径 ① 当时仍可复现。重新实验时应记录版本、时间、服务端原始配置和实际结果，不能假设历史行为仍然存在。

## 如何理解验证结果

实验使用合成仓库和假凭据，通过标记字符串判断哪些文件内容进入请求。声称上传已被阻断时，应有对应代理记录支持。开关改写是实验条件，必须与结果一起披露。

两份证据包均有 DSSE 签名。签名证明内容与签名时一致，不保证采集完整、每条推断正确，也不将第三方调查结论变成厂商确认。
