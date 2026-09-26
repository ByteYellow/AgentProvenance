# Grok 源码外发示例的原始采集设计

[English](DESIGN.md) | 中文

本文记录无需密钥的早期采集设计，实际采集结果与复现情况见[示例指南](../README.zh-CN.md)。

## 当时要复查的第三方报告

第三方报告称，基于 Rust 的官方 xAI CLI `@xai-official/grok@0.2.93` 会将仓库及 Git 历史打成 `before_/after_codebase` Git bundle，上传到 `api.x.ai/v1/upload/storage` 和 `/v1/traces`，涉及 GCS 的 `grok-code-session-traces`；报告称该行为不取决于用户任务或 Agent 声明读取的文件。

当时在二进制中找到的字符串包括 `before_codebase`、`after_codebase`、`git bundle`、`grok-code-session-traces`、`GROK_STORAGE_MODE` 和 `GROK_CLAUDE_*_ENABLED`。实验据此检查相关路径的运行时行为和发送内容。

## 针对 rustls 的采集设计

该版本 Grok 的 HTTP 客户端使用 rustls，libssl 的 `SSL_write` uprobe 无法读取其明文。因此，原设计用受控端点记录请求和响应，配合内核事件形成三类证据。

**① 内核事件。** eBPF 传感器观测 Grok 所在 cgroup 的系统调用：对 `.env`、`.aws/credentials`、`.claude/*` 的 `openat`／读取，即 `secret_read`；对 `*codebase*.tar` 或 bundle 的 `write`，即 `file_write`；以及到端点的 `connect()`，即 `network_connect`。

**② 模型请求与外发载荷。** 通过 `XAI_API_BASE_URL` 将 Grok 指向本地 fake-xai。模拟服务对 `/v1/chat/completions` 返回单词、无工具调用的回答，让客户端继续运行；如果收到 `/v1/upload/storage` 或 `/v1/traces` 请求，则接受并保存正文。原设计假设聊天和上传共用同一 API 基地址，从而在虚拟机内记录两类请求。首次实验先核对这一假设。

**③ 应用上下文。** 草案计划从 `/v1/traces` 的会话同步流量补充上下文，再按聊天请求、上传和轨迹载荷分类。这些格式转换组成第二阶段的 Grok 适配器。

## 希望在图中对照的差异

设计流程：

```text
用户：“只回复一个单词”
  模拟模型响应：文本 “ok”，没有工具调用                  ← 证据来源 ②
  已捕获的意图：没有声明文件或网络操作
    计划检查的运行时事件（证据来源 ①）：
      读取 .env / .aws/credentials / .claude/settings.local.json  (secret_read)
      写入 before_codebase / after_codebase bundle                (file_write)
      连接并 POST /v1/upload/storage，正文为仓库 Git bundle         (network_connect)
        └─ declared_vs_effect_mismatch / intent_coverage_gap
```

## 原计划的三个阶段

- **基础阶段**：准备带识别标记的合成仓库、fake-xai 端点和 record／传感器采集，执行对象化、意图比较、校验、签名及导出，保留内核证据和端点原始正文。尚无适配器时，没有关联到意图的效果表现为 `intent_coverage_gap`。
- **第二阶段**：将 `/v1/chat`、`/v1/upload`、`/v1/traces` 的已捕获正文接入 `llm_call` 和外发证据，对照三类来源，并让相同方式可复用于其他 rustls／Rust Agent。具体转换方案见[适配器草案](ADAPTER.zh-CN.md)。
- **可选在线阶段**：配置实际 xAI 凭据后，观察真实服务响应。无密钥实验则通过本地端点记录上传尝试和正文。

## 实验环境与记录

- 使用合成仓库、模拟秘密和隔离虚拟机，将请求引导至本地端点。
- 固定 Grok 版本 `0.2.93`，记录二进制 SHA-256、模拟服务响应和时间戳。
- 为“不应读取”的各文件设置不同标记，在已捕获正文中查找，从内核读取和载荷内容两个来源核对文件流向。
- 区分默认配置、主动改写的实验开关（如 `GROK_STORAGE_MODE`），以及后续服务端关闭的情况。

## 首次运行用于发现实际协议

fake-xai 记录收到的请求方法、路径、头和正文。第一次实验用于核对聊天路径、请求格式、是否接受 HTTP 基地址、是否强制 HTTPS 与可信 CA，以及上传路径和正文格式。根据结果调整模拟服务，再执行正式采集。
