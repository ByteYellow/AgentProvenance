# AgentProvenance 使用入门

[English](../release-start.md) | 中文

解压后，在当前目录打开示例库：

```sh
./agentprov demo
```

点击**打开回放**查看签名执行记录，点击**阅读指南**查看图文说明。
包内共有七份回放和九篇指南。回放无需 Go、Docker、Agent 账号或 API Key。

## 先看 DeepSeek 开发任务

```sh
./agentprov demo deepseek-context
```

真实 Agent 给 Python 报表增加按日汇总，并通过七项测试。
执行图谱在上，**Agent 会话在下，默认收起**。展开会话可以查看任务和工具结果，
在**权限与配置**中了解当时的设置，在**采集情况**中查看记录范围。
选择图中的文件即可打开已保存的正文，收起会话后仍能继续阅读。

CLI 先校验签名，再导入独立的临时目录。回放可以离线使用，不会重新运行记录中的命令。
按 Ctrl-C 退出时，程序关闭本地服务并清理临时数据。

## 查看其他示例

```sh
./agentprov demo --list
./agentprov demo multiagent-provenance
./agentprov demo k8s-cross-pod-a2a
./agentprov demo --no-browser
```

`--no-browser` 只输出本地地址。运行在远程机器上时，可通过端口转发访问。
`demo/` 目录包含原始证据包、公钥、脚本和指南；重新采集所需的环境见各指南。

LLM Judge 和 Jev 是可选的 Python 接入示例，打开指南不会调用模型。
以下命令用预设结果体验 LLM Judge 的离线接入流程：

```sh
AGENTPROV_BIN="$PWD/agentprov" python3 demo/llm-judge/judge.py run --offline
```

Jev 需要 Python 3.9+；实际评估还需要模型凭据，并允许发送选定的证据。
步骤见 [Jev 指南](../../demo/jev-judge/README.zh-CN.md)。已完成的评估可离线重新打开。

## 语言

网页首次打开时跟随浏览器语言，无法匹配时使用英文；手动切换 English / 中文后保留选择。
命令行默认输出英文，命令、路径、ID、JSON 和原始证据保留原文。
已有的 `--lang zh-CN` 可以选择中文帮助及已支持的中文输出，并用中文打开网页。

## 平台与校验

- Linux 包附带可选的原生传感器；内核采集需要相应内核、cgroup 和 BPF/perf 权限。
- macOS 支持应用侧记录与回放。CLI 尚未经过 Apple Developer ID 签名或公证。
- Windows 用户在 WSL 中使用 Linux 包。
- `SHA256SUMS` 和 `.sha256` 用于检查下载完整性；示例公钥用于验证证据签名。
  原始采集记录了哪些内容，在“采集情况”中单独说明。

内置指南和图片支持离线阅读，访问外部链接时才需要联网。
