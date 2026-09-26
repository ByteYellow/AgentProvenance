# AgentProvenance 使用入门

[English](../release-start.md) | 中文

解压后，在当前目录执行：

```sh
./agentprov --version
./agentprov demo
./agentprov demo --list
./agentprov demo multiagent-provenance
```

CLI 内置六份签名采集记录和全部示例指南，无需安装 Go。回放支持离线使用，只读取证据，不会执行记录中的命令。数据保存在临时目录，按 Ctrl-C 退出时清理。

程序会在本机回环地址打开浏览器。没有图形界面时，可添加 `--no-browser`，再使用输出的地址。

## 选择语言

命令行默认使用英文，添加 `--lang zh-CN` 可切换中文帮助和输出：

```sh
./agentprov --lang zh-CN --help
./agentprov --lang zh-CN demo
```

显式选择会同时应用到打开的网页。未指定时，网页跟随浏览器语言。JSON、命令、路径、ID 和证据正文保留原样。

## 查看示例

示例库中的“打开回放”用于查看证据，“阅读指南”用于打开带目录、图片、表格和代码复制按钮的说明页。两者沿用 Dashboard 的视觉样式。

示例库和指南首次打开时跟随浏览器语言，无法匹配时使用英文。右上角可切换 English 或中文；手动选择后，后续页面会保留选择。

指南正文已内置，查看它们无需网络。点击指向仓库或外部网站的链接时，需要联网。

## 运行可选评估器

压缩包的 `demo/` 目录包含全部示例、原始签名、公钥、脚本和文档。LLM Judge 与 Jev 是独立的 Python 示例，需要另行运行；打开阅读页不会调用模型服务。

LLM Judge 提供不需要密钥的离线流程：

```sh
AGENTPROV_BIN="$PWD/agentprov" python3 demo/llm-judge/judge.py run --offline
```

该流程使用预设结论检查集成，不代表实际模型评估。

Jev 需要 Python 3.9+。实际评估还需要密钥，并明确允许发送选定的原始证据，详见 [Jev 中文指南](../../demo/jev-judge/README.zh-CN.md)。命令使用压缩包中 `agentprov` 的绝对路径；只有选择从源码构建时才需要 Go。已完成的 Jev 评估可以离线重新打开。

重新采集的环境要求见各示例指南。

## 平台支持

- Linux 压缩包附带可选传感器。使用 eBPF 时，仍需满足内核和权限要求。
- macOS 支持回放和应用侧记录，不提供 Linux eBPF 采集。
- Windows 用户应在 WSL 中使用对应架构的 Linux 压缩包。

## 验证下载与证据

`SHA256SUMS` 和各压缩包的 `.sha256` 文件用于检查下载完整性，不是发布者签名。CLI 使用随包公钥校验示例证据；校验通过表示证据内容与签名时一致，不代表采集完整，也不证明全部因果推断正确。

macOS CLI 二进制尚未使用 Apple Developer ID 签名，也未经过公证。
