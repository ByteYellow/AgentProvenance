# 升级到 v0.10.1

[English](../upgrading-v0.10.1.md) | 中文

本文说明计划发布的 v0.10.1 变化，适用于集成分支的源码构建。
当前最新正式版仍为 v0.10.0。

升级前先停止写入，备份完整数据目录。需要回退时，将旧版程序与这份备份一起使用。
原始签名证据包及其公钥保持不变。

## 选择执行方式

本地 `launch` 和 `record` 保留终端输入、Ctrl-C、长任务、调用方环境变量和任意工作目录。
交互式 Agent、API Key、代理变量和虚拟环境建议通过本地命令使用：

```sh
agentprov --data-dir "$HOME/.agentprov" launch --workdir "$PWD" -- claude
agentprov --data-dir "$HOME/.agentprov" record --workdir "$PWD" -- python3 task.py
```

需要鉴权的 HTTP `POST /v1/record` 接口使用独立的执行策略：

| 设置 | HTTP 默认行为 | 迁移方式 |
| --- | --- | --- |
| 执行超时 | 60 秒 | 长任务可设置 `daemon serve --record-timeout 10m`；负数时长显式关闭限制 |
| 首个程序为 Shell | 拒绝执行 | 直接指定程序，或在 daemon 启用 `--record-allow-shell` |
| 工作目录 | 限制在 `<data-dir>/workspaces` 内 | 将任务放入该目录；省略 `workdir` 时为本次 Run 创建目录 |
| 子进程环境 | 只继承 `PATH`、`HOME`、`TMPDIR`、`TERM` | 需要调用方完整环境的任务使用本地采集 |

例如，为已授权的 Shell 任务设置十分钟执行上限：

```sh
agentprov --data-dir "$HOME/.agentprov" daemon serve \
  --listen 127.0.0.1:8574 --record-timeout 10m --record-allow-shell
```

超时后会终止被记录的进程组。客户端超时独立设置，SDK 的 `timeout` 应留出服务端执行所需时间。
daemon 以自身的系统权限执行授权程序；Shell 选项控制命令形式，执行隔离仍由运行环境承担。
只向可信调用方提供令牌。

## 连接 daemon

daemon 默认要求 Bearer Token。首次启动生成令牌，以 `0600` 权限保存到
`<data-dir>/auth-token`，后续启动复用。新生成的令牌会显示在启动输出中，请保护服务日志。
`--auth-token` 或 `AGENTPROV_DAEMON_TOKEN` 可覆盖文件中的令牌，覆盖值不会写回文件。

CLI 会从所选数据目录自动读取令牌：

```sh
agentprov --data-dir "$HOME/.agentprov" --daemon-url http://127.0.0.1:8574 \
  telemetry list --run RUN_ID --json
```

直接调用 HTTP 或 Python SDK 时需要传入令牌。本机 Shell 示例：

```sh
export AGENTPROV_DAEMON_TOKEN="$(cat "$HOME/.agentprov/auth-token")"
curl --fail-with-body 'http://127.0.0.1:8574/v1/telemetry/events?run=RUN_ID' \
  -H "Authorization: Bearer $AGENTPROV_DAEMON_TOKEN"
```

使用自行配置的令牌时，请传入对应值。SDK 从 `env` 参数或进程环境读取
`AGENTPROV_DAEMON_TOKEN`；直接走 HTTP 的方法需要单独配置令牌，不能只设置 `data_dir`。
完整示例见 [Python 接入指南](python-sdk.md#client-配置)。

- GET `/v1/health`、`/v1/ready`、`/v1/live` 保留匿名健康检查。
- 带请求体的写入必须使用 `Content-Type: application/json`。
- 浏览器请求须通过 Origin 检查，写入还检查 Fetch Metadata；带令牌的请求同样适用。
- `--insecure-open` 供显式选择的本地开发场景使用。正常部署保持鉴权，浏览器检查和路径限制始终生效。

生成证据清单时改用 POST：

```sh
curl --fail-with-body http://127.0.0.1:8574/v1/evidence/manifest \
  -H "Authorization: Bearer $AGENTPROV_DAEMON_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"run_id":"RUN_ID"}'
```

普通 GET 只读。旧版 `GET ...?materialize=1` 即使在开放模式下也要求鉴权。
CLI 的 `evidence manifest --run RUN_ID --materialize` 已自动使用 POST。

服务端文件摄取限制在 `<data-dir>/ingest` 或 `--ingest-allow-dir` 指定的目录。
这影响 `/v1/leases` 接收的任务 YAML 路径，以及 `/v1/telemetry/ingest-falco` 接收的文件路径。
请将文件放到服务端对应目录；指向目录外的符号链接会被拒绝。

## 导入历史证据包

导入前先校验 DSSE 签名，通过后才写入存储。请从发布者或其他可信渠道取得公钥，
并把签名声明放在证据包旁边：

```text
capture.forensics.json.gz
capture.forensics.dsse.json
publisher.pub
```

```sh
agentprov --data-dir ./replay forensics import capture.forensics.json.gz \
  --pub-key publisher.pub --json
```

成功结果包含 `attestation_verified: true` 和 `attestation_status: "verified"`。
已有签名 Demo 使用随包提供的公钥，`agentprov demo` 会自动完成校验。

确需导入可信但没有签名的历史记录时，显式选择未验证路径：

```sh
agentprov --data-dir ./replay forensics import unsigned.json \
  --allow-unverified --json
```

该路径输出警告，并将结果标为 `unverified`。同时传入两个选项时，以 `--pub-key` 为准：
公钥错误、声明缺失或证据包被修改都会失败，验签失败后不会自动转入未验证导入。

JSON 字段和导入诊断信息保持英文。`--lang zh-CN` 用于中文帮助和文本模式提示，
原始证据保留记录时的语言。

## Docker 兼容命令

Docker 模式的 `lease`、`session`、`api` 命令移除全部 Linux capability，并启用
`no-new-privileges`。在 Unix 系统上，容器默认使用启动 CLI 或 daemon 的有效 UID:GID，
让挂载的工作目录保持可写。默认非 root 账号使用 `HOME=/tmp`，依赖安装到项目目录或虚拟环境。

镜像需要指定账号时，可在任务 YAML 中设置 `user: "1000:1000"`，并确保该账号能访问工作目录。
显式指定账号会保留镜像的 HOME 环境。Rootless Docker 需要根据 UID 映射选择账号。
账号映射和 Docker 29.0–29.2 的 API 配置见[部署模式](deployment-modes.md)。
本地 `launch`、`record` 和回放不使用这套 Docker 客户端。

## 升级后如何阅读证据

- 意图覆盖按具体工具调用计算，同一 Agent 的其他调用分别判断。
- 委派详情在归属有歧义时保留候选消息；外传详情分别展示正文命中、源读取候选和执行归属。
- TLS 阅读器区分完整消息、不完整片段和历史未知状态，缺口保留在正文与解析信息中。

这些信息沿用现有 Dashboard 布局，并随选中的证据进入离线回放。
原始签名包保留当时的分析，新计算的关系带有各自的规则版本。

[发行说明草稿](releases/v0.10.1.md) · [部署模式](deployment-modes.md)
