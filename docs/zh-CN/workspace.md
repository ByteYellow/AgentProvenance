# 受控远端工作区

整个 Harness 在权威工作区所在机器运行。Read、Edit、Write、Bash
通过 stdio MCP 调用 `agentprov workspace` JSON CLI。每个工具单独进入受控边界，
Harness 主循环不持有工作区锁。当前执行平台为 Linux/macOS；其他平台的 CLI
保留明确的 unsupported 入口，避免导入 Unix core。

## 操作员配置

准备绝对、规范化的 workspace root，以及位于工作区之外的受保护操作员目录。
配置、当前 Target、journal 和现有 evidence store 均放在操作员目录。
`state_dir`、`data_dir` 的父目录需要预先存在；同一 binding 的所有进程共享
同一个 state 目录和数据库。

`/operator/workspace.json` 示例：

```json
{
  "schema": "agentprovenance.workspace_cli/v1",
  "workspace_id": "task-workspace",
  "run_id": "run-workspace-demo",
  "root": "/work/task",
  "state_dir": "/operator/workspace-state",
  "data_dir": "/operator/evidence",
  "target": {
    "producer_id": "lab",
    "instance_id": "agentprov-lab",
    "generation": "g1"
  },
  "target_file": "/operator/current-target.json",
  "allowed_operations": ["read", "write", "edit", "execute"],
  "bash_timeout_seconds": 60
}
```

`/operator/current-target.json` 只保存当前 Target：

```json
{"producer_id":"lab","instance_id":"agentprov-lab","generation":"g1"}
```

这两个文件要求：普通文件、单一硬链接、最多 64 KiB、属于调用操作员或 root，
group/other 无写权限。推荐 `0600`，父目录设为私有目录；拒绝符号链接配置路径。
每次 core 身份校验都会重新打开 `target_file`，包括 Bash 开始前和结束后。
可信生命周期控制面通过原子替换更新此文件。环境重建/restore 使用新 generation，
并建立新的 binding/state 目录；已有 journal 的身份保持固定。

证据目录只使用操作员配置中的 `data_dir`，全局 `--data-dir` 和模型参数不参与选择。
可选 `limits` 字段为 `file_bytes`、`total_bytes`、`entries`、`output_bytes`。
默认单文件 2 MiB、单次扫描 16 MiB、1024 个目录项、stdout/stderr 合计 2 MiB。
Bash 默认超时 60 秒，配置范围为 1–300 秒。

使用选定 runtime 的隔离和权限保护操作员文件。Bash 在该 runtime 中执行任意命令；
workspace 的路径检查约束受控文件工具。Sensor 采集另行配置。

## JSON CLI

命令为 `inspect`、`read`、`write`、`edit`、`bash`，全部要求
`--config /absolute/operator.json --json`，从 stdin 接收一个 JSON 对象。
未知字段直接拒绝。stdout 始终为一个 JSON 响应；操作失败同时返回非零退出码。
子命令 stdout/stderr 单独捕获，不混入 JSON 协议。

每个请求必须包含 `workspace_id` 和完整的预期 `target`。先查询：

```sh
printf '%s\n' '{"workspace_id":"task-workspace","target":{"producer_id":"lab","instance_id":"agentprov-lab","generation":"g1"}}' |
  agentprov workspace inspect --config /operator/workspace.json --json
```

在这个基础请求上加入对应字段：

| 命令 | 字段 |
| --- | --- |
| `inspect` | 可选 `expected_revision`；返回 binding 和观察到的文件清单。 |
| `read` | `path`；可选 `expected_revision`、`expected_digest`。 |
| `write` | `path`、`content`，以及至少一个 CAS 前置条件；支持空文件。 |
| `edit` | `path`、`old_text`、`new_text`、正整数 `count`，以及至少一个 CAS 条件；匹配数必须恰好等于 `count`。 |
| `bash` | `command`、必填 `expected_revision`；在绑定 root 中运行 `/bin/bash --noprofile --norc -c`。 |

CAS 字段是 `expected_revision` 和 `expected_digest`。digest 使用 Read 返回的
小写源内容 SHA-256；特殊值 `absent` 表示只允许创建。两个条件同时提供时同时检查。
编辑必须携带形成这次编辑依据的旧 revision/digest；冲突后重新读取并重新决策。

响应 schema 为 `agentprovenance.workspace_tool_result/v1`：

- `ok`；失败时提供 `error.{code,message,next_action}`。
- `run_id` 和可信 CLI 入口生成的 `tool_call_id`，模型无法提交这两个字段。
- `view.binding`：workspace、Target、root、权限、revision、manifest digest/ref、证据 head。
- `view.last_receipt`：输入/输出观察版本、manifest、变更、结果，以及独立采集的 record 引用。
- `operation_ref`：仅在 receipt 属于本次调用时返回；Inspect/冲突返回的旧 receipt 不会冒充本次操作。
- Read 返回 `content`、`sha256`、`content_evidence`，区分源摘要与存储/脱敏后摘要。
- Bash 返回脱敏的 `stdout`/`stderr`、`output_truncated`、真实的 `record_tool_call_id`。
  命令退出码位于 `view.last_receipt.exit_code`；`ok` 表达工具及证据操作的完成状态。
- `context_status` 表达可信工具观察是否已写入现有 context store。

本期 CLI 文件正文限 UTF-8 文本。core manifest 继续记录二进制文件摘要和明确的正文省略状态。
大量命令输出通过有界缓冲消费，超限时明确标注 omitted/truncated，同时保留文件观察与 record 引用。

## stdio MCP 与整个 Harness 远端运行

复用现有 Browser/Notebook MCP Python 环境中的 `mcp.server.mcpserver.MCPServer`，
已使用 MCP 2.0.0/2.3.0 验证。包内没有网络监听器、模型客户端、新 SDK 或自制 Harness。

```json
{
  "mcpServers": {
    "agentprov_workspace": {
      "command": "/operator/mcp-venv/bin/python",
      "args": ["-m", "agentprov.workspace_mcp", "--agentprov", "/opt/agentprov", "--config", "/operator/workspace.json"],
      "env": {"PYTHONPATH": "/opt/AgentProvenance/python"}
    }
  }
}
```

在工作区所在机器启动 Claude，并仅开放受控工具：

```sh
claude --setting-sources user --strict-mcp-config --mcp-config /operator/mcp.json \
  --tools '' \
  --allowedTools mcp__agentprov_workspace__workspace_inspect,mcp__agentprov_workspace__workspace_read,mcp__agentprov_workspace__workspace_edit,mcp__agentprov_workspace__workspace_write,mcp__agentprov_workspace__workspace_bash
```

MCP server key 使用 `agentprov_workspace`；`workspace` 是 Claude 保留名，会被拒绝加载。
只部署 Python 模块时，需同时部署 `python/agentprov` 和 `python/agentprov_eval`。

Bridge 从启动配置固定 workspace/Target。模型工具参数只有路径、正文、命令及 CAS 值，
没有 Target、run、工具身份、record IDs 或证据引用。每次工具调用只执行一次 JSON CLI。
Provider 凭据不转交给该 CLI 或 Bash 子进程；Claude 继续使用操作员已有 provider 配置，
不要把 API key 写入 MCP/config 文件。

只有单次 Bash 进入 `ObserveExecution`，调用现有 `record.Service.RunContext`，
保留真实基线快照、attempt 和工具调用 ID。命令使用有界前台执行；后台任务生命周期由现有执行层管理，
不纳入本期 workspace 工具契约。

workspace CLI 收到 SIGINT/SIGTERM 时，通过 record 现有停止路径取消执行，
并尝试保存最终观察。响应丢失时使用 Inspect 核对结果，不自动重放命令。

## 冲突与恢复

| 错误码 | 下一步 |
| --- | --- |
| `conflict` | `reread`：重新读取内容，再决定新的编辑；bridge 不自动重试变更。 |
| `stale_target` | `operator_rebind`：控制面为当前身份建立新 binding。 |
| `recovery_required` / `outcome_unknown` | `inspect`：查询持久状态，结合已有 record attempt 核对结果，再决定是否发起新执行。 |
| `unsafe_path`、`invalid_request`、`forbidden` | 修正请求或操作员策略。 |
| `limit_exceeded` | 查询观察结果和显式的工作区/输出预算。 |

重复 Inspect 和 bridge 重启都不会执行 Bash。受管理操作在同一个进程安全锁中完成
CAS、文件应用、证据和 revision 发布。外部修改单独记录为 observation。
输入/输出 manifest 表达文件系统观察边界；record 快照和 kernel/sensor 保持独立证据等级。

CLI 通过现有 context store 写入 `workspace-cli` 工具调用/结果，引用当前 run 下验证过的
CAS manifest/receipt。该身份是可信工具入口，不冒充原生 Claude tool-call ID；Claude
原始流日志可独立保留。用户提交的证据引用被拒绝，关联对象在加入结果/context 前检查所属 run。

## 可复现验收与 x86 交接

在选定执行机器的仓库根目录运行：

```sh
go build -o /operator/agentprov ./cmd/agentprov
PYTHONPATH=python /operator/mcp-venv/bin/python scripts/accept_workspace.py \
  --agentprov /operator/agentprov --output /operator/w01-contract-new
```

脚本建立实际 stdio MCP 会话，验证 Read → Edit → Write → Bash、record 基线字节、
产物正文、当前 run 证据引用、context 持久化、CAS 冲突、并发调用、重启查询不重放、
路径/链接拒绝和模拟 generation 失效。结束时会故意将测试 Target 的 generation 改为失效值。
每次运行使用全新的输出目录。

真实 whole-Harness 演示使用已有 Claude 或其 wrapper：

```sh
PYTHONPATH=python /operator/mcp-venv/bin/python scripts/accept_workspace.py \
  --agentprov /operator/agentprov --output /operator/w01-harness-new \
  --claude /operator/bin/claude
```

这个显式选项使用独立 workspace/run，将工具限制为受控 MCP，校验最终产物及恰好一次真实
Bash attempt，并保留私有 Claude 日志。验收先检查真实 `system/init` 中的 server/tool 库存，
再检查原生 `tool_use` 和实际产物。Provider success 消息或正文 XML 不计作工具调用。
失败报告包含 `failure_phase` 以及 `mcp_not_connected`、`missing_controlled_tools`、
`no_tool_calls`、`missing_artifact` 等明确分类。
请求最多 12 个 turns、0.50 美元预算及 300 秒总时长。
脚本直接使用既有 provider 环境，不读取或打印凭据。

相同脚本可用于 ARM Linux 和 x86-64 Linux，无需 Sensor 或 sudo。
`report.json` 明确区分实际 Harness 执行与 `harness.status=not_requested`，记录架构、
MCP 版本、二进制 SHA-256、run IDs 和验证结果。验收目录保持私有，原始日志不进入公开提交。

本地回归命令：

```sh
go test -race -count=1 ./internal/cli ./internal/workspace
go test ./...
PYTHONPATH=python python3 -m unittest discover -s python/tests -p 'test_workspace_mcp.py' -v
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o /operator/agentprov-amd64 ./cmd/agentprov
```
