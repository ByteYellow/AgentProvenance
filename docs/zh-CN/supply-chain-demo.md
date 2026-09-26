# 供应链示例：调查 Agent 执行中的敏感读取与外发

[English](../supply-chain-demo.md) · 简体中文

本指南介绍仓库随附的签名供应链采集记录：将 Agent 上下文、系统操作和证据图关联，用于安全调查、回放与审计。演示从已提交的签名包离线运行，查看时无需 Linux eBPF 虚拟机。

## 一条命令回放

解压[发行包](../releases/v0.8.2-rc.2.md)后运行 `./agentprov demo snake-supply-chain`。命令自动校验签名、导入数据、选择执行记录与图视图，并管理临时存储。`./agentprov demo` 打开全部示例及格式化指南。

下文保留手动导入方式，供需要持久保存调查数据时使用。

## 1. 演示内容

AgentProvenance 将应用侧的执行、工具调用、进程上下文与系统侧的执行、文件和网络事件关联，保存内容寻址对象并导出签名包。使用者可以追踪一次操作的来源、依据和后续记录。

签名证明证据包与签名时一致，不证明采集没有遗漏，也不自动证明图中的每个推断正确。

## 2. 场景

一个真实 Coding Agent 在沙箱中无界面运行，任务是编写贪吃蛇游戏。安装说明 `SETUP.md` 中包含提示注入，要求先执行 `python3 ../pysnake-helper/setup.py install`，安装一个本地“网格辅助包”。该模拟恶意包的安装钩子会：

1. 读取预先放置的假凭据，例如 `~/.aws/credentials` 和 API token。
2. 尝试连接云元数据地址 `169.254.169.254`。

这是使用假凭据复现 ctx、torchtriton 一类供应链攻击行为的实验，不使用真实恶意软件或真实密钥。记录来自 Linux eBPF 实验虚拟机，导出时签名，并作为可移植包提交。

| 查看方式 | 入口 | 用途 |
|---|---|---|
| 原始遥测 | 事件和时间线 | 检查采集事实 |
| 因果与溯源关系 | 证据图视图 | 串联上下文、进程、文件、网络、风险和响应 |
| 审计证据 | 签名包和合规映射 | 校验记录内容，查看策略触发依据 |

## 3. 手动导入并打开

以下源码方式先构建 CLI，再将签名包导入新的本地存储：

```bash
go build -o /tmp/agentprov ./cmd/agentprov

/tmp/agentprov forensics import demo/snake-supply-chain/run-snake-supervised.forensics.json.gz \
  --pub-key demo/snake-supply-chain/attestation.pub \
  --data-dir /tmp/snake-demo
# --pub-key 在加载前校验 in-toto/DSSE 签名；签名不匹配时拒绝导入。

/tmp/agentprov --data-dir /tmp/snake-demo dashboard serve
# 打开输出的网址，会自动加载 run-snake-supervised。
```

之后使用相同的 `--data-dir /tmp/snake-demo` 启动界面即可，无需重复导入。

## 4. 界面调查顺序

1. **Agent 意图视图**：从工具调用或进程开始。这次执行由记录器放入真实 cgroup，节点级 `sensor stream` 采集内核事件，通过 cgroup 和时间关联。原始内核事件不含 `tool_call_id`。
2. **安全视图**：查看安装钩子的 `secret_path` 读取和 `metadata_ip` 外发尝试，沿 `runtime_event → policy_decision → risk_signal → response_action` 追踪记录。
3. **信号与风险面板**：本次触发 `secret_path_access` 和 `metadata_ip_dst`，分别记录 `kill` 和 `quarantine` 决策。点击条目定位图节点。未触发的已有规则显示 `not_triggered`，不表示通过了安全检查。
4. **数据流与污点视图**：查看 `possible_sensitive_data_flow` 虚线及置信值。它依据同一进程先读取敏感路径、后尝试外发的顺序推断可能的数据流，不证明具体内容已传出。
5. **时间控制条**：按事件时间回看，核对敏感读取与外发尝试的先后顺序。
6. **节点详情**：查看证据字段和有限长度、经过敏感内容处理的对象预览，并核对对象哈希。原始证据仍需按其访问权限管理。
7. **时间线与进程树**：查看操作顺序和进程名称。界面优先显示 argv 或命令，再回退到内核 `comm`；只有缺少命令证据时才只显示 PID。

## 5. 合规映射

```bash
agentprov --data-dir /tmp/snake-demo compliance map \
  --framework owasp-asi --run run-snake-supervised
```

也可打开 Dashboard 的合规卡片。CLI 与界面共用 `compliance.MapRunRules`，按控制项映射到的规则和本次触发记录给出四种状态：

| 状态 | 在当前实现中的含义 |
|---|---|
| `enforced` | 映射规则触发，并记录 `deny`、`quarantine` 或 `kill` 类决策 |
| `detected` | 映射规则触发，但未记录上述阻止类决策 |
| `not_triggered` | 存在映射规则，本次未触发 |
| `no_rule` | 没有检测规则映射到该控制项 |

`enforced` 根据保存的决策分类，不能单独证明操作系统实际阻止了行为；要结合执行路径和响应证据判断。`no_rule` 和 `not_triggered` 都不是合规通过。

该示例中，目标劫持 ASI01、记忆污染 ASI06、Agent 间交互 ASI07 等控制项可显示 `no_rule`，因为没有映射相应检测器。展开控制项可查看每次规则命中的时间、决策、原因和图引用，例如多次触发的 `secret_path_access`。

## 6. 校验证据

```bash
agentprov forensics verify-attestation \
  demo/snake-supply-chain/run-snake-supervised.forensics.json.gz \
  --pub-key demo/snake-supply-chain/attestation.pub
```

证据按 SHA-256 内容寻址，导入时校验哈希。包使用 in-toto Statement、DSSE 和 ed25519 签名；启用公钥验证时，在提交数据行前检查签名，篡改导致校验失败会拒绝导入。

## 7. 能力边界

- 当前强调完整性校验。拥有宿主 root 权限的攻击者可以改写本地 SQLite 并重建哈希链；主机外采集时锚定，例如 KMS、TPM 或透明日志，属于后续方向。
- 这份历史记录来自 ARM64 实验机，不验证生产 x86 或 HTTP/2 流量。后续 amd64 能力应查阅独立的[实测报告](../benchmarks/amd64-kvm-k3s/README.md)。
- 此记录不能证明所有模型框架的 TLS 明文采集都完整。当前 TLS 范围和缺口见[传感器说明](ebpf-sensor-plan.md)。
- 凭据为预先放置的假数据，回放不会再次执行读取或网络连接。
- `self_launched` 表示作用域由 AgentProvenance 直接启动；`kernel_correlated` 表示系统事件通过 cgroup、容器、PID、时间等身份关联到作用域。这是两个独立事实，内核关联不要求由记录器启动。

## 8. 实现说明

`internal/correlation` 按进程、cgroup、容器和 PID 等层次关联时间窗口内的事件，并记录匹配置信值和来源。监督采集由 `record` 创建真实 cgroup，`sensor stream` 观测系统调用，关联器将事件归入执行记录。整个流程无需让原始内核载荷携带 Agent 标识。
