# 合规证据映射

[English](../compliance.md) | 中文

AgentProvenance 将检测规则及其在一次执行中的结果映射到安全框架配置，包括 OWASP Agentic Security 和 NIST AI Agent 安全评估问题。帮助查看检测与阻断情况，整理自评和审计材料。

```sh
./agentprov compliance frameworks
./agentprov compliance frameworks --ruleset examples/compliance/custom-ruleset.yaml
./agentprov compliance validate --ruleset examples/compliance/custom-ruleset.yaml
./agentprov compliance map --framework owasp-asi --run <run_id>
./agentprov compliance map --framework owasp-asi --run <run_id> --only ASI05,ASI10,TRACE
./agentprov compliance explain --framework owasp-asi --run <run_id> --item ASI05
./agentprov compliance gaps --framework owasp-asi --run <run_id>
./agentprov compliance gaps --framework owasp-asi --run <run_id> --no-rule-only --json
./agentprov compliance map --framework enterprise-agent-review --ruleset examples/compliance/custom-ruleset.yaml --run <run_id>
./agentprov compliance report --framework nist-rfi-2026-00206 --run <run_id> --json
```

## 如何理解结果

每个控制项根据映射到它的检测规则报告状态：

| 状态 | 含义 |
|---|---|
| `enforced` | 阻断：规则触发了拒绝、隔离或终止决策。 |
| `detected` | 仅检测：规则已命中，没有阻断决策。 |
| `not_triggered` | 存在映射规则，但本次执行没有触发它们。 |
| `no_rule` | 尚无检测规则映射到此控制项，存在覆盖缺口。 |

阻断按策略决策统计，具体执行结果见响应记录。未触发表示这次运行没有命中规则。报告用于自评，不提供合规认证。

`agentprovenance.compliance_rule_mapping/v1` 报告按控制项列出 `rules`、各规则的 `hits`、具体 `evidence_refs`、缺口 `gap`、建议 `recommended_next_step` 和原因 `reason`。命中记录包含决策、时间、来源事件及本次命中是否记录了阻止类决策。JSON 使用 `control_id` 标识控制项，当前报告不附带 `item_id` 别名。

`compliance gaps` 列出需要处理的 `detected` 和 `no_rule` 项。添加 `--no-rule-only` 可只查看尚未映射检测器的控制项。旧版 `--missing-only` 参数及 `covered/partial/missing/not_applicable` 状态不适用于当前的规则映射命令。

## 自定义框架与检测规则

`--ruleset` 加载包含 `rules`、`frameworks` 和 `mappings` 的 YAML 目录配置，在内置目录上扩展。映射可以在本地评审配置中复用 `ASI05`、`ASI10`、`TRACE` 等内置控制项。

框架目录与实际执行的检测规则用途不同。如果部署使用自定义检测器，映射时还应通过 `--rules` 指定对应的检测规则 YAML。仅增加框架条目，不会让传感器自动产生检测该威胁所需的事件。可参考[规则集示例](../../examples/compliance/custom-ruleset.yaml)。
