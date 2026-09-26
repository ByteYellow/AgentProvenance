# Falco 兼容接收器

[English](../falco-receiver.md) · 简体中文

**状态：保留兼容，不作为主推采集方式。** 主要的内核证据来源是 AgentProvenance 原生 eBPF 传感器 `agentprov sensor stream`，支持 Linux amd64 和 arm64。

已有 Falco 的环境可以将其过滤后的运行时事件汇入同一套证据图、关联、策略和风险流程。无法加载自有 eBPF 的托管环境，也可接收环境中已有的 Falco 输出；接收器本身不会绕过平台权限限制。

建立绑定并导入样例：

```sh
./agentprov telemetry bind --run run-falco-demo --substrate-scope substrate-falco-demo \
  --execution-scope exec-falco-demo --tool-call tool-falco-demo \
  --process process-falco-demo --container-id container-falco-demo --pid 4242 \
  --started-at 2026-01-01T00:00:00Z

./agentprov telemetry ingest-falco \
  --file examples/telemetry/falco-risk-events.jsonl --json

./agentprov telemetry list --run run-falco-demo
./agentprov telemetry list --run run-falco-demo --limit 100 --json
./agentprov telemetry list --run run-falco-demo --limit 100 --cursor <next_cursor> --json
./agentprov timeline --run run-falco-demo
./agentprov security risks --run run-falco-demo --json
./agentprov security responses --run run-falco-demo --json
```

实时接收时，可以直接通过管道传入 Falco JSON 输出：

```sh
sudo falco -o json_output=true -o json_include_output_property=true | \
  ./agentprov telemetry ingest-falco --file -
```

接收器将 Falco 的进程、文件和网络记录转换为标准化事件。默认策略评估会把云元数据地址访问、私有网段连接、敏感路径访问等事件转成 `RiskSignal`、`ResponseAction`、策略图边和时间线证据。

`graph explain --risk <policy_decision_id> --json` 可以追溯风险对应的运行时事件，并查看记录的响应动作。Falco 负责采集，AgentProvenance 负责关联、因果与溯源分析，以及风险和审计引用。

主要的快速验收入口：

```sh
./scripts/demo_telemetry_jsonl.sh
```

脚本先建立工具调用作用域，再导入不带 `tool_call_id` 的 Falco、Tetragon、LoongCollector 格式事件，进行标准化存储、应用上下文关联和图解释。

Falco 兼容队列与原生事件流的持久化流程不同。重启恢复保证请分别查阅对应实现，不能将[原生采集队列](native-capture-spool.md)的保证套用到旧版 Falco 工作进程。
