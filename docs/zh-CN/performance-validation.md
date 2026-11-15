# 性能验收

[English](../performance-validation.md) | 简体中文

每份报告对应明确的工作负载和环境。遥测压测覆盖 JSONL 接收、队列处理、SQLite
存储和分页查询。原生 Sensor 开销、Browser/Notebook 附件成本、浏览器回放加载
分别使用各自的工作负载与报告。

## 测量遥测基线

选择空闲的测试主机，固定可执行文件，每次使用新的输出目录。
比较期间保持 CPU、内存、内核、Python 版本和后台服务一致。
脚本保留生成的输入、独立存储、服务日志和 JSON 报告。多次运行建议预留数 GiB
空间，另外为可执行文件和构建缓存保留余量。

```sh
BASELINE=/absolute/path/to/baseline-agentprov
MEASUREMENTS=$(mktemp -d)
for trial in 1 2 3; do
  python3 scripts/accept_telemetry_100k_pressure.py run \
    --agentprov "$BASELINE" --events 100000 \
    --output "$MEASUREMENTS/baseline-$trial"
done
```

服务沿用默认的 Bearer 鉴权和文件导入目录限制。脚本在本机读取新生成的私有令牌，
仅发送回环请求，报告中不包含令牌。此摄入配置显式关闭策略评估、后台采样、
证据处理和 GC，也不启动原生内核 Sensor。输入保持原有合成 Falco 用例：
一个队列文件，包含 10 万条进程身份不同的事件。

报告包含：

- 输入、脚本和可执行文件的 SHA-256，以及版本、环境和实际参数。
- 已处理与失败数量、每页最多 5 条的查询结果，以及生产者健康状态。
- 队列处理耗时和吞吐量；摄入期间最多 10 组查询，完成后 30 组查询。
  两个阶段分别保存延迟样本和 p50、p95、p99、最大值。30 个样本下的 p99 就是
  样本最大值，尾部延迟估计还需要更大的样本集。
- 轮询得到的服务 CPU 和 RSS 峰值。Linux 每 100 毫秒读取进程的用户态、内核态
  CPU 时间增量；macOS 按相同间隔读取 `ps` 的生命周期平均值。报告标注统计方法，
  只在同环境内比较。
- 排队、处理完成、服务停止三个时点的逻辑文件字节数。
  存储统计包含 SQLite、WAL 和保留的队列文件，排除生成的原始输入。
  文件清单解释各项体积；文件系统实际占用块数和压缩 Bundle 体积另行测量。

HTTP 请求失败时，本次验收失败。没有样本的延迟保留未知；失败运行的报告和日志
继续保留。可选参数 `--source-commit FULL_SHA` 还会核对可执行文件的版本输出
是否包含指定源码提交。

## 冻结预算，再测候选版本

在运行候选版本**之前**冻结预算：

```sh
python3 scripts/accept_telemetry_100k_pressure.py freeze \
  --baseline "$MEASUREMENTS/baseline-1/report.json" \
  --baseline "$MEASUREMENTS/baseline-2/report.json" \
  --baseline "$MEASUREMENTS/baseline-3/report.json" \
  --allowed-regression 0.25 --budget "$MEASUREMENTS/budget.json"

python3 scripts/accept_telemetry_100k_pressure.py run \
  --agentprov /absolute/path/to/candidate-agentprov --events 100000 \
  --budget "$MEASUREMENTS/budget.json" --output "$MEASUREMENTS/candidate"
```

预算取至少三次独立、成功运行的中位数。示例允许处理耗时、RSS 峰值、停止后的
存储体积和摄入后查询 p95 增加 25%。两项查询上限另加固定的 1 毫秒计时余量，
用于容纳亚毫秒级抖动；这两种余量都会写入预算。比较时必须使用同一环境、
工作负载和测量脚本。任何指标超限，脚本都会以非零状态退出，并列出实际值和上限。
保留失败结果，先调查原因，再决定是否调整工作负载或预算。
这份预算用于指定环境的回归验收。

## 原有 Shell 入口

`scripts/accept_telemetry_100k_pressure.sh` 转发到同一份 Python 实现。
原有 `AGENTPROV_ACCEPT_100K_` 前缀下的 `EVENTS`、`LISTEN`、`REPORT`、`DATA_DIR`
和 `BIN` 配置仍可用。`DATA_DIR` 现在是保留的输出目录，内部使用 `store/`；
已有路径会被拒绝。指定的 `BIN` 必须是已有可执行文件，脚本不会重建或删除它。
未指定时，脚本在自己的输出目录中构建。已有报告和预算也不会被覆盖。
详细报告的格式版本更新为 `v2`。

本地存储、生成的鉴权令牌和原始日志保留在公开提交之外。
对外只发布经过检查的测量结果及其环境、源码摘要。
