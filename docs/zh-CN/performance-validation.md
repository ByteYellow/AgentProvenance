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

### 重启后相差一页内存时

同一套虚拟机配置重启后，Linux 报告的 `MemTotal` 可能相差 4 KiB。保留严格比较
失败的结果及两次环境记录，先核对虚拟机的 CPU、内存分配和其余身份字段。
随后在新目录中不带 `--budget` 完成测量，再显式执行下面的比较。
这个入口只接受最多 4,096 字节的系统内存统计差异，性能上限、工作负载和测量
脚本的检查继续沿用冻结预算。结果会列出具体差异和原始文件摘要，输入文件保持原样。

```sh
python3 scripts/compare_acceptance_budget.py sensor \
  --report "$MEASUREMENTS/candidate-measured/report.json" \
  --budget "$MEASUREMENTS/budget.json" \
  --allow-memory-page-variation --output "$MEASUREMENTS/comparison.json"
```

同一入口也支持 `telemetry` 和 `context`。更大的内存差异，以及 CPU 数量、内核、
Python 等其他身份字段变化，仍会使比较失败。

## 原有 Shell 入口

`scripts/accept_telemetry_100k_pressure.sh` 转发到同一份 Python 实现。
原有 `AGENTPROV_ACCEPT_100K_` 前缀下的 `EVENTS`、`LISTEN`、`REPORT`、`DATA_DIR`
和 `BIN` 配置仍可用。`DATA_DIR` 现在是保留的输出目录，内部使用 `store/`；
已有路径会被拒绝。指定的 `BIN` 必须是已有可执行文件，脚本不会重建或删除它。
未指定时，脚本在自己的输出目录中构建。已有报告和预算也不会被覆盖。
详细报告的格式版本更新为 `v2`。

本地存储、生成的鉴权令牌和原始日志保留在公开提交之外。
对外只发布经过检查的测量结果及其环境、源码摘要。

## 测量原生 Sensor 开销

使用有 root 和 BPF 权限的独立 Linux 测试主机。沿用四进程工作负载：
突发执行 4 万次文件打开，限速执行 16 万次。
`accept_sensor_overhead.py` 在每种配置下分别运行三次：

| 配置 | Sensor 行为 |
| --- | --- |
| `off` | 不启动 Sensor，只测工作负载耗时和 CPU |
| `minimal` | 启用基础探针，关闭自动 TLS 发现及 AppArmor、seccomp 状态采样 |
| `default` | 启用基础探针、自动 TLS 发现和两种状态采样 |

这些是测量用的探针组合，与应用上下文的 basic、detailed 留存档位分开。
脚本清除指定库路径和自动 TLS 开关的环境变量覆盖，每轮轮换执行顺序，
分别保留就绪期间和停机后的探针及 TLS 发现能力报告。
文件工作负载测量这组配置的运行成本；TLS 流量和附件存储使用各自的工作负载。

基线和候选 Sensor 使用相同的 Go 工具链、目标架构、CGO 设置及优化参数。
分别保存 `go version -m /absolute/path/to/agentprov-sensor` 的结果和构建命令。
脚本中的 `compiler` 校验的是测试负载使用的 C 编译器，尚未自动校验 Sensor 的 Go 构建设置。
发行验收沿用发行流水线的 Go 版本和构建参数。候选构建配置与基线不一致时，
先按基线配置重建，再使用已冻结的预算比较；之前的测量结果及实际构建配置一并保留。

```sh
MEASUREMENTS=$(mktemp -d)
sudo python3 scripts/accept_sensor_overhead.py run \
  --sensor /absolute/path/to/baseline-agentprov-sensor \
  --output "$MEASUREMENTS/baseline"
sudo python3 scripts/accept_sensor_overhead.py freeze \
  --baseline "$MEASUREMENTS/baseline/report.json" \
  --allowed-regression 0.25 --budget "$MEASUREMENTS/budget.json"
sudo python3 scripts/accept_sensor_overhead.py run \
  --sensor /absolute/path/to/candidate-agentprov-sensor \
  --budget "$MEASUREMENTS/budget.json" --output "$MEASUREMENTS/candidate"
```

所有开启采集的运行都必须保留准确的打开、返回数量及 5 条进程退出记录，
包括工作负载结束后立即停止 Sensor 的收尾数据。
内核、状态队列和 TLS 发现队列的丢失数必须为零。
节点级 procfs 状态可用性与工作负载事件计数分别展示。
`off` 的采集指标保持未知。原有 `accept_sensor_pressure.py` 继续执行
1 MiB 缓冲过载测试，要求实际报告丢失。

报告保留每次结果、中位数和相对 `off` 的耗时。
CPU 使用已回收子进程的用户态与内核态时间：工作负载记录分摊给自身进程的开销，
Sensor 记录启动、发现和收尾开销。每 20 毫秒采样一次 RSS。
工作负载用阻塞的 `wait4` 测量结束时刻，避免限时等待轮询抬高短任务的耗时；
启动与收尾分别计时。测量期间不启动策略引擎或数据库。

原始 JSONL 体积和摘要覆盖整个节点，另行统计工作负载进程名对应的记录字节数。
计时结束后，用 gzip 的压缩等级 1 保存原始记录，并保留标准错误日志和能力报告。
这些指标反映采集文件成本；Bundle 和 SQLite 分别测量。
输出目录为私有目录，root 所有的记录可能包含后台进程元数据，应留在本地。
重复运行前预留数 GiB 磁盘空间。

预算根据每个配置和工作负载的三次中位数冻结，默认允许耗时、Sensor CPU、RSS
和工作负载 JSONL 字节数增加 25%。耗时和 CPU 额外允许 20 毫秒计时波动；
该数值在测量前固定于脚本，并写入预算。`off` 的耗时也参与检查，以识别主机基线变化。
节点总输出和压缩体积只报告，不作为固定工作负载的数量上限。
候选版本必须使用相同的环境、负载编译器、工作负载及测量脚本；超限时非零退出，
成功和失败记录均保留。更换环境或测量方法时，明确建立新基线。

可选的 `--source-commit FULL_SHA` 记录操作者提供的构建提交。
Sensor 没有版本查询入口；记录源码来源时，将构建命令和源码归档摘要与二进制哈希一并保留。

## 测量上下文存储与导出成本

固定一组 Browser 和 Notebook 原始记录，包含截图、HAR 和图表输出。
可用 `scripts/accept_browser.py` 与 `scripts/accept_notebook.py --attachments`
生成这些输入。分享前检查内容，尤其是截图中的可见信息。
成本脚本重新导入已保存的记录，测量期间不启动 Agent、浏览器、kernel 或 Sensor。

```sh
MEASUREMENTS=$(mktemp -d)
python3 scripts/accept_context_cost.py run \
  --agentprov /absolute/path/to/baseline-agentprov \
  --browser-input /absolute/path/to/browser/first.jsonl \
  --browser-input /absolute/path/to/browser/second.jsonl \
  --notebook-input /absolute/path/to/notebook/first.jsonl \
  --notebook-input /absolute/path/to/notebook/restarted.jsonl \
  --output "$MEASUREMENTS/baseline"
python3 scripts/accept_context_cost.py freeze \
  --baseline "$MEASUREMENTS/baseline/report.json" \
  --budget "$MEASUREMENTS/budget.json"
```

候选版本使用相同输入和环境，指定新的 `--output`，并增加
`--budget "$MEASUREMENTS/budget.json"`。可选的 `--source-commit FULL_SHA`
会核对 CLI 版本中的源码提交。每次测量均对 basic、detailed 和
`--capture-attachments=false` 下的 detailed 各运行三轮，并轮换顺序。
详细档必须实际保存附件；主动省略等场景由对应功能测试覆盖。
三个档位下的原生操作、请求关联必须一致。

报告分别统计生成 Bundle 前的存储文件逻辑体积、保留附件的字节数、签名 Bundle
体积和只读回放 ZIP 体积。CLI 导入、投影、分页查询、签名导出、完整回放导出和
排除附件后的导出分别计时。CPU 包含校验命令；RSS 取 `wait4` 返回的单个子进程峰值
中的最大值。每条命令保留参数、标准输出、标准错误、耗时和退出码。

脚本检查重复导入、独立存储中的签名验证、移走来源存储后的记录一致性、图谱验证、
附件分页摘要及导出选择数量。完整阅读体验另用浏览器验收；服务停止后执行：

```sh
node scripts/accept_offline_replay.cjs \
  "$MEASUREMENTS/candidate/1-browser-detailed/whole.zip" \
  "$MEASUREMENTS/candidate/1-browser-detailed/excluded.zip" \
  "$MEASUREMENTS/candidate/1-jupyter-detailed/whole.zip" \
  "$MEASUREMENTS/candidate/1-jupyter-detailed/excluded.zip"
```

预算取各 harness、档位三次结果的中位数，允许增加 25%；CLI 耗时及 CPU 另加预先
声明的 50 毫秒余量。输入哈希、环境和测量脚本必须一致。缺少指标、原生关联变化
或任一指标超限时，验收失败。调查时保留原失败报告与预算。
这组小规模固定输入测量对应体量的留存、导出成本；容量测试另设明确的工作负载。
为来源存储、恢复存储和所有 ZIP 预留磁盘空间。生成的签名密钥、记录和命令日志留在本地。
