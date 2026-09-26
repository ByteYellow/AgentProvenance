# Python 接入指南

[English](../python-sdk.md) | 中文

Python 辅助库负责调用 `agentprov`、读取执行证据和提交评估信号。普通 Python 函数就能定义评估规则，适合接入测试、基准评估或 RL 流水线。

## 安装

需要 Python 3.9+ 和可运行的 `agentprov`。在仓库根目录安装辅助库：

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
export AGENTPROV_BIN=/absolute/path/to/agentprov
```

将 `AGENTPROV_BIN` 改为 CLI 的实际路径。预编译 CLI 的安装方法见[快速开始](../../README.zh-CN.md#快速开始)。

`agentprov` 和 `agentprov_eval` 导出同一组 Python 接口；下文使用 `from agentprov import ...`。命令输出和 JSON 字段保持英文。

## 记录、评估并导入结果

下面的脚本记录一次文件写入，用自定义规则统计文件变化，再将结果导入同一次执行。示例使用临时目录，退出后自动清理。

```python
import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from agentprov import Client, Registry, Signal, evaluate_context

registry = Registry(name="example-quality")

@registry.rule("changed_files")
def changed_files(ctx):
    return Signal.quality_signal(
        "changed_files", float(len(ctx.file_changes())), "File changes observed"
    )

with TemporaryDirectory(prefix="agentprov-python-") as directory:
    root = Path(directory)
    work = root / "work"
    work.mkdir()
    client = Client(binary=os.environ["AGENTPROV_BIN"], data_dir=root / "data")
    manifest = client.record(
        [sys.executable, "-c", "from pathlib import Path; Path('result.txt').write_text('ok')"],
        run_id="run-python-example", workdir=work,
    )
    context = client.eval_context(manifest["run_id"])
    report = evaluate_context(context, registry=registry, engine=registry.name)
    imported = client.import_signal_reports([report], engine=registry.name)
    print(manifest["run_id"], report["signal_count"], imported["signal_count"])
    print(client.signals(manifest["run_id"])["schema_version"])
```

`Client.record` 会实际执行传入的命令。`evaluate_context` 在当前 Python 进程中运行规则；调用 `import_signal_reports` 后，结果才写入存储。

## 批量处理

`run_batch_pipeline` 完成批量记录、读取上下文、评估、导入信号和导出取证包。每个并发任务使用独立工作目录：

```python
import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from agentprov import Client, Registry, Signal

registry = Registry(name="batch-quality")

@registry.rule("changed_files")
def changed_files(ctx):
    return Signal.quality_signal(
        "changed_files", float(len(ctx.file_changes())), "File changes observed"
    )

with TemporaryDirectory(prefix="agentprov-batch-") as directory:
    root = Path(directory)
    client = Client(binary=os.environ["AGENTPROV_BIN"], data_dir=root / "data")
    jobs = []
    for index in range(2):
        work = root / str(index)
        work.mkdir()
        jobs.append({
            "run_id": f"run-python-batch-{index}", "job_id": f"job-{index}",
            "workdir": str(work),
            "command": [sys.executable, "-c", "from pathlib import Path; Path('result.txt').write_text('ok')"],
        })
    result = client.run_batch_pipeline(jobs, registry, concurrency=2)
    print(result.batch_id, len(result.run_ids), result.signal_count)
```

默认导入信号并导出取证包。仅需内存中的结果时，可设置 `import_signals=False` 和 `include_forensics=False`。返回的 `BatchPipelineResult` 包含 `record_manifest`、`contexts`、`reports`、`import_report`、`forensics`、`summary`，并提供 `batch_id`、`run_ids`、`signal_count` 和 `to_dict()`。

## Client 配置

| 参数 | 用途 |
|---|---|
| `binary` | CLI 路径，默认从 PATH 查找 `agentprov` |
| `data_dir` | 本地数据目录 |
| `daemon_url` | 后台服务地址；部分方法直接使用 HTTP，其余方法仍调用 CLI |
| `env` | 调用 CLI 时追加或覆盖的环境变量 |
| `timeout` | 普通 CLI 和 HTTP 调用的超时，默认 600 秒；`None` 关闭超时 |

`record`、`eval_context`、`signals` 在设置 `daemon_url` 后直接使用 HTTP。其他方法仍需 CLI。当前直接 HTTP 路径没有 Bearer Token 配置项；需要认证时，可自行调用 [REST 接口](ai-access.md)。

`iter_eval_contexts` 使用流式子进程读取结果，不使用上述 `timeout`；消费方需负责中止或限时。

## Client 方法

| 方法 | 用途 |
|---|---|
| `run_cli(args, input_text=None)` | 调用 CLI，返回 `CommandResult`；通过 `json()` 解析输出 |
| `record(command, ...)` | 记录一次命令，支持 `run_id`、`workdir`、`name`、采样间隔和根进程退出后的等待时间 |
| `batch_record(jobs, continue_on_error=False)` | 顺序记录多条命令；开启继续处理后，失败任务返回包含错误的条目 |
| `record_batch(jobs, concurrency=1)` | 调用 CLI 批量记录，返回批次清单 |
| `evidence_manifest(run_id, materialize=False)` | 查询证据清单，可同时生成图对象 |
| `batch_summary(...)` | 按批次、执行、任务或分片查询汇总 |
| `eval_context(run_id)` | 获取一次执行的评估上下文 |
| `batch_eval_contexts(...)` | 将多个评估上下文读取为列表 |
| `iter_eval_contexts(...)` | 逐行读取上下文，适合较大批次 |
| `signals(run_id, dimension=None)` | 读取统一信号，可按维度筛选 |
| `score_trajectory(command, registry, ...)` | 记录并评估单次执行，返回 `TrajectoryScore` |
| `import_signals(run_id, signals, validate=True)` | 导入单次执行的信号，默认先检查格式 |
| `import_signal_reports(reports, engine="python-sdk")` | 批量导入评估报告 |
| `evaluate_batch(registry, ..., import_signals=False)` | 读取并评估已有执行，可选导入结果 |
| `batch_forensics(...)` | 导出批次取证包，可包含执行包和评估上下文 |
| `run_batch_pipeline(jobs, registry, ...)` | 运行完整批处理流程 |

批次查询通常使用 `batch_id`、`run_id`、`job_id`、`shard_id`、`latest` 和 `limit`；上下文读取还支持 `run_ids`。各方法的完整参数见 [Client 源码](../../python/agentprov_eval/__init__.py)。

## 编写评估规则

`Registry(name=...)` 管理一组规则。用 `@registry.rule(...)` 或 `registry.register(fn, ...)` 注册函数，可附带 `name`、`description` 和 `tags`。`registry.rules()` 返回规则列表，`registry.evaluate(ctx)` 执行规则。

规则接收 `EvalContext`，返回一个 `Signal`、字典、信号序列或 `None`：

| 上下文方法 | 返回内容 |
|---|---|
| `trajectories()` | 轨迹清单 |
| `runtime_events(event_type=None)` | 运行时事件 |
| `risks(severity=None)` | 风险信号 |
| `responses(action=None)` | 响应动作 |
| `file_changes(change_type=None)` | 文件变化 |
| `has_event_type(event_type)` | 是否出现指定事件类型 |

`ctx.run_id` 提供执行 ID，`ctx.raw` 保留完整输入。

| 信号构造方法 | 类型 |
|---|---|
| `Signal.reward_feature(name, score, reason, ...)` | 奖励特征：`reward_feature` |
| `Signal.penalty(name, score, reason, ...)` | 惩罚信号：`penalty` |
| `Signal.dataset_label(name, label, score, reason, ...)` | 数据标签：`dataset_label` |
| `Signal.quality_signal(name, score, reason, ...)` | 质量信号：`quality_signal` |

共同字段包括 `run_id`、`attempt_id`、`tool_call_id` 和 `evidence`。`to_dict()` 转为字典，`validate()` 检查名称、类型和分数。字典形式可调用 `validate_signal_dict()`。四种类型也提供对应的 `KIND_*` 常量。

`TrajectoryScore` 保存 `run_id`、`record_manifest`、`context` 和 `report`，通过 `signals` 读取信号。`reward()` 默认累加奖励特征与惩罚信号的分数；可用 `include_kinds` 改类型，用 `weights` 按名称加权。指定权重后，未列出的名称权重为 0。奖励规则由使用方定义。

## 独立评估器与便捷函数

- `evaluate()` 返回信号字典列表；`evaluate_context()` 返回一份评估报告。
- `evaluate_batch()` 接收上下文对象、字典或 JSONL 行，返回报告列表。
- `reports_jsonl()` 返回 JSONL 字符串；`emit_jsonl()` 写入指定输出流，默认标准输出。
- 全局 `rule()`、`register()` 使用 `default_registry`；多个独立评估器建议各建一个 `Registry`。
- `main(registry)` 从标准输入读取一个上下文，向标准输出写入信号 JSON，便于接入 CLI 外部评估流程。
- 顶层 `record`、`batch_record`、`record_batch`、`batch_eval_contexts`、`batch_forensics` 和 `run_batch_pipeline` 是便捷入口，可直接传入 `binary`、`data_dir` 等参数。

完整评估器例子见 [python_signal_eval.py](../../examples/evaluators/python_signal_eval.py)，模型评估接入见 [LLM Judge](../../demo/llm-judge/README.zh-CN.md)。

## 错误处理

参数或信号格式错误抛出 `ValueError`。CLI 非零退出、普通调用超时和 HTTP 错误抛出 `RuntimeError`，保留命令或服务端错误信息。批处理需要保留成功任务时，可用 `batch_record(..., continue_on_error=True)`。
