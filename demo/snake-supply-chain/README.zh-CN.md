# 恶意依赖示例：贪吃蛇项目

[English](README.md) | 中文

本目录提供已签名的执行记录，以及重新采集所需的脚本。示例使用 Claude Code 和 DeepSeek：Agent 接到开发贪吃蛇游戏的任务后，安装了被植入恶意代码的 `pysnake-helper`。安装脚本读取预置的假凭据，并尝试连接云元数据地址 `169.254.169.254`。

eBPF 传感器记录文件访问和网络连接。数据流与污点视图根据这些事件推断潜在的敏感数据流。仅凭读取和连接记录，不能证明凭据内容已传输或被接收。

有关场景、视图操作、合规映射和验证方法，参见[完整演示说明](../../docs/supply-chain-demo.md)。

## 打开回放

下载并解压[预编译版本](https://github.com/ByteYellow/AgentProvenance/releases/tag/v0.8.2-rc.2)，在解压目录执行：

```sh
./agentprov demo snake-supply-chain
```

程序先验证签名，再打开对应的执行记录和视图。数据保存在临时目录，按 Ctrl-C 退出时清理。回放无需 Go、虚拟机、Kubernetes 或模型账号。

运行 `./agentprov demo` 可查看全部示例及阅读指南。页面首次打开时跟随浏览器语言，未匹配时使用英文；右上角可手动切换，后续访问会保留选择。

## 文件说明

| 文件 | 用途 |
|---|---|
| `run-snake-supervised.forensics.json.gz` | 用于导入和回放的证据包 |
| `run-snake-supervised.forensics.dsse.json` | DSSE/Ed25519 签名证明 |
| `attestation.pub` | 验证签名的公钥 |
| `capture/` | 在 Linux/eBPF 环境重新采集的脚本 |

## 手动导入

如果需要保留导入的数据，可在源码根目录执行：

```sh
go build -o /tmp/agentprov ./cmd/agentprov
/tmp/agentprov --data-dir /tmp/snake-replay forensics import \
  demo/snake-supply-chain/run-snake-supervised.forensics.json.gz \
  --pub-key demo/snake-supply-chain/attestation.pub
/tmp/agentprov --data-dir /tmp/snake-replay dashboard serve
```

页面打开后，选择执行记录 `run-snake-supervised`。指定 `--pub-key` 后，导入前会验证签名；验证失败则拒绝导入。

## 重新采集

需要支持 eBPF 的 Linux 主机，以及 `CAP_BPF` 和 `CAP_PERFMON` 权限。以下流程使用常驻节点传感器和 `record`：前者接收运行时事件，后者将 Agent 及其子进程放入独立的 cgroup v2。

先在本示例目录准备工作区、假凭据和恶意依赖：

```sh
bash capture/vm-snake-assets.sh
```

将 `DD` 设为本次采集的数据目录，并确保 `agentprov` 位于 PATH 中。随后启动传感器和 Agent：

```sh
agentprov --data-dir "$DD" sensor stream &

AGENTPROV_CGROUP_PARENT=/sys/fs/cgroup/agentprov \
  agentprov --data-dir "$DD" record --run run-snake-supervised \
    --workdir ~/agentprov-snake-demo/workspace -- bash ~/agentprov-snake-demo/run-agent.sh

agentprov --data-dir "$DD" graph materialize --run run-snake-supervised
agentprov --data-dir "$DD" forensics export run-snake-supervised --sign-key <key>
```

将 `<key>` 替换为签名私钥路径。非 root 用户需要获得 `/sys/fs/cgroup/agentprov` 的委派权限；也可使用 root 运行 `record`。传感器排除自身活动，并丢弃不属于目标执行的主机事件。

此采集流程通过 `cgroup_id` 关联进程树，记录的关联置信度为 0.98，并标记 `self_launched`。该数值是关联规则给出的等级，不是经过统计校准的准确率。`record` 还会保存变更文件的内容对象，供页面预览 `snake.py` 等产物。

示例使用真实模型执行任务。预置凭据均为假数据，元数据地址在原演示环境中不可达；复现时仍应使用隔离环境和假凭据。
