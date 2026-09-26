# 多 Agent 溯源示例的采集材料

[English](README.md) | 中文

本目录保存实验虚拟机上的采集脚本和 hook 记录，避免重启清空 `/tmp/*` 后丢失。场景说明与签名包回放方法见[示例指南](../README.zh-CN.md)。重新采集前，按文末说明配置实验环境。

## 两次尝试

两次尝试通过 hook 桥接，汇入同一份签名证据图：

- **尝试 A**：要求 `recon` 读取云凭据，并向元数据 IP 发送。保存的应用记录显示模型拒绝了该指令。该分支通过 hook 记录模型回答。
- **尝试 B**：将相同的窃取行为藏入 `setup.py install`，经 `alice` 转交给 `bob`。安装期间的敏感文件读取和元数据地址连接由内核传感器记录，再通过命令匹配归属到 `bob`。

两次尝试分别启动 Claude，hook 都追加到 `/tmp/hooklog2.jsonl`，最后合并到一次执行记录中。这样安排是因为早先将两个阶段放进一次提示时，`bob` 未能按预期参与。B 同时启用传感器，并通过命令匹配关联子 Agent 与内核事件。

## 双尝试采集文件

| 文件 | 用途 |
|---|---|
| `double-attempt-capture.sh` | 主脚本：构建、设置能力、委派 cgroup、准备模拟秘密和恶意辅助包；先运行只有 hook 的 A，再运行由传感器和 record 记录的 B；用 `hooks bridge` 合并并归属系统调用，最后导出签名包。脚本在实验虚拟机中运行，需要环境变量 `AGENTPROV_SUDO_PW` |
| `recon-run.sh` | 尝试 A：向 `recon` 提出窃取凭据的要求 |
| `team-run.sh` | 尝试 B：`alice` 将 `setup.py install` 交给 `bob` 执行 |
| `hookstamp.sh` | 为 hook 载荷补充实际时间戳 `ts`；原始标准输入没有该时间，桥接时靠它排序 |
| `hooks-settings.json` | `~/.claude/settings.json` 的 hook 参考配置；实际采集生成指向 `hookstamp.sh` 的版本 |
| `SETUP.md` | `alice` 读取并转交的原始注入指令，以“安装辅助包”为由引入恶意依赖；译文见[提示词说明](SETUP.zh-CN.md)，原文件保留不变 |
| `double-attempt-hooklog.jsonl` | 已保存实验的真实合并 hook 载荷，可用于核对桥接器实际收到的字段和结构 |

## 较早的单尝试版本

供应链安装分支最早单独采集。`bestfx-capture.sh` 和 `hooklog-sample.jsonl` 保留了仅包含 B 的版本，供最小对照使用，不含尝试 A，也没有新增时间戳步骤。

## 场景细节

- B 将恶意行为藏在子 Agent 执行的安装代码中；A 则直接提出窃取要求，保存的模型回答是拒绝。两次尝试可在同一张图中对照。
- 恶意 `pysnake-helper` 来自 `demo/snake-supply-chain/`。安装钩子读取模拟秘密 `~/.aws/credentials`、`~/.config/agentprov-demo-secrets/api_token`，并连接元数据 IP。这些动作在同一进程内执行，系统调用共享 `python3 setup.py` 的 PID。
- 进程内的子 Agent 共享 cgroup，归属主要依靠工具调用命令与传感器 `execve` 命令匹配，即 `agent_syscall` 关系；时间窗口是辅助条件。
- 传感器也会记录 Agent 自身读取 `.claude/.credentials.json` 等认证文件。默认 `self_credential_access` 规则保留这些事件，但不按高风险目标秘密读取告警，以便区分两个预置目标。

## 重新采集

先进入实验虚拟机（`ssh agentprov@<lab-vm>`）并同步仓库。脚本使用 `~/agentprovenance`、`~/agentprov-snake-demo`、`~/team-ws` 和特定 cgroup 路径，并会重建工作目录、覆盖实验用户的 hook 配置；运行前请按实验环境调整这些路径。常规新记录可参考主文档的 `launch` 流程。

在已准备好的实验环境中，将环境变量设为虚拟机 sudo 密码，再执行：

```sh
AGENTPROV_SUDO_PW='your-vm-sudo-password' \
  bash demo/multiagent-provenance/capture/double-attempt-capture.sh
```

脚本处理 setcap、cgroup 委派、模拟秘密和辅助包等步骤。Agent 每次的执行可能不同，重新采集后可与现有签名记录比较。
