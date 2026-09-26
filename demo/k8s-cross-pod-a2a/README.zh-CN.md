# 跨 Pod 协作示例：两个 Pod，一份证据图

[English](README.md) | 中文

本示例将[Agent 团队协作场景](../multiagent-provenance/README.zh-CN.md)放入同一 Kubernetes 节点上的两个 Pod：`alice` 通过网络向 `bob` 发送安装指令，`bob` 执行恶意依赖。一个节点传感器同时采集两个 Pod 的内核事件，并保留各自的 cgroup 归属。

应用侧的委派、消息和拒绝记录来自已保存的 hooks 日志；跨 Pod 网络通信及安装行为则在本次实验中实际执行并采集。两种来源必须分别理解。

## 打开回放

下载并解压[预编译版本](https://github.com/ByteYellow/AgentProvenance/releases/tag/v0.8.2-rc.2)，执行：

```sh
./agentprov demo k8s-cross-pod-a2a
```

程序验证签名后打开执行记录 `a2a-demo` 和运行环境视图。临时数据在 Ctrl-C 退出时清理。回放无需 Go、虚拟机、Kubernetes 或模型账号。

运行 `./agentprov demo` 可查看全部示例。页面首次打开时跟随浏览器语言，未匹配时使用英文；右上角可手动切换，后续访问会保留选择。

## 场景与采集方式

- `alice` 位于 Pod A，通过实际网络调用向 `bob` 发送安装指令。
- `bob` 位于 Pod B，执行 `python3 ../pysnake-helper/setup.py install --user`。
- 安装脚本读取预置的假凭据，将内容暂存到 `harvested_creds.bin`，并连接元数据地址 `169.254.169.254`。

```text
同一 Kubernetes 节点
├─ Pod A：alice
│  └─ HTTP 请求 → bob:8080
│                    ↓
├─ Pod B：bob
│  └─ 执行 setup.py install --user
│     ├─ openat：读取假凭据
│     ├─ write：写入 harvested_creds.bin
│     └─ connect：169.254.169.254
│
└─ 节点 eBPF 传感器
   ├─ 分别记录 Pod A、Pod B 的 cgroup_id
   └─ 将两个 cgroup 绑定到 a2a-demo
            ↓
   hooks bridge --correlate
   合并应用侧记录，并通过命令匹配关联系统调用
```

示例主动将两个 cgroup 绑定到同一次执行，使已有的执行内关联逻辑能够建立 `alice → bob` 关系。每条事件仍保留原始 `cgroup_id`。

这不代表已经实现独立执行之间的自动关联。将两个独立 Run 通过交接标识关联，是另一个问题；本示例没有验收该能力。

## 协作视图中的两条分支

```text
主协调 Agent（a2a-demo）
├─ 尝试 A：直接提出窃取凭据
│  └─ recon → refused
│     来自先前 hooks 记录，本分支没有本次内核证据
│
└─ 尝试 B：通过跨 Pod 消息安装恶意依赖
   ├─ alice（Pod A）
   │  └─ SendMessage → bob
   │     指令：python3 ../pysnake-helper/setup.py install --user
   │     网络：Pod A → Pod B，记录为 private_cidr
   └─ bob（Pod B）
      └─ Bash → execve：python3 setup.py
         ├─ secret_path：~/.aws/credentials
         ├─ secret_path：~/.config/.../api_token
         ├─ file_write：harvested_creds.bin
         └─ metadata_ip：169.254.169.254
```

安装进程的 PID 用于限定“读取敏感文件 → 写入文件 → 网络连接”的关联范围。它支持调查潜在的数据流，但并未直接记录网络请求正文。

## 各视图的内容

| 视图 | 内容 |
|---|---|
| 协作（Orchestration） | 任务委派、`alice → bob` 消息、`recon` 的拒绝和 `agent_syscall` 归属关系 |
| 运行环境（Substrate） | 两个 Pod、各自的 cgroup，以及由跨 Pod 调用推导出的 `pod_influences_pod` 关系 |
| 数据流与污点 | 限定在 `bob` 进程内的 `possible_sensitive_data_flow` 推断 |
| 文件与产物 | 根据原始 `file_write` 事件建立的 `harvested_creds.bin` 文件节点 |
| 安全 | `secret_path_access`、`metadata_ip_dst` 等风险，以及事件、策略、风险和响应之间的关系 |
| 网络外发 | `bob → 169.254.169.254` 和 `alice → bob` 的连接 |
| 进程、信任来源与沙箱边界 | 进程树、证据来源类别和边界跨越 |

## 归属验收

采集脚本检查以下结果：

- `secret_path` 和 `metadata_ip` 事件属于 `bob` 的 cgroup，`alice` 的 cgroup 中这两类事件为 0。
- `alice → bob` 的网络请求被采集为 `private_cidr`，因为目标是 Pod 私网地址。
- `agent_syscall` 将 `bob` 的安装调用与 Pod B 的系统调用关联。
- `graph verify` 返回 `errors=0`。

这些结果支持本次事件的 Pod 归属。`alice` 中没有记录到上述事件，不等于证明它没有任何异常行为；图验证通过也不等于采集完整。

## 手动导入与查看

在源码或发行包根目录执行：

```sh
agentprov --data-dir /tmp/a2a-view init
agentprov --data-dir /tmp/a2a-view forensics import \
  demo/k8s-cross-pod-a2a/run-a2a-demo.forensics.json.gz \
  --pub-key demo/k8s-cross-pod-a2a/attestation.pub
agentprov --data-dir /tmp/a2a-view graph verify --run a2a-demo
agentprov --data-dir /tmp/a2a-view dashboard serve
```

导入前会校验 Ed25519/DSSE 签名，篡改后拒绝导入。打开页面后选择 `a2a-demo`。

证据文件分别为 `run-a2a-demo.forensics.json.gz`（证据包）、`run-a2a-demo.forensics.dsse.json`（签名证明）和 `attestation.pub`（公钥）。

## 重新采集

需要单节点 k3s 或 Kubernetes、Docker，并在节点上使用 root 运行。传感器需要 eBPF 权限，实验中的 k3s 配置也仅允许 root 读取。

在源码根目录执行：

```sh
AGENTPROV=./agentprov \
SENSOR=./agentprov-sensor \
HOOKLOG=demo/multiagent-provenance/capture/double-attempt-hooklog.jsonl \
  bash scripts/demo_k8s_a2a.sh
```

脚本打印归属检查结果，验证图后启动页面。

## 证据范围与限制

- **应用侧记录是回放，内核事件是本次采集。** 委派、消息和拒绝来自已提交的 hooks 日志，标记为 `binding_source=hooks`。桥接器不生成系统调用；命令匹配建立的 Agent 归属仍是推断。此示例的模型提示词和响应记录较少。
- **文件节点来自传感器。** Pod 没有通过 `record` 启动，因此不存在工作区前后快照。文件视图直接使用 `file_write` 事件，并过滤 `/dev/null` 等伪文件，不代表保存了每次文件访问或完整文件内容。
- **采集没有阻断执行。** `recon` 的拒绝来自意图层；`bob` 的安装被允许，异常在运行时被记录。页面上的策略和响应记录不能代替实际阻断验收。
- **仅使用假凭据。** 示例中的 AWS 凭据和 API Token 均为测试数据。元数据地址连接用于复现行为特征，不应替换为真实凭据或实际攻击目标。
