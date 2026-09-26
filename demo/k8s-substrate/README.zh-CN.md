# Kubernetes 示例：从节点采集 Pod 行为

[English](README.md) | 中文

本示例展示 `k8s-daemonset` 采集方式：Agent 在普通 Kubernetes Pod 中运行，节点上的 eBPF 传感器记录系统调用，并通过 cgroup 将事件归属到执行记录。对于节点能够访问的 TLS 库，传感器还可采集部分模型请求和响应。

工作负载不需要增加 sidecar、接入 SDK 或通过 `agentprov record` 启动。[跨 Pod 协作示例](../k8s-cross-pod-a2a/README.zh-CN.md) 在此基础上展示多个 Pod 的事件归属。

## 打开回放

下载并解压[预编译版本](https://github.com/ByteYellow/AgentProvenance/releases/tag/v0.8.2-rc.2)，执行：

```sh
./agentprov demo k8s-substrate
```

程序先验证签名，再打开执行记录 `claude-demo` 和运行环境视图。数据保存在临时目录，按 Ctrl-C 退出时清理。回放无需 Go、虚拟机、Kubernetes 或模型账号。

运行 `./agentprov demo` 可查看全部示例。页面首次打开时跟随浏览器语言，未匹配时使用英文；右上角可手动切换，后续访问会保留选择。

## 采集场景

`claude-agent` Pod 内的 Python Agent 循环请求模型服务，包括 `POST api.anthropic.com/v1/messages` 和 `POST api.deepseek.com/chat/completions`。

节点传感器记录 `execve`、`connect`、`openat` 等事件。`sandbox bind-cgroup` 将 Pod 的 cgroup 绑定到执行记录，并保存命名空间、Pod 名称、UID 和镜像信息。

```text
Kubernetes 节点
├─ claude-agent Pod
│  └─ python3 agent.py
│     ├─ HTTPS 请求模型服务
│     └─ 使用容器内的 libssl.so.3
│
└─ 节点 eBPF 传感器
   ├─ 系统调用：execve、openat、connect
   ├─ TLS 写入：SSL_write，包含模型请求
   └─ TLS 读取：SSL_read，部分响应可见
            ↓
   cgroup 绑定及 Kubernetes 元数据
            ↓
   claude-demo 执行记录
   运行环境视图：采集方式 → 节点 → Pod → cgroup → 执行记录
```

TLS uprobe 按文件 inode 挂载。将 `AGENTPROV_SSL_LIB` 指向 `/proc/<pid>/root/.../libssl.so.3`，可从节点访问容器内实际使用的库。是否能够采集，取决于权限、库符号、协议和挂载结果；不能由“Pod 正在运行”推定 TLS 已完整覆盖。

采集入口使用 `AGENTPROV_TLS_CAPTURE_BODY=1` 保存完整内容，再通过 `graph materialize-llm` 建立模型调用节点。

## 各视图的内容

| 视图 | 本次记录中可查看的内容 |
|---|---|
| 运行环境（Substrate） | `k8s-daemonset` 采集方式、节点传感器、`default/claude-agent` Pod、cgroup 和执行记录 |
| Agent 意图（Agent intent） | `llm_call` 节点中的模型请求，以及成功采集到的响应；模型标识保留原文 |
| 网络外发（Network-egress） | 到模型服务 IP 的连接；本次历史记录主要提供 IP |
| 进程（Process） | `python3 agent.py` 的进程树 |
| 信任来源与沙箱边界 | 内核观测、Kubernetes 声明、关联推断及边界跨越 |

## 手动导入与查看

证据包包含实际采集记录，其中有从节点采集到的 DeepSeek 响应。可在源码或发行包根目录执行：

```sh
agentprov --data-dir /tmp/sub-view init
agentprov --data-dir /tmp/sub-view forensics import \
  demo/k8s-substrate/run-claude-demo.forensics.json.gz \
  --pub-key demo/k8s-substrate/attestation.pub
agentprov --data-dir /tmp/sub-view graph verify --run claude-demo
agentprov --data-dir /tmp/sub-view dashboard serve
```

导入前验证 DSSE 签名，篡改后会拒绝导入。图验证预期返回 `status=ok`、`errors=0`。打开页面后选择 `claude-demo`。

## 重新采集

需要单节点 k3s 或 Kubernetes、Docker，以及节点上的 root 权限。正常模型响应需要 `agent-keys` Secret 中的 `DEEPSEEK_API_KEY` 或 `ANTHROPIC_API_KEY`。没有有效密钥时，接口可能返回 401；请求内容仍可能被采集，但这不能替代成功调用的验收。

在源码根目录执行，将示例密钥替换为测试环境的实际配置：

```sh
AGENTPROV=./agentprov SENSOR=./agentprov-sensor \
DEEPSEEK_API_KEY=... \
  bash scripts/demo_k8s_substrate.sh
```

脚本会启动页面。选择 `claude-demo`，从运行环境视图查看归属关系。

## 本次历史记录的限制

- **响应覆盖不完整。** 原采集中的 `SSL_write` 能记录请求；`SSL_read` 对分块响应和 HTTP/2 的重组存在缺口，部分响应无法还原。这个历史证据包不能证明当前版本的全部 TLS 能力。
- **正文需显式开启。** 默认仅保留 SHA-256 和短预览；`AGENTPROV_TLS_CAPTURE_BODY=1` 才保存完整正文。提示词和响应可能包含敏感内容。
- **网络连接主要显示 IP。** `connect()` 提供目标 IP。域名需要额外的 DNS 或 TLS/HTTP 信息，本次记录未完整提供，不能根据 IP 猜测域名。
- **归属包含置信等级。** 本次 `k8s_cgroup` 关联标为 0.8，表示规则的置信等级，不是准确率或采集完整度。不同采集路径的等级不能作为覆盖范围的替代指标。
