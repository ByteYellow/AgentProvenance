# 变更记录

[English](CHANGELOG.md) | 中文

按版本记录新增功能、调整和修复。使用方法见 [README](README.zh-CN.md)。

## v0.8.2 - 2026-09-26

下载即用的回放体验、中文文档与网页界面。发行说明：[v0.8.2](docs/zh-CN/releases/v0.8.2.md)。

### 新增

- Linux/macOS 的 amd64/arm64 预编译包，附带校验文件、构建信息、全部示例源码和中英文入门指南。回放无需安装 Go。
- 一条命令打开示例首页和阅读页，集中展示六份签名采集记录与两个可选评估器示例，沿用 Dashboard 样式。
- 中文 Dashboard、示例页面、评估器工作台、文档、接口和 SDK 指南，以及中文图示和回放动画。
- CI 检查中文文档缺页、链接、界面词条和双语 OpenAPI 契约；四个平台的压缩包验收覆盖双语指南。

### 调整

- 网页首次访问时跟随浏览器语言，手动选择后保留偏好。英文继续作为回退语言和命令行、工具输出的默认语言；已有的 `--lang zh-CN` 选项继续可用。
- 切换语言时保留当前页面状态和复核草稿，原始证据与协议字段值保持不变。

### 修复

- 为健康接口的响应说明补上 YAML 引号，避免解析器将句子中的逗号识别为额外字段。

## v0.8.2-rc.2 - 2026-09-26

预发布：示例首页沿用 Dashboard 风格，提供排版后的本地指南阅读页。发行说明：[v0.8.2-rc.2](docs/zh-CN/releases/v0.8.2-rc.2.md)。

### 调整

- 示例首页和指南阅读页与 Dashboard 统一主题，支持响应式布局、章节目录、表格、内嵌图片和代码复制。
- 更新中英文介绍、全部示例入口、产品与部署指南、截图和包内说明，介绍预编译包的使用流程。
- 各平台压缩包验收覆盖八个指南入口及阅读页资源。

## v0.8.2-rc.1 - 2026-09-26

预发布：预编译 CLI 与全部示例回放。发行说明：[v0.8.2-rc.1](docs/zh-CN/releases/v0.8.2-rc.1.md)。

### 新增

- Linux/macOS 的 amd64/arm64 预编译包、单文件及汇总 SHA-256 校验和、源提交与构建元数据，以及 `agentprov --version`。
- `agentprov demo` 内嵌六份签名采集记录和两个可选评估器指南；回放前校验证据，使用隔离的临时存储。
- 四个平台在 PATH 不包含 Go 的环境下验收实际解压后的压缩包。全部原始示例源码随 CLI 分发。

## v0.8.1 - 2026-09-22

在 `demo/jev-judge/` 增加可选的外部评估器接入示例。发行说明：[v0.8.1](docs/zh-CN/releases/v0.8.1.md)。已有证据与信号接口不变，不增加核心模块或必需的运行时依赖。

### 新增

- **Jev 参考适配器。** 有界 TypeSafe/Jev 客户端对选定的行动声明、运行时一致性和秘密传输证据进行评估，保留原始请求响应、概率、模型标识和哈希。
- **独立演示页面。** 单独启动工作台，比较人工编写的 v1/v2 评估标准，记录独立参考标签和批准／拒绝结果。已评审信号通过现有接口显式导入，工作台不嵌入主证据 Dashboard。
- **评审边界。** 使用固定的运行时覆盖缺失检查、逐问题回归检查和只追加的本地评审修订；参考评审变化后使旧批准失效。没有优化器、自动提升或自动处置。
- **无密钥回归测试。** 覆盖可选示例；实际 API 调用与本地浏览器验收按日期另行记录，不混作 CI 结果。

## v0.8.0 - 2026-09-20

完善 Linux、KVM 客体和 Kubernetes 的原生证据采集可靠性，入门流程从已有证据回放开始。详细验收与限制见 [v0.8.0 发行说明](docs/zh-CN/releases/v0.8.0.md)。

### 新增

- **原生 Linux amd64 传感器。** 按架构选择独立 eBPF 对象，处理 amd64 C 和 Go ABI，增加旧版 open/unlink 探针、内核采集时间，以及系统调用、OpenSSL 和 Go TLS 实机验收。保留已有 ARM64 绑定。
- **KVM 客体与 K3s 部署。** 客体内 systemd 采集、节点归属控制器，以及多工作负载、语义一致性、进程重启、正常重启、导入导出和数据库升级验收。KVM 使用 `local-record`。
- **容器 TLS 自动发现。** 根据可见进程和 rootfs 发现目标，去重共享库，并随目标生命周期核对挂载状态。受支持的 amd64 Go 1.23–1.26 程序通过解码返回位置及 goroutine／栈帧配对采集响应；移除符号或不受支持的目标报告覆盖缺口。
- **原生流持久化。** `sensor stream` 使用有界持久批次、迟到绑定重试、中断批次恢复、事务去重，以及丢失和积压报告。
- **就绪接口。** `/v1/live` 与数据库、格式就绪状态分开。存储失败返回 503，未知队列计数为 null；报告历史采集丢失时，不会把当前可用的存储误报为不可用。
- **回归验收。** 冻结格式的升级测试、真实 HTTP 就绪故障检查、Go 1.23–1.26 的 amd64 实机测试，以及 Linux amd64/arm64 静态构建。

### 修复

- 关联按真实时刻比较不同小数精度和时区偏移的时间，能看到当前事务中的绑定变化，排队事件保留采集时间。record 在启动工作负载前发布绑定。
- 共用摄入路径以原子方式写入事件、关系、证据及关联状态，错误向上传递，不留下部分记录。JSONL 行级保存点隔离失败事件，同批有效行仍可提交。
- CPU 样本清理按解析后的真实时刻比较，正确排序不足一秒的样本；遇到无效时间时回滚本次清理。
- 健康接口的 OpenAPI 3.1 定义使用明确的 integer/null 联合类型，并对照健康和存储不可用时的 HTTP 响应检查。
- 原生恢复保留文件缺失诊断，拒绝无法重放的超大行；载荷清理失败可稍后重试，不阻塞采集器重启。

### 调整

- 中英文 README 先介绍签名证据包回放，再介绍实时采集。回放和本地 record 无需 Docker；launch 签名明确为可选。保留已有真实示例和图片。
- 能力说明、架构 SVG、示例索引、部署指南和收尾标准同步到 KVM 与当时 TLS 覆盖状态。旧路线图标为历史设计。
- Falco 专用缓冲的重启恢复不变。共用摄入修复适用，但原生流恢复保证不能直接套用于 Falco。

## v0.7.2 - 2026-08-05

加固证据采集与调查能力。Kubernetes 生产者从采集预览发展为经过测量、能处理生命周期变化的节点配置；增加有界的大批量摄入，并将外发数据作为通用可查询证据。

### 新增

- **Kubernetes 生命周期归属。** 带过滤条件的 `client-go` informer 将 Pod、容器生命周期映射到内核 cgroup 绑定，处理容器重启和 Pod 删除。一个特权节点传感器可观测多个独立工作负载，无需修改工作负载 Pod。
- **本地与 Kubernetes 语义一致性验收。** 相同的 `id + ls /` 工作负载分别经过主动 `local-record` 和被动 `k8s-daemonset`。两份图校验错误和警告均为 0，保留相同的 `execve -> runtime_process -> runtime_event` 规范化语义，以及各自不同的归属置信等级。
- **有界遥测摄入。** 服务磁盘缓冲限制批次数、总字节数和单批大小，明确拒绝、丢弃行为及生产者健康计数。保存的 10 万事件报告包含吞吐、查询与健康接口延迟、内存、队列状态、丢弃和关联覆盖。
- **外发数据视图。** 端点采集、规范化外发证据、意图偏差、风险／响应关系和通用调查卡片，覆盖敏感上下文、源码包上传尝试和第三方行为遥测。
- **Grok CLI 调查场景。** 可回放示例分别展示秘密进入模型上下文、源码上传调查和产品遥测三类外发路径；各路径的实际证据范围见示例说明。

### 调整

- **能力状态以验收为依据。** 生产者配置报告 `validated` 或 `planned`。`microvm-guest-init` 仍可查询，但在客体运行器和 KVM 实机验收完成前，报告无覆盖、置信度为 0；本地与 Kubernetes 配置已验证。`agentprov sandbox profiles --json` 提供机器可读报告。
- **补全被动运行时关系。** 即使没有应用层进程标识，按 PID 建立的运行时进程节点也能连接到对应事件，支持无需 SDK 的 Kubernetes 采集。
- **中心服务仍为设计。** 该版本验证有界单节点生产者，并说明横向扩展边界，不包含多租户控制面。

## v0.7.1 - 2026-07-09

增加无需侵入 Pod 的 K8s 归属和多 Agent 框架应用上下文接入。Pod 采集可一条命令完成或自动发现；外发目标可显示域名，节点侧响应采集得到修复。应用上下文从 Claude Code 扩展到 Kimi Code 和 Codex 的会话记录，并完成相应端到端验证。

### 新增

- **`agentprov sandbox capture`：单次 Pod 归属采集。** 将节点侧 PID/cgroup 解析、Pod 元数据获取、bind-cgroup、传感器启动和摄入合成一条命令。`--container` 可选择多容器 Pod 中的特定容器。libssl/libc uprobe 指向 Pod 自身的 `/proc/<pid>/root`，在节点侧采集模型意图和 DNS。
- **`agentprov sandbox watch`：自动归属的第二阶段预览。** 节点循环发现 Pod，并分别绑定到执行记录，无需逐 Pod 操作。`agentprov.io/run` 注解指定执行记录，否则按 UID 自动创建。当时使用 kubectl 轮询，尚非 client-go informer；每轮共用一个传感器，模型意图覆盖弱于 `capture`，需要该层证据时使用后者。
- **外发显示域名。** getaddrinfo uprobe 指向 Pod 自身 libc，采集 DNS 查询；Dashboard 将 `dns_query` 主机名与后续连接关联，显示 `api.deepseek.com` 等域名。
- **多框架应用上下文：`hooks bridge --harness kimi|codex|claude`。** 轻量适配器将会话记录规范化后送入已有桥接器。支持 Kimi Code 的 `wire.jsonl`，将单 Agent 和多 Agent 委托合并到同一实际时间线；支持 Codex 的 `rollout-*.jsonl`，将 `exec_command` shell 工具规范为 Bash 以进行命令匹配。三种框架均用真实执行完成端到端检查。

### 修复

- **节点侧 `tls_read` 可靠性。** 以连接关闭为边界的 HTTP 响应没有正文内终止标志，在复用 SSL* 连接的长期工作负载中可能一直缓冲并丢失。现在新请求会刷出待处理响应；当时节点测试的读取采集从 0 改善到与 tls_write 的 1∶1。部分 TLS 探针挂载失败也会明确报告。

## v0.7.0 - 2026-07-08

引入跨环境生产者配置，沿用原证据图和格式，将本地／虚拟机采集扩展到 **Kubernetes Pod**。核心从 SQLite 读取规范化遥测，不依赖具体运行环境。不同生产者分别说明传感器位置、归属方式、传输方式及可采集层次。一个节点传感器可观测多个 Pod cgroup，并将它们分别绑定到签名执行记录。microVM 客体配置先作为能力声明提供，实际集成仍在进行中。

### 新增

- **生产者配置：`internal/producer/profile.go`。** 声明传感器位置、归属模式及系统遥测、模型意图、应用上下文三层覆盖，将降级明确记录为数据。提供 `local-record`、`k8s-daemonset`、`microvm-guest-init`；最后一项当时仅声明能力，运行器和客体镜像集成尚未完成。
- **k8s-daemonset 归属。** `agentprov sandbox bind-cgroup` 将节点观测到的 Pod cgroup 以被动 `k8s_cgroup` 来源绑定到执行记录，置信度为 0.8，主动 record 的内核验证等级为 1.0。可把集群、节点、命名空间、Pod、容器、镜像、服务账号、Pod IP 和标签作为上下文事件补充，无需改格式，当时也无需 client-go informer。
- **运行环境视图：Dashboard 与 `graph lens --lens substrate`。** 展示配置 → 节点传感器 → 工作负载 → Pod cgroup → 执行范围 → 执行记录。某 Pod 的外发目标匹配另一 Pod IP 时，可建立 `pod_influences_pod` 关系。执行概览展示证据来源、归属来源和置信度；底层网络连接与派生的 Pod 影响关系应区分理解。
- **节点侧 Pod 模型意图。** libssl uprobe 按 inode 挂载，指向 Pod 的 `/proc/<pid>/root/.../libssl.so.3` 即可在节点侧采集对应 TLS 请求响应，无需改镜像。自动发现 Python 模块加载的 OpenSSL（`_ssl.so`）。
- **一致性验收：`scripts/accept_k8s_pod_parity.sh`。** 检查节点观测的 Pod 遥测归属到执行记录，校验结果 `errors=0`。Pod 由外部调度，未经 `record` 包装，也能生成可校验记录。

### 调整

- **被动绝对路径写入生成文件节点。** 原先文件节点仅来自 record 的工作区差异，使用工作区相对路径。节点侧被动采集没有该差异，绝对路径写入因此缺少文件节点。摄入现在将有意义的绝对路径连接到 `workspace_file/<abspath>`，过滤 `/dev/null`、`/proc`、`/sys`、套接字和管道，并关联写入进程，供文件、原始证据和污点视图查询。

### 示例

- **`demo/k8s-substrate/`**：展示 k8s-daemonset 的完整流程。在节点侧采集真实 LLM Agent Pod 的系统遥测和模型意图，按 cgroup 归属，提供签名回放包 `run-claude-demo`。
- **`demo/k8s-cross-pod-a2a/`**：通过真实跨 Pod A2A 网络调用，展示 Pod A 的 `alice` 影响 Pod B 的 `bob`；一个节点传感器将 `bob` 的秘密读取、暂存文件和元数据 IP 连接归到其 cgroup，两个 cgroup 汇入签名记录 `run-a2a-demo`。采集过程见示例指南。

## v0.6.0 - 2026-07-06

增加一条命令的采集流程和意图一致性分析。`agentprov launch -- <agent>` 将 Agent 纳入溯源记录；意图分析开始比较行动声明与实际效果，区分越界、拒绝后仍执行和覆盖缺口。提示词及可见说明从会话记录读取，无需修改 Agent。

### 新增

- **`agentprov launch -- <agent>`：`internal/launch`。** 创建执行范围、启动实时 Dashboard，通过 `--settings` 注入本次运行专用的 Claude Code hook 配置，不修改用户的 `~/.claude`；主机满足条件时启动内核传感器，否则报告降级；在专用 cgroup 中执行 Agent，结束后封存证据图、按签名配置签名并输出结论。启动时分别报告应用侧证据（hook／会话记录或仅 record）与系统侧证据（内核遥测或无）。增加隐藏的 `internal` 命令组，开始区分日常入口与底层工具。
- **`agentprov doctor -- <agent>`：启动前检查。** 无需启动 Agent 即可检查程序位置、Claude hook 注入兼容性、Dashboard 端口、cgroup v2 范围和内核采集能力。明确报告降级原因；`--json` 供安装脚本读取。
- **意图与运行时比较：`internal/intent`、`agentprov intent diff`。** 将工具调用、同伴消息或拒绝对应的 IntentContract，与归属到其范围的 RuntimeEffects 比较。结果包括 `declared_vs_effect_mismatch`、`refused_but_runtime_happened`、`decided_and_executed` 和 `intent_coverage_gap`。无法关联到已捕获意图的效果报告为缺口，不凭空补成发现。效果分类复用策略引擎，区分目标秘密和 Agent 自身凭据；是否越界依赖具体声明，例如只读工具不应连接网络，而 Bash 可允许。结果进入统一信号的 `intent_conformance` 维度，并影响 launch 结论；`peer_message_intent_mismatch` 表示来自同伴消息的意图与效果不符。
- **会话记录提取。** 从 Claude Code hook 标准输入指向的 JSONL 提取模型提示词、可见说明和工具决策，接入与 TLS 采集共用的 `llm_call` 模型。在不同平台无需插桩，沿用 Agent 意图视图。
- **意图一致性视图。** 展示约束范围 → 比较结论 → 观测效果，按状态着色，同时展示委托和对等 Agent 关系。

### 调整

- **Agent 意图图汇总大量派生事件。** 一次模型响应引出大量系统调用时，超过阈值后聚合为“引发 N 次系统调用”，保留清楚的提示词、决策、行动主线。具体调用仍可在进程或安全视图中查看。
- **用 `launch` 重新采集示例。** 贪吃蛇供应链和 Agent 团队的证据包改用一条命令采集，并附带会话记录。恶意安装的秘密读取和元数据地址连接被标为超出 `install` 声明范围，关联到执行该调用的子 Agent。

同一版本还将 LLM 流量证据接入签名图：传感器捕获支持范围内的 TLS 明文，重组、解析后关联模型调用与实际命令。Agent 意图视图改为基于证据节点的有向无环图；新增外部 LLM 评估示例，评估过程本身也可审计。

### 新增

- **TLS 正文采集：`internal/sensor`。** SSL_write/SSL_read uprobe 将明文按 TLS 连接和方向拆成有序片段；此前只保留哈希与有界元数据。
- **TLS 重组与 LLM 语义：`internal/tlsintent`。** 用户态将片段重组为完整 HTTP/1.1 消息，支持 Content-Length、分块和 SSE 正文。当时通过客户端前言识别 HTTP/2 后按原始数据传递，避免误解析。兼容 Anthropic Messages 和 OpenAI Chat Completions 的最小语义：模型、消息数、系统提示词是否存在、可用工具、工具调用、声明的 shell 命令及停止原因。模块不依赖 eBPF，可在非 Linux 平台单元测试。
- **签名图中的 LLM 调用：`graph materialize-llm`、`internal/provenance.MaterializeLLMCalls`。** 正文存为内容寻址的 `llm_message`；请求响应对生成 `llm_call` 节点，包含 `llm_request`、`llm_response`、`llm_body` 关系。操作幂等，纳入 `graph verify` 和 `scripts/accept_llm_intent_causality.sh` 检查。
- **`llm_caused` 限于匹配的命令。** 只有实际执行命令匹配模型响应中的 `tool_command`，才建立 `llm_call` 到系统调用的关系。旧的摄入期 `llm_intent_caused` 不再渲染，改用生成的 `llm_caused`。
- **Agent 意图视图改为因果图。** 用真实证据节点展示 `llm_call` → 声明命令 → 进程 → 运行时事件 → 风险；拒绝或被策略标记的意图作为独立节点，按提出它的 Agent 分组。执行概览中的工具调用和 LLM 意图入口可直接进入该图。
- **Dashboard 的 LLM 主线与可读性。** 存在模型调用时，`summary` 优先展示其生命周期路线，发送消息步骤对应协调者委托；改进 execve 标签，支持 tool_call／event 内容预览，保留展开状态，并将节点标签限制在边框内。
- **LLM 评估示例：`demo/llm-judge/judge.py`，第 3 阶段。** 单文件、仅依赖 Python 标准库的评估器，通过通用 EvalContext、AI 工具和图视图读取完整轨迹，不按事件类型预筛选；超出上下文预算时分块归纳，并记录覆盖情况。兼容 Anthropic/OpenAI 协议的模型返回 `agentprovenance.llm_judge/v1` 结构化判断，再导入为带图引用的信号。评估器自身在 `record` 下运行，其请求响应成为评估记录中的 `llm_call`；没有密钥时可使用离线测试数据。
- **示例包中的真实模型调用：`demo/shared/llm-intent-curl.sh`。** 两套采集脚本通过 curl/OpenSSL 发起一次真实的模型与工具意图请求，密钥放在请求头，不写入脚本或正文。重新采集并签名的第 1、2 阶段包包含选择恶意安装命令的模型调用，按 `llm_call` → `llm_caused` 关联到匹配系统调用。

### 调整

- **README 按证据层介绍。** 使用统一的 `record -- <cmd>` 入口，以内核／运行时事实为基础，再补充 hooks bridge、MCP 上下文写入等应用声明。`ai_asserted` 的置信度不高于 0.5。去除原白盒／无 SDK 两套入口的表述，并同步 `docs/product.md`。
- **完整命令参考移入文档。** 分别放到 `docs/security-commands.md`、`docs/graph-commands.md`、`docs/compliance.md`；Python 自定义规则并入外部评估器协议，减少重复说明。
- **Falco 改为兼容入口。** README 中的对应章节移到 `docs/falco-receiver.md`。原生 eBPF 传感器作为主要内核证据来源，Falco/Tetragon 接收器保留兼容维护，不再扩展。

### 修复

- **大范围 `graph explain` 崩溃。** 遥测批次改在 Go 中按事件标识匹配，避免每个事件各拼一条 SQL `LIKE`，触发 SQLite 约 1,000 层的表达式深度上限，影响 `--attempt/--tool-call/--process/--file`。
- **图渲染结果可重复。** 参与因果图的 `created_at` 排序增加标识作为并列条件；视图摘要按 `(created_at, node id)` 遍历，`/api/graph` 的节点输出排序。BFS 顺序、`page_hash`、evidence_refs 和每视图 32 项截断结果在重建前后保持稳定，两个示例包分别验证 3 次。
- **子 Agent 身份。** Agent 工具启动的子 Agent 从 `name` 字段读取名称，不再回退为通用标识。
- **性能。** 图关系增加 `(run_id, created_at, id)` 索引，缓存视图元数据。

## v0.5.0 - 2026-07-03

增加多 Agent 编排溯源：在同一签名图中，将 Claude Code 团队的委托和同伴关系关联到真实内核系统调用。另增加策略重放、配置导出及应用上下文加固，为 record 自身范围建立内核关联键。

### 新增

- **多 Agent 编排溯源：`agentprov hooks bridge`、`internal/hooksbridge`。** 将 Claude Code 或兼容框架的团队 hook 转为图数据：`agents` 表使用 `PRIMARY KEY (run_id, id)`，使不同执行的 `main` 协调者独立；增加 `tool_calls.agent_id`；用 `agent_spawn` 表示委托，`agent_message` 表示同伴消息，`SendMessage` 正文存成内容寻址对象；每个行动形成与执行 Agent 绑定、经过策略评估的工具调用。子 Agent 共享 cgroup，外发系统调用通过命令匹配的 `agent_syscall` 关系归属。新增 `orchestration` 视图，渲染 Agent、A2A 消息和 `refused` 节点，运行时标签显示 `secret_path .aws/credentials`、`metadata_ip 169.254.169.254` 等目标。在 `demo/multiagent-provenance` 的签名虚拟机采集中完成端到端验证。
- **`agentprov security reevaluate --run [--rules]`。** 对已保存事件重跑当前或自定义策略，重新生成决策、风险、响应、统一信号和对应图关系。原始事件不变，重复执行结果幂等，`graph verify` 保持通过；修改策略后无需重跑 Agent 或传感器。
- **`agentprov policy rules [--out]`。** 导出内置策略为可编辑 YAML，再通过 `policy test --rules` 或 `security reevaluate --rules` 使用。
- **默认 `self_credential_access` 规则。** Agent 读取自己的 `.claude/.credentials.json` 或模型 API 环境凭据时，仍保留完整事件，但允许规则排在 kill 规则之前，不再触发高等级 `secret_path` 告警，以突出目标秘密读取。可通过导出的规则文件调整。
- **`SelfLaunched` 与 `CorrelationClass` 分开。** 事件可同时为 `kernel_correlated` 和 `self_launched`，分别说明内核独立观测和进程由本项目启动。该标记依据事件来源和匹配绑定的 `binding_source` 推导，经新增的 `events.binding_source` 字段传递，并在 Dashboard 关联类别旁展示。
- **Linux record 每范围一个真实 cgroup。** 使用 `SysProcAttr.UseCgroupFD`，将子进程及其后代放入专用 cgroup v2 叶节点；独立遥测按 `cgroup_id` 以 0.98 关联整个子树，不靠 PID 轮询。非 Linux 或缺少 cgroup v2／委派权限时，回退到原合成逻辑标识。Ubuntu 24.04、6.8 内核、arm64 实验虚拟机的端到端检查表明：子进程进入 `/agentprov/<attempt>`，保存的 cgroup 标识等于目录 inode，与 `bpf_get_current_cgroup_id` 一致；没有上下文的传感器事件通过 `cgroup_time_window` 以 0.98 关联，标为内核关联且由本项目启动。父叶节点按需创建，各范围叶节点退出时删除。
- **`agentprov sensor stream`：节点常驻采集。** 一条长期运行的命令启动 eBPF 传感器，按 cgroup 关联并将事件写入存储，替代手工 `agentprov-sensor | telemetry ingest-jsonl` 管道。排除本项目的数据目录快照和数据库 I/O，避免自反馈；当时丢弃无执行范围的主机事件，以免破坏逐执行记录的图校验。需要 `CAP_BPF` 与 `CAP_PERFMON`，可用 setcap 或 root。后续有界暂存与持久化变化见 v0.8.0。
- **record 自动保存产物对象。** 将变更文件正文存为 `workspace_file/<path>`，侧栏可直接预览 Agent 产物，替代容易遗漏的采集后手动步骤。

### 调整

- **`CorrelationClass` 按事件来源分类。** 不再根据合成的 `agentprov-record-` 容器标识把事件归为 `self_observed`。真实内核事件匹配 record 绑定后仍为 `kernel_correlated`，另附 `self_launched` 标记。
- **应用声明的置信度降低。** `bind_scope` 产生的 `ai_asserted` 绑定上限为 0.5，不再默认 1.0；模型声明的范围不应与内核验证匹配具有同等确定性。当时的匹配等级维持 cgroup 0.98、container 0.92、pid 0.85、process 1.0，Dashboard 按区间着色。

### 修复

- **图中的说明节点不再孤立。** 此前从全部过滤后关系构建可见节点，但只返回有上限的部分关系，导致 `policy_decision`、`response_action`、`risk_signal`、`file`、`artifact` 节点的边被大量运行时关系挤掉。现在优先保留较少见的语义关系，只从实际返回的边构建节点集合；当时九种视图检查均无孤立节点。
- **进程显示名称。** 通过 `comm`／`tgid` 补充 `runtime_process` 和线程组标签；进程树合并 `base64 -d ×72` 这类重复叶命令，改善大量子进程的可读性。
- **Dashboard 性能。** 按轻量指纹缓存 `graph verify`，执行概览首次加载后的耗时明显下降；按拓扑缓存 Sugiyama 布局，选择、悬停、缩放不再重排；调整边数量上限和实时刷新间隔。时间轴的 `edgeVisible` 改为同时考虑边自身时间。
- **重新采集供应链示例。** 用受监督流程生成并签名 `demo/snake-supply-chain/run-snake-supervised.forensics.json.gz`，替换旧的 cgroup 绑定前版本。`snake.py` 已保存为可预览对象，供应链行为以 0.98 关联并标注 `self_launched`，图校验通过。

## v0.4.1 - 2026-07-01

在 `v0.4.0` 基础上整理合规映射、统一 CLI 与 Dashboard 模型，并修复两处展示问题，不增加新的功能入口。

### 调整

- 合规映射改为按规则报告四种状态，不再仅看“是否存在某类证据”：`enforced` 表示记录了拒绝、隔离或终止类决策，`detected` 表示命中但没有这类决策，`not_triggered` 表示有映射规则但未命中，`no_rule` 表示没有映射检测器。
- Dashboard 与 `compliance map`、`gaps`、`explain` 共用 `compliance.MapRunRules`。展开控制项可查看每次命中的时间、决策和原因，并跳转到对应图节点。
- `security.Rule` 增加 `mode`（enforce／detect）和 `controls:`，使自定义 YAML 规则能映射到框架控制项。detect 模式只记录，参见 `examples/policies/agentic-security.yaml`。

### 修复

- 时间线详情和证据载荷不再截断到 160 字符；保留全文，默认收起，可展开。
- 图视图按标识前缀识别 `tool_call`、`session`、`attempt`、`rollout`、`process`，不再把这些端点显示为通用未知节点，概览计数也相应正确。

### 移除

- 旧的按证据类别映射的合规模型，包括 `MapRun`、`ResolveEvidence` 和 `internal/compliance/evidence.go` 加载器，由按规则映射的模型替代。

## v0.4.0 - 2026-06-30

从以 CLI 为主的证据原型，发展为可在本地回放沙箱 Agent 执行的溯源 Dashboard。相比 `v0.3.0`，主要新增证据图浏览器和沙箱内 Agent 示例：可直接导入签名供应链采集包，离线查看，无需 Linux/eBPF 虚拟机。

### 新增

- **签名示例包：`demo/snake-supply-chain/`。** 保存真实 Coding Agent 在沙箱内的执行，展示依赖安装钩子读取模拟秘密、尝试连接元数据 IP。通过 `forensics import` 导入后在 Dashboard 回放。
- **证据图视图。** 包含执行概览、安全、进程、文件／产物、网络外发、数据流／污点、Agent 意图、信任／来源和沙箱边界。
- **有界细节层次。** `summary` 展示分组摘要，`expanded` 展示选定的重要细节，`raw` 用于原始证据追查，不作为默认渲染。
- **证据追查。** 从节点和风险信号定位相关证据；局部展开上游、下游、子节点和原始记录。
- **产物预览。** Dashboard 支持有大小限制、经过脱敏的内容预览。
- **取证导入。** 支持签名可移植包，并增加导出后再导入的往返测试。
- **合规规则映射。** 增加 `examples/policies/agentic-security.yaml`、`internal/compliance` 的规则到控制项映射、Dashboard 合规 API 和面板，以及执行处置／仅检测两种规则模式。
- **展示测试。** 增加 Dashboard 预览和图视图测试。

### 调整

- Dashboard 按查询组织证据，不再默认倾倒整张标准图。
- README 围绕执行可观测、Git 式溯源、Dashboard 回放和签名证据介绍项目。
- 原始遥测仍可查询，但默认不把每个系统调用或事件都画成图节点。
- 收窄污点推导：敏感数据流结合高风险外发目标判断，不把所有网络连接都当作数据泄露。
- 从采样进程数据补充名称，使图节点更易辨认。
- 遥测格式和 eBPF 文档同步到已交付的原生传感器能力。
- 路线图与状态文档同步到当时实际实现的 Dashboard、MCP、原生传感器、回放和合规接口。

### 修复

- 修正 Dashboard 视图的图摘要聚合计数。
- 点击风险信号时定位对应图路径，而非只列原始事件。
- 修正大量进程事件分组后的展开，使其返回预期证据集合。
- 区分“聚焦证据”和“执行时间线”的界面标签。
- 修复示例的正常回放校验，并补全信号面板。

### 示例

该版本示例无需重跑 Agent 或 eBPF 传感器，导入签名包即可：

```sh
go build -o /tmp/agentprov ./cmd/agentprov

/tmp/agentprov --data-dir /tmp/snake-replay forensics import \
  demo/snake-supply-chain/run-snake-supervised.forensics.json.gz \
  --pub-key demo/snake-supply-chain/attestation.pub

/tmp/agentprov --data-dir /tmp/snake-replay dashboard serve --addr 127.0.0.1:7396
```

然后打开 `http://127.0.0.1:7396`，选择 `run-snake-supervised`。

只有在兼容虚拟机中重新采集原始 Linux/eBPF 场景时，才需要 `demo/snake-supply-chain/capture/` 下的脚本。回放已有包无需这些步骤。

### 验证

- `go test ./...`
- Dashboard JavaScript 语法检查。
- 签名取证包导入和回放流程。
- 图视图与 Dashboard 预览测试。

### 当时的已知边界

- 技术预览，不是生产级主机入侵检测系统。
- 提供本地完整性校验和签名证据导出，尚无采集时建立的主机外可信锚点，不能据此抵御恶意宿主机 root 对全部本地数据的重写。
- 中心证据服务、通知接入、长期多租户部署和生产级 eBPF 打包仍列为后续工作。
