# 固定版本的 SecCheck 协议

这四个 Protocol Buffer 文件取自 gVisor
[`a0e6be6fb5e03d8ebea13592f36a097c7e9a41b9`](https://github.com/google/gvisor/tree/a0e6be6fb5e03d8ebea13592f36a097c7e9a41b9/pkg/sentry/seccheck/points)，
对应 `release-20261109.0`。保留上游 Apache-2.0 声明。本地仅添加
`go_package`，并缩短 `common.proto` 的导入路径；消息定义和字段编号保持原样。

生成工具为 protoc 25.1 和 protoc-gen-go v1.35.1。安装工具后，在仓库根目录执行：

```sh
protoc -I internal/seccheck/wire \
  --go_out=internal/seccheck/wire --go_opt=paths=source_relative \
  common.proto container.proto sentry.proto syscall.proto
```

只保留协议定义，可避免引入 gVisor 内核、运行时及其 Go 工具链依赖。
接收器仅解析已声明的事件子集，其余消息类型生成明确诊断；已知消息中的新字段
遵循 Protobuf 的兼容规则。
