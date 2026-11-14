# Pinned SecCheck Wire Schema

These four Protocol Buffer schemas come from gVisor
[`a0e6be6fb5e03d8ebea13592f36a097c7e9a41b9`](https://github.com/google/gvisor/tree/a0e6be6fb5e03d8ebea13592f36a097c7e9a41b9/pkg/sentry/seccheck/points),
the source commit for `release-20261109.0`.
The upstream Apache-2.0 notices are retained. Local changes only add
`go_package` and shorten the `common.proto` import path. No field numbers or
message definitions are changed.

Generated files use protoc 25.1 and protoc-gen-go v1.35.1. From the repository
root, with these tools installed:

```sh
protoc -I internal/seccheck/wire \
  --go_out=internal/seccheck/wire --go_opt=paths=source_relative \
  common.proto container.proto sentry.proto syscall.proto
```

Vendoring just the wire contract avoids depending on the gVisor kernel,
runtime implementation or its Go toolchain. The receiver decodes only its
declared event subset. Other message types produce an explicit diagnostic;
new fields in known types follow Protobuf compatibility rules.
