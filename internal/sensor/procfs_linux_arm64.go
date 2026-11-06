package sensor

import "github.com/cilium/ebpf"

// Preserve the separately validated ARM64 object and its existing host-PID path.
func configureProcfsNamespace(_ *ebpf.CollectionSpec) (*procfsResolver, error) { return nil, nil }
func bindProcfsResolver(_ *procfsResolver, _ *sensorbpfObjects)                {}
