package sensor

import (
	"github.com/byteyellow/agentprovenance/internal/i18n"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func goTLSWriteProgram(objs *sensorbpfObjects) *ebpf.Program {
	return objs.HandleSslWrite
}

// Kernel cgroup-name caching is currently available on amd64 only.
func configureCgroupResolver(_ *cgroupResolver, _ *sensorbpfObjects) {}

func archTracepoints(_ *sensorbpfObjects) []sensorTracepoint { return nil }

func attachGoTLSRead(_ *link.Executable, _ string, _ *sensorbpfObjects) ([]link.Link, error) {
	return nil, i18n.Errorf("Go TLS Read is unsupported by the preserved arm64 sensor object")
}
