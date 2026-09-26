package sensor

import (
	"time"

	"github.com/byteyellow/agentprovenance/internal/i18n"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func eventTimestamp(_ sensorbpfSensorEvent) string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func goTLSWriteProgram(objs *sensorbpfObjects) *ebpf.Program {
	return objs.HandleSslWrite
}

// Keep the already validated arm64 object and its map layout unchanged.
func configureCgroupResolver(_ *cgroupResolver, _ *sensorbpfObjects) {}

func archTracepoints(_ *sensorbpfObjects) []sensorTracepoint { return nil }

func attachGoTLSRead(_ *link.Executable, _ string, _ *sensorbpfObjects) ([]link.Link, error) {
	return nil, i18n.Errorf("Go TLS Read is unsupported by the preserved arm64 sensor object")
}
