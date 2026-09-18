package sensor

import (
	"time"

	"github.com/cilium/ebpf"
)

func eventTimestamp(_ sensorbpfSensorEvent) string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func goTLSWriteProgram(objs *sensorbpfObjects) *ebpf.Program {
	return objs.HandleSslWrite
}

func archTracepoints(_ *sensorbpfObjects) []sensorTracepoint { return nil }
