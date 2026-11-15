package sensor

import (
	"github.com/cilium/ebpf"
)

func goTLSWriteProgram(objs *sensorbpfObjects) *ebpf.Program {
	return objs.HandleGoTlsWrite
}

func archTracepoints(objs *sensorbpfObjects) []sensorTracepoint {
	return []sensorTracepoint{
		{"syscalls", "sys_enter_open", objs.HandleOpen},
		{"syscalls", "sys_exit_open", objs.HandleOpenReturn},
		{"syscalls", "sys_enter_unlink", objs.HandleUnlinkPlain},
	}
}
