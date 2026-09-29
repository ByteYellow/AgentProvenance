package sensor

import (
	"github.com/cilium/ebpf"
)

func goTLSWriteProgram(objs *sensorbpfObjects) *ebpf.Program {
	return objs.HandleGoTlsWrite
}

func configureCgroupResolver(resolver *cgroupResolver, objs *sensorbpfObjects) {
	resolver.kernelName = func(id uint64) string {
		var names [3 * 96]byte
		if objs.CgroupNames == nil || objs.CgroupNames.Lookup(id, &names) != nil {
			return ""
		}
		return string(names[:])
	}
}

func archTracepoints(objs *sensorbpfObjects) []sensorTracepoint {
	return []sensorTracepoint{
		{"syscalls", "sys_enter_open", objs.HandleOpen},
		{"syscalls", "sys_exit_open", objs.HandleOpenReturn},
		{"syscalls", "sys_enter_unlink", objs.HandleUnlinkPlain},
	}
}
