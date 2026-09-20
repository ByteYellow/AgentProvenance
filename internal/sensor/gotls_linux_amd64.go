package sensor

import (
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Convert the kernel's monotonic capture time to wall time. Using drain time
// loses short-lived scopes when a busy K3s node queues records until after
// their binding has closed. The amd64 wire layout carries this extra field;
// the existing arm64 object and layout remain unchanged.
func eventTimestamp(e sensorbpfSensorEvent) string {
	now := time.Now()
	var monotonic unix.Timespec
	if e.KtimeNs != 0 && unix.ClockGettime(unix.CLOCK_MONOTONIC, &monotonic) == nil {
		now = now.Add(time.Duration(int64(e.KtimeNs) - monotonic.Nano()))
	}
	return now.UTC().Format(time.RFC3339Nano)
}

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
		{"syscalls", "sys_enter_unlink", objs.HandleUnlinkPlain},
	}
}
