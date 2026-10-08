//go:build linux && (amd64 || arm64)

package sensor

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

var sensorBootID = sync.OnceValue(func() string {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
})

func eventTimestamp(e sensorbpfSensorEvent) string {
	now := time.Now()
	var monotonic unix.Timespec
	if e.KtimeNs != 0 && unix.ClockGettime(unix.CLOCK_MONOTONIC, &monotonic) == nil {
		now = now.Add(time.Duration(int64(e.KtimeNs) - monotonic.Nano()))
	}
	return now.UTC().Format(time.RFC3339Nano)
}

func processInstance(pid uint32, start uint64) string {
	if pid == 0 || start == 0 || sensorBootID() == "" {
		return ""
	}
	return fmt.Sprintf("%s:%d:%d", sensorBootID(), pid, start)
}

func addProcessIdentity(ev map[string]any, e sensorbpfSensorEvent) {
	if id := processInstance(e.Pid, e.ProcessStartNs); id != "" {
		ev["process_instance_id"] = id
	}
	if id := processInstance(e.Ppid, e.ParentStartNs); id != "" {
		ev["parent_process_instance_id"] = id
	}
}
