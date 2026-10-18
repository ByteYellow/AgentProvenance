//go:build linux && (amd64 || arm64)

package sensor

import (
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Use PID 1's root so a hostPID DaemonSet reports the node's machine identity,
// not its container image's /etc/machine-id. An inaccessible source stays absent.
var sensorHostID = sync.OnceValue(func() string {
	raw, err := os.ReadFile("/proc/1/root/etc/machine-id")
	if err != nil {
		return ""
	}
	return normalizedMachineID(string(raw))
})

var auditClockResolution = sync.OnceValue(func() int64 {
	var resolution unix.Timespec
	if unix.ClockGetres(unix.CLOCK_REALTIME_COARSE, &resolution) != nil {
		return 0
	}
	return resolution.Nano()
})

func normalizedMachineID(raw string) string {
	id := strings.ToLower(strings.TrimSpace(raw))
	if len(id) != 32 || id == strings.Repeat("0", 32) {
		return ""
	}
	if _, err := hex.DecodeString(id); err != nil {
		return ""
	}
	return id
}

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
	if host := sensorHostID(); host != "" {
		ev["host_id"] = host
		ev["host_identity_source"] = "pid1_root_machine_id"
	}
	if resolution := auditClockResolution(); resolution > 0 {
		ev["realtime_coarse_resolution_ns"] = resolution
	}
	if boot := sensorBootID(); boot != "" {
		ev["boot_id"] = boot
	}
	if e.KtimeNs != 0 {
		ev["monotonic_ns"] = strconv.FormatUint(e.KtimeNs, 10)
	}
	if e.ProcessStartNs != 0 {
		ev["process_start_ns"] = strconv.FormatUint(e.ProcessStartNs, 10)
	}
	if id := processInstance(e.Tid, e.ThreadStartNs); id != "" {
		ev["thread_instance_id"] = id
		ev["thread_start_ns"] = strconv.FormatUint(e.ThreadStartNs, 10)
	}
	if id := processInstance(e.Pid, e.ProcessStartNs); id != "" {
		ev["process_instance_id"] = id
	}
	if id := processInstance(e.Ppid, e.ParentStartNs); id != "" {
		ev["parent_process_instance_id"] = id
	}
}

func addSyscallIdentity(ev map[string]any, e sensorbpfSensorEvent) {
	if e.SyscallStartNs == 0 {
		return
	}
	ev["syscall_number"] = e.SyscallNr
	ev["sensor_arch"] = runtime.GOARCH
	ev["syscall_start_ns"] = strconv.FormatUint(e.SyscallStartNs, 10)
	switch e.SyscallKind {
	case eventOpen:
		ev["operation"] = "file_open"
	case eventConnect:
		ev["operation"] = "network_connect"
	}
	// Include the boot and both lifetimes. TID or entry time alone is not an
	// operation identity across reused threads, processes or host boots.
	if thread := processInstance(e.Tid, e.ThreadStartNs); thread != "" && e.ProcessStartNs != 0 {
		ev["operation_id"] = fmt.Sprintf("syscall-v1:%s:%d:%d:%d", thread, e.Pid, e.ProcessStartNs, e.SyscallStartNs)
	}
}

func addSyscallResult(ev map[string]any, e sensorbpfSensorEvent) {
	ev["observation_stage"] = "result"
	ev["syscall_result"] = e.SyscallResult
	if e.KtimeNs >= e.SyscallStartNs {
		ev["syscall_duration_ns"] = strconv.FormatUint(e.KtimeNs-e.SyscallStartNs, 10)
	}
	switch {
	case e.SyscallResult == -512 || e.SyscallResult == -513 || e.SyscallResult == -514 || e.SyscallResult == -516:
		ev["syscall_outcome"] = "kernel_restart"
	case e.SyscallKind == eventConnect && (e.SyscallResult == -115 || e.SyscallResult == -114):
		ev["syscall_outcome"] = "pending"
		ev["errno"] = -e.SyscallResult
	case e.SyscallResult < 0:
		ev["syscall_outcome"] = "failure"
		ev["errno"] = -e.SyscallResult
	default:
		ev["syscall_outcome"] = "success"
	}
}

func addExitResult(ev map[string]any, e sensorbpfSensorEvent) {
	ev["event_type"], ev["exit_scope"] = "process_exit", "thread_group"
	if e.Kind == eventThreadExit {
		ev["event_type"], ev["exit_scope"] = "thread_exit", "thread"
	}
	if e.ThreadStartNs == 0 {
		ev["exit_code"] = e.ExitCode
		return
	}
	ev["raw_exit_status"] = e.RawExitStatus
	if signal := e.RawExitStatus & 0x7f; signal != 0 {
		ev["exit_signal"] = signal
		ev["termination"] = "signal"
		ev["core_dump_flag"] = e.RawExitStatus&0x80 != 0
	} else {
		ev["exit_code"] = (e.RawExitStatus >> 8) & 0xff
		ev["termination"] = "exit"
	}
}
