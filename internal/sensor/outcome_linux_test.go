//go:build linux && (amd64 || arm64)

package sensor

import "testing"

func TestSyscallIdentityUsesThreadAndLifetime(t *testing.T) {
	e := sensorbpfSensorEvent{Kind: eventConnect, Pid: 41, Tid: 42, ProcessStartNs: 90,
		ThreadStartNs: 100, SyscallStartNs: 200, SyscallKind: eventConnect}
	a := normalize(e, newCgroupResolver())
	if a["tgid"] != uint32(41) || a["tid"] != uint32(42) || a["operation_id"] == nil {
		t.Fatalf("thread/group identity lost: %+v", a)
	}
	for _, mutate := range []func(*sensorbpfSensorEvent){
		func(v *sensorbpfSensorEvent) { v.Tid++ },
		func(v *sensorbpfSensorEvent) { v.ThreadStartNs++ },
		func(v *sensorbpfSensorEvent) { v.ProcessStartNs++ },
		func(v *sensorbpfSensorEvent) { v.SyscallStartNs++ },
	} {
		b := e
		mutate(&b)
		if normalize(b, newCgroupResolver())["operation_id"] == a["operation_id"] {
			t.Fatal("reused or concurrent invocation shares operation id")
		}
	}
	e.Kind, e.KtimeNs = eventSyscallResult, 250
	b := normalize(e, newCgroupResolver())
	if b["operation_id"] != a["operation_id"] || b["syscall_duration_ns"] != "50" || b["observation_stage"] != "result" {
		t.Fatalf("return no longer refers to same attempt: %+v", b)
	}
}

func TestSyscallOutcomeSemantics(t *testing.T) {
	for _, tc := range []struct {
		result int64
		want   string
	}{{0, "success"}, {-13, "failure"}, {-115, "pending"}, {-114, "pending"}, {-512, "kernel_restart"}} {
		row := normalize(sensorbpfSensorEvent{Kind: eventSyscallResult, SyscallKind: eventConnect, SyscallResult: tc.result}, newCgroupResolver())
		if row["syscall_result"] != tc.result || row["syscall_outcome"] != tc.want || row["event_type"] != "syscall_result" {
			t.Fatalf("result %d: %+v", tc.result, row)
		}
		if row["mechanism"] != nil {
			t.Fatal("return code inferred enforcement mechanism")
		}
	}
}

func TestExitSignalPreservesRawStatus(t *testing.T) {
	for _, tc := range []struct {
		kind, status uint32
		key          string
		value        uint32
	}{
		{eventExit, 7 << 8, "exit_code", 7},
		{eventExit, 31 | 0x80, "exit_signal", 31},
		{eventThreadExit, 31, "exit_signal", 31},
	} {
		row := normalize(sensorbpfSensorEvent{Kind: tc.kind, ThreadStartNs: 1, RawExitStatus: tc.status}, newCgroupResolver())
		if row[tc.key] != tc.value || row["raw_exit_status"] != tc.status {
			t.Fatalf("lost exit outcome: %+v", row)
		}
		if tc.key == "exit_signal" && row["exit_code"] != nil {
			t.Fatalf("signal became a successful exit: %+v", row)
		}
	}
}

func TestOpenEntryPathIsRetainedOnReturn(t *testing.T) {
	e := sensorbpfSensorEvent{Kind: eventSyscallResult, SyscallKind: eventOpen, ExitCode: 1, SyscallResult: -13}
	copy(e.Path[:], "/home/test/.aws/credentials")
	row := normalize(e, newCgroupResolver())
	if row["path"] != "/home/test/.aws/credentials" || row["mode"] != "read" || row["syscall_result"] != int64(-13) {
		t.Fatalf("lost open return: %+v", row)
	}
	e.Path = [256]uint8{}
	copy(e.Path[:], "/home/test/ordinary.txt")
	if normalize(e, newCgroupResolver()) != nil {
		t.Fatal("return bypassed the existing sensitive-read filter")
	}
}
