package telemetry

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNativeSyscallResultPreservesIdentityAndZero(t *testing.T) {
	for _, result := range []float64{0, -13, -115, 9} {
		raw := map[string]any{
			"source": "agentprov_ebpf", "event_type": "syscall_result", "operation": "network_connect",
			"pid": float64(42), "tgid": float64(42), "tid": float64(43), "dst_ip": "169.254.169.254", "dst_port": 80,
			"syscall_result": result, "observation_stage": "result", "syscall_number": 203,
			"operation_id": "syscall-v1:boot:43:100:42:90:200", "thread_instance_id": "boot:43:100",
			"process_instance_id": lifecycleBoot + ":42:90", "boot_id": lifecycleBoot,
			"host_id": "0123456789abcdef0123456789abcdef", "host_identity_source": "pid1_root_machine_id",
			"realtime_coarse_resolution_ns": float64(4000000),
			"monotonic_ns":                  "1234567890123456789", "syscall_start_ns": "1234567890123456788",
		}
		event, mapped, err := mapNative(raw)
		if err != nil || !mapped || event.EventType != "syscall_result" || event.PID != 42 || event.TGID != 42 {
			t.Fatalf("result became an attempt: %+v %v", event, err)
		}
		if err := ValidateRawPayload(event.EventType, event.Payload); err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		if err := json.Unmarshal([]byte(event.Payload), &body); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"operation_id", "thread_instance_id", "syscall_result", "monotonic_ns", "syscall_start_ns", "host_id", "host_identity_source", "realtime_coarse_resolution_ns"} {
			if body[key] != raw[key] {
				t.Fatalf("lost %s: %v != %v", key, body[key], raw[key])
			}
		}
	}
}

func TestNativeExitSignalDoesNotBecomeSuccessfulExit(t *testing.T) {
	for _, kind := range []string{"process_exit", "thread_exit"} {
		event, mapped, err := mapNative(map[string]any{"event_type": kind, "exit_signal": 31,
			"raw_exit_status": 159, "termination": "signal", "core_dump_flag": true})
		if err != nil || !mapped || event.EventType != kind || strings.Contains(event.Payload, `"exit_code"`) {
			t.Fatalf("exit signal became an exit code: %+v %v", event, err)
		}
		if err := ValidateRawPayload(kind, event.Payload); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNativeProcfsAddressDoesNotReplaceKernelIdentity(t *testing.T) {
	for _, kind := range []string{"execve", "file_open", "tls_write"} {
		raw := map[string]any{"source": "agentprov_ebpf", "event_type": kind, "pid": float64(9001), "tgid": float64(9001), "tid": float64(9002),
			"process_instance_id": lifecycleBoot + ":9001:123", "procfs_pid": float64(41), "procfs_tid": float64(42), "procfs_pid_namespace": "pid:[123]"}
		event, ok, err := mapNative(raw)
		if err != nil || !ok || event.PID != 9001 || event.TGID != 9001 {
			t.Fatalf("procfs address replaced kernel identity: %+v %v", event, err)
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(event.Payload), &payload); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"process_instance_id", "tid", "procfs_pid", "procfs_tid", "procfs_pid_namespace"} {
			if payload[key] != raw[key] {
				t.Fatalf("%s lost %s", kind, key)
			}
		}
	}
}

func TestNativeMissingOutcomeIsNotZero(t *testing.T) {
	for _, raw := range []map[string]any{
		{"event_type": "process_exit"},
		{"event_type": "thread_exit", "exit_signal": 0},
		{"event_type": "syscall_result", "operation": "file_open"},
	} {
		event, _, err := mapNative(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateRawPayload(event.EventType, event.Payload); err == nil {
			t.Fatalf("missing result accepted: %s", event.Payload)
		}
	}
}

func TestNativeThreadExitDoesNotCloseProcess(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{Ingest: JSONLIngestOptions{DropUncorrelated: true}, BatchEvents: 1})
	nativeBind(t, db, "scope", "run-threads")
	lifecycleEvent(t, n, 10, 1, 100, 50, "scope", "execve", "2026-09-19T00:00:00.100Z")
	lifecycleEvent(t, n, 10, 1, 100, 50, "scope", "thread_exit", "2026-09-19T00:00:00.200Z")
	if err := n.Process(32); err != nil {
		t.Fatal(err)
	}
	// The surviving worker can move to a new cgroup after the leader exits.
	lifecycleEvent(t, n, 10, 1, 100, 50, "moved", "file_write", "2026-09-19T00:00:00.300Z")
	if err := n.Process(32); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id='run-threads' AND event_type='file_write'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("thread exit closed surviving process: count=%d err=%v", count, err)
	}
}
