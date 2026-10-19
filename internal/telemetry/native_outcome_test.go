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
