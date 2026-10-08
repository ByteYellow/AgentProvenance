package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

const lifecycleBoot = "01234567-89ab-cdef-0123-456789abcdef"

func TestNativeOpenRetryRetainsSyscallOutcome(t *testing.T) {
	e, _, err := mapNative(map[string]any{"event_type": "file_open", "path": "/dev/tty", "mode": "write",
		"path_observation": "syscall_exit_retry", "syscall_result": float64(-6)})
	if err != nil || !strings.Contains(e.Payload, `"syscall_result":-6`) || !strings.Contains(e.Payload, `"path_observation":"syscall_exit_retry"`) {
		t.Fatalf("lost retry evidence: %s %v", e.Payload, err)
	}
}

func lifecycleEvent(t *testing.T, n *NativeStream, pid, parent int, birth, parentBirth int, cgroup, kind, at string) {
	t.Helper()
	event := map[string]any{"event_type": kind, "pid": pid, "ppid": parent, "cgroup_id": cgroup,
		"process_instance_id":        fmt.Sprintf("%s:%d:%d", lifecycleBoot, pid, birth),
		"parent_process_instance_id": fmt.Sprintf("%s:%d:%d", lifecycleBoot, parent, parentBirth),
		"timestamp":                  at, "command": "python3 report.py --daily", "path": "report.py", "exit_code": 0,
		"observation": "kernel_fork"}
	raw, _ := json.Marshal(event)
	if _, err := n.Write(append(raw, '\n')); err != nil {
		t.Fatal(err)
	}
}

func TestNativeLifecycleCrossCgroupAndLateDrain(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{Ingest: JSONLIngestOptions{DropUncorrelated: true}, BatchEvents: 1})
	nativeBind(t, db, "scope", "run-lifetime")
	// Deliberately reverse parent/child order and spread them across batches.
	lifecycleEvent(t, n, 12, 11, 300, 200, "migrated", "file_write", "2026-09-19T00:00:00.400Z")
	lifecycleEvent(t, n, 11, 10, 200, 100, "scope", "process_observed", "2026-09-19T00:00:00.100Z")
	lifecycleEvent(t, n, 12, 11, 300, 200, "migrated", "execve", "2026-09-19T00:00:00.200Z")
	if err := n.Process(32); err != nil {
		t.Fatal(err)
	}
	// This unrelated PID must not inherit another process's entire cgroup.
	lifecycleEvent(t, n, 14, 1, 500, 50, "migrated", "execve", "2026-09-19T00:00:00.300Z")
	if _, err := db.Exec(`UPDATE telemetry_spool_batches SET retry_at=? WHERE status='queued'`, time.Now().Add(time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := n.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id='run-lifetime'`).Scan(&count); err != nil || count != 3 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	var method, group string
	if err := db.QueryRow(`SELECT correlation_method,cgroup_id FROM events WHERE pid=12 AND event_type='file_write'`).Scan(&method, &group); err != nil || !strings.HasPrefix(method, "kernel_process_instance:") || group != "migrated" {
		t.Fatalf("method=%s group=%s err=%v", method, group, err)
	}
	status, err := ReadNativeStreamStatus(db)
	if err != nil || status.PendingEvents != 1 {
		t.Fatalf("unrelated pending: %+v %v", status, err)
	}
	if err := n.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&count); err != nil || count != 3 {
		t.Fatalf("duplicate events: %d %v", count, err)
	}
}

func TestNativeLifetimeRejectsPIDReuseAndParentSpoof(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{Ingest: JSONLIngestOptions{DropUncorrelated: true}, BatchEvents: 1})
	nativeBind(t, db, "scope", "run-lifetime")
	lifecycleEvent(t, n, 10, 1, 100, 50, "scope", "execve", "2026-09-19T00:00:00.100Z")
	lifecycleEvent(t, n, 10, 1, 100, 50, "scope", "process_exit", "2026-09-19T00:00:00.200Z")
	if err := n.Process(32); err != nil {
		t.Fatal(err)
	}
	// Reuse is outside the tracked cgroup. Same PID is insufficient, and the
	// parent lifetime must be the exact captured parent, not just its PID.
	lifecycleEvent(t, n, 10, 1, 500, 50, "other", "execve", "2026-09-19T00:00:00.300Z")
	lifecycleEvent(t, n, 11, 10, 600, 500, "other", "execve", "2026-09-19T00:00:00.400Z")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := n.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	status, err := ReadNativeStreamStatus(db)
	if err != nil || status.Counters["ingested"] != 2 || status.PendingEvents != 2 {
		t.Fatalf("reuse incorrectly joined: %+v %v", status, err)
	}
}

func TestNativeDrainHonorsCancellation(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{BatchEvents: 1})
	nativeWrite(t, n, "scope", "/tmp/unchanged")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := n.Drain(ctx); err == nil {
		t.Fatal("ignored cancellation")
	}
}

func TestNativeRejectedSamplesAreBoundedAndExcludePayload(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{})
	for i := 0; i < NativeRejectionLimit+5; i++ {
		_, err := n.Write([]byte(`{"event_type":"file_write","pid":17,"cgroup_id":"scope","timestamp":"2026-09-19T00:00:00Z","path":"","secret":"NEVER-PERSIST-THIS"}` + "\n"))
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := n.Flush(); err != nil {
		t.Fatal(err)
	}
	examples, err := ReadNativeRejections(paths.Logs)
	if err != nil || len(examples) != NativeRejectionLimit {
		t.Fatalf("examples=%d %v", len(examples), err)
	}
	raw, _ := json.Marshal(examples)
	if strings.Contains(string(raw), "NEVER-PERSIST-THIS") {
		t.Fatal("rejected body leaked")
	}
	if examples[0].PID != 17 || examples[0].CgroupID != "scope" || examples[0].Reason == "" {
		t.Fatalf("missing diagnostic identity: %+v", examples[0])
	}
	status, err := ReadNativeStreamStatus(db)
	if err != nil || status.Counters["invalid"] != NativeRejectionLimit+5 {
		t.Fatalf("counter was truncated with examples: %+v %v", status, err)
	}
}

func TestNativeRejectionFieldsAreBounded(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{})
	large := strings.Repeat("\x00<", 2000)
	payload, _ := json.Marshal(map[string]string{"process_instance_id": large})
	for i := 0; i < NativeRejectionLimit; i++ {
		if err := n.reject(IngestEvent{Timestamp: large, EventType: large, CgroupID: large, Payload: string(payload)}, large); err != nil {
			t.Fatal(err)
		}
	}
	items, err := ReadNativeRejections(paths.Logs)
	if err != nil || len(items) != NativeRejectionLimit {
		t.Fatalf("bounded diagnostics unreadable: %d %v", len(items), err)
	}
	if len(items[0].Reason) > 256 || len(items[0].ProcessInstanceID) > 80 {
		t.Fatal("unbounded diagnostic fields")
	}
}
