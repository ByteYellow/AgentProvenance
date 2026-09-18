package telemetry

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func nativeTestStore(t *testing.T) (*sql.DB, store.Paths) {
	t.Helper()
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, paths
}

func nativeTestStream(t *testing.T, db *sql.DB, paths store.Paths, opts NativeStreamOptions) *NativeStream {
	t.Helper()
	n, err := NewNativeStream(db, paths, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

func nativeWrite(t *testing.T, n *NativeStream, cgroup, path string) {
	t.Helper()
	line := fmt.Sprintf(`{"event_type":"file_write","cgroup_id":%q,"path":%q,"time":"2026-09-19T00:00:00.250Z"}`+"\n", cgroup, path)
	if _, err := n.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
}

func nativeBind(t *testing.T, db *sql.DB, cgroup, run string) {
	t.Helper()
	_, err := correlation.RecordBinding(db, correlation.Binding{RunID: run, SessionID: "session-" + run, ToolCallID: "tool-" + run, ProcessID: "process-" + run, CgroupID: cgroup, StartedAt: "2026-09-19T00:00:00Z", EndedAt: "2026-09-19T00:00:00.500Z", BindingSource: correlation.BindingSourceK8sCgroup})
	if err != nil {
		t.Fatal(err)
	}
}

func retryNativeNow(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`UPDATE telemetry_spool_batches SET retry_at=0 WHERE format='native'`); err != nil {
		t.Fatal(err)
	}
}

func TestNativePendingRecoversClosedBindingWithoutDuplicateEvents(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{Ingest: JSONLIngestOptions{DropUncorrelated: true}, BatchEvents: 2})
	nativeBind(t, db, "known", "run-known")
	nativeWrite(t, n, "late", "/tmp/early")
	nativeWrite(t, n, "known", "/tmp/current")
	if err := n.Process(32); err != nil {
		t.Fatal(err)
	}
	status, err := ReadNativeStreamStatus(db)
	if err != nil {
		t.Fatal(err)
	}
	if status.PendingEvents != 1 || status.Counters["ingested"] != 1 {
		t.Fatalf("status=%+v", status)
	}
	var firstID string
	if err := db.QueryRow(`SELECT id FROM events WHERE run_id='run-known'`).Scan(&firstID); err != nil {
		t.Fatal(err)
	}
	var manifests int
	if err := db.QueryRow(`SELECT COUNT(*) FROM telemetry_batches WHERE run_id='run-known'`).Scan(&manifests); err != nil || manifests != 1 {
		t.Fatalf("live manifest count=%d err=%v", manifests, err)
	}
	// Simulate a crash while replay was claimed. Its committed row receipt
	// must prevent a duplicate of the already accepted sibling event.
	if _, err := db.Exec(`UPDATE telemetry_spool_batches SET status='processing' WHERE format='native' AND status='queued'`); err != nil {
		t.Fatal(err)
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	nativeBind(t, db, "late", "run-late")
	n = nativeTestStream(t, db, paths, NativeStreamOptions{Ingest: JSONLIngestOptions{DropUncorrelated: true}})
	if err := n.Process(32); err != nil {
		t.Fatal(err)
	}
	var events, receipts int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM telemetry_native_rows`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if events != 2 || receipts != 0 {
		t.Fatalf("events=%d receipts=%d", events, receipts)
	}
	var unchangedID string
	if err := db.QueryRow(`SELECT id FROM events WHERE run_id='run-known'`).Scan(&unchangedID); err != nil {
		t.Fatal(err)
	}
	if unchangedID != firstID {
		t.Fatal("replayed event identity changed")
	}
	var lateCgroup, lateMethod string
	if err := db.QueryRow(`SELECT cgroup_id,correlation_method FROM events WHERE run_id='run-late'`).Scan(&lateCgroup, &lateMethod); err != nil {
		t.Fatal(err)
	}
	if lateCgroup != "late" || !strings.Contains(lateMethod, "cgroup_time_window") {
		t.Fatalf("wrong late attribution %s %s", lateCgroup, lateMethod)
	}
	var capturedAt string
	if err := db.QueryRow(`SELECT created_at FROM events WHERE run_id='run-late'`).Scan(&capturedAt); err != nil {
		t.Fatal(err)
	}
	if capturedAt != "2026-09-19T00:00:00.250Z" {
		t.Fatalf("late event was retimestamped: %s", capturedAt)
	}
	status, err = ReadNativeStreamStatus(db)
	if err != nil {
		t.Fatal(err)
	}
	if status.QueuedBytes != 0 || status.Counters["ingested"] != 2 {
		t.Fatalf("status=%+v", status)
	}
	files, err := os.ReadDir(paths.Spool)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".jsonl") {
			t.Fatalf("processed payload retained: %s", file.Name())
		}
	}
}

func TestNativeStreamSealsAndProcessesWhileCaptureContinues(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{BatchEvents: 8, FlushInterval: 5 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- n.Run(ctx, func(err error) { t.Errorf("worker: %v", err) }) }()
	for i := 0; i < 97; i++ {
		nativeWrite(t, n, "untracked", "/tmp/identical")
	}
	if err := n.Flush(); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := n.Process(128); err != nil {
		t.Fatal(err)
	}
	var count, distinct, rawDistinct int
	if err := db.QueryRow(`SELECT COUNT(*),COUNT(DISTINCT id),COUNT(DISTINCT raw_event_id) FROM events`).Scan(&count, &distinct, &rawDistinct); err != nil {
		t.Fatal(err)
	}
	if count != 97 || distinct != 97 || rawDistinct != 97 {
		t.Fatalf("identical captures were lost or conflated: %d %d %d", count, distinct, rawDistinct)
	}
	var biggest int
	if err := db.QueryRow(`SELECT MAX(ingested_count) FROM telemetry_batches`).Scan(&biggest); err != nil {
		t.Fatal(err)
	}
	if biggest > 8 {
		t.Fatalf("unbounded batch manifest: %d", biggest)
	}
	status, err := ReadNativeStreamStatus(db)
	if err != nil {
		t.Fatal(err)
	}
	if status.QueuedBatches != 0 || status.Counters["captured"] != 97 {
		t.Fatalf("status=%+v", status)
	}
}

func TestNativeCrashBeforeSealRecoversCompleteRows(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{Ingest: JSONLIngestOptions{DropUncorrelated: true}})
	nativeWrite(t, n, "late", "/tmp/early")
	if n.file == nil {
		t.Fatal("batch was not capturing")
	}
	if _, err := n.file.Write([]byte(`{"partially-written"`)); err != nil {
		t.Fatal(err)
	}
	// Do not call Close: simulate process death after fsynced complete rows.
	n.file.Close()
	n.file = nil
	n.lock.Close()
	n.closed = true
	n = nativeTestStream(t, db, paths, NativeStreamOptions{Ingest: JSONLIngestOptions{DropUncorrelated: true}})
	nativeBind(t, db, "late", "run-recovered")
	if err := n.Process(32); err != nil {
		t.Fatal(err)
	}
	status, err := ReadNativeStreamStatus(db)
	if err != nil {
		t.Fatal(err)
	}
	if status.Counters["ingested"] != 1 || status.Counters["dropped_partial_recovery"] != 1 {
		t.Fatalf("status=%+v", status)
	}
}

func TestNativeQueueBoundAndTTLAreDurableAndDoNotBlockNewBatches(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{Ingest: JSONLIngestOptions{DropUncorrelated: true}, BatchEvents: 1, BatchBytes: 1024, MaxQueuedBytes: 1024, MaxQueuedBatches: 1})
	nativeWrite(t, n, "unknown", "/tmp/first")
	nativeWrite(t, n, "unknown", "/tmp/second")
	nativeWrite(t, n, "unknown", "/tmp/third")
	status, err := ReadNativeStreamStatus(db)
	if err != nil {
		t.Fatal(err)
	}
	if status.QueuedBatches != 1 || status.QueuedBytes > 1024 || status.Counters["dropped_queue_full"] != 2 {
		t.Fatalf("status=%+v", status)
	}
	if _, err := db.Exec(`UPDATE telemetry_spool_batches SET expires_at=? WHERE format='native'`, time.Now().Add(-time.Second).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if err := n.Process(32); err != nil {
		t.Fatal(err)
	}
	nativeBind(t, db, "known", "run-after-expiry")
	nativeWrite(t, n, "known", "/tmp/fourth")
	if err := n.Process(32); err != nil {
		t.Fatal(err)
	}
	status, err = ReadNativeStreamStatus(db)
	if err != nil {
		t.Fatal(err)
	}
	if status.Counters["expired_uncorrelated"] != 1 || status.Counters["ingested"] != 1 || status.QueuedBatches != 0 {
		t.Fatalf("status=%+v", status)
	}
}

func TestNativeTransactionFailureRetriesWithoutPartialEvidence(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{BatchEvents: 1})
	nativeBind(t, db, "known", "run-retry")
	nativeWrite(t, n, "known", "/tmp/retry")
	if _, err := db.Exec(`CREATE TRIGGER fail_manifest BEFORE INSERT ON telemetry_batches BEGIN SELECT RAISE(ABORT,'simulated disk error'); END`); err != nil {
		t.Fatal(err)
	}
	if err := n.Process(32); err == nil {
		t.Fatal("expected transaction failure")
	}
	for _, table := range []string{"events", "graph_edges", "telemetry_native_rows", "telemetry_event_windows"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("partial evidence in %s: %d", table, count)
		}
	}
	if _, err := db.Exec(`DROP TRIGGER fail_manifest`); err != nil {
		t.Fatal(err)
	}
	retryNativeNow(t, db)
	if err := n.Process(32); err != nil {
		t.Fatal(err)
	}
	status, err := ReadNativeStreamStatus(db)
	if err != nil {
		t.Fatal(err)
	}
	if status.Counters["ingested"] != 1 || status.Counters["retry_failures"] != 1 {
		t.Fatalf("status=%+v", status)
	}
}

func TestNativePrivacyBeforePersistenceAndExclusiveCollector(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{})
	if running, err := NativeStreamRunning(paths); err != nil || !running {
		t.Fatalf("collector liveness=%v err=%v", running, err)
	}
	if other, err := NewNativeStream(db, paths, NativeStreamOptions{}); err == nil {
		other.Close()
		t.Fatal("second collector accepted")
	}
	line := `{"event_type":"tls_write","data":"POST /v1/responses HTTP/1.1\r\nAuthorization: Bearer sk-live-secret-1234567890\r\n\r\nvery private full body","length":100,"time":"2026-09-19T00:00:00Z"}` + "\n"
	if _, err := n.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
	if err := n.Flush(); err != nil {
		t.Fatal(err)
	}
	var path string
	if err := db.QueryRow(`SELECT spool_path FROM telemetry_spool_batches WHERE format='native'`).Scan(&path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "very private full body") || strings.Contains(string(raw), "sk-live-secret-1234567890") {
		t.Fatalf("unredacted TLS in spool: %s", raw)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("spool mode=%v", info.Mode())
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	if running, err := NativeStreamRunning(paths); err != nil || running {
		t.Fatalf("stopped collector liveness=%v err=%v", running, err)
	}
}

func TestNativeCoverageLossSurvivesNormalizationAndKernelCounterReset(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{Ingest: JSONLIngestOptions{DropUncorrelated: true}, BatchEvents: 3})
	for _, line := range []string{
		`{"event_type":"resource_pressure","resource":"sensor_ringbuf","signal":"event_drop","dropped":7,"dropped_delta":7}`,
		`{"event_type":"resource_pressure","resource":"sensor_ringbuf","signal":"event_drop","dropped":2,"dropped_delta":2}`,
		`{"event_type":"resource_pressure","resource":"sensor_tls_reassembly","signal":"reassembly_limit","dropped_delta":3,"dropped_bytes_delta":1234}`,
	} {
		if _, err := n.Write([]byte(line + "\n")); err != nil {
			t.Fatal(err)
		}
	}
	if err := n.Process(32); err != nil {
		t.Fatal(err)
	}
	status, err := ReadNativeStreamStatus(db)
	if err != nil {
		t.Fatal(err)
	}
	if status.Counters["kernel_dropped_events"] != 9 || status.Counters["tls_reassembly_dropped_streams"] != 3 || status.Counters["tls_reassembly_dropped_bytes"] != 1234 || status.PendingEvents != 0 {
		t.Fatalf("coverage counters=%+v", status)
	}
	report, err := BuildProducerHealth(db, ProducerHealthOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Events.SensorDroppedEvents != 9 || report.Events.CorrelatedEvents != 0 || !report.Coverage.HasSensorDrops || report.Coverage.Complete {
		t.Fatalf("health=%+v", report)
	}
	event, ok, err := mapNative(map[string]any{"event_type": "tls_read", "data": "partial", "truncated": true})
	if err != nil || !ok || !strings.Contains(event.Payload, `"truncated":true`) {
		t.Fatalf("truncation lost: %+v %v", event, err)
	}
}

func TestNativeGraphFailureDoesNotAcknowledgePartialEvidence(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{BatchEvents: 1})
	nativeBind(t, db, "known", "run-graph-retry")
	nativeWrite(t, n, "known", "/tmp/retry")
	if _, err := db.Exec(`CREATE TRIGGER fail_graph BEFORE INSERT ON graph_edges BEGIN SELECT RAISE(ABORT,'graph write failed'); END`); err != nil {
		t.Fatal(err)
	}
	if err := n.Process(32); err == nil {
		t.Fatal("graph failure was acknowledged")
	}
	for _, table := range []string{"events", "graph_edges", "telemetry_native_rows", "telemetry_batches", "telemetry_event_windows"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("partial %s: %d", table, count)
		}
	}
	if _, err := db.Exec(`DROP TRIGGER fail_graph`); err != nil {
		t.Fatal(err)
	}
	retryNativeNow(t, db)
	if err := n.Process(32); err != nil {
		t.Fatal(err)
	}
	var events, edges int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM graph_edges`).Scan(&edges); err != nil {
		t.Fatal(err)
	}
	if events != 1 || edges == 0 {
		t.Fatalf("retry events=%d edges=%d", events, edges)
	}
}

func TestNativeLateTLSUsesCaptureTimeForCausalEdges(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{BatchEvents: 1})
	nativeBind(t, db, "known", "run-late-tls")
	for _, raw := range []string{
		`{"event_type":"tls_write","cgroup_id":"known","time":"2026-09-19T00:00:00Z","data":"request","length":7}`,
		`{"event_type":"tls_read","cgroup_id":"known","time":"2026-09-19T00:00:00.1Z","data":"response","length":8}`,
	} {
		if _, err := n.Write([]byte(raw + "\n")); err != nil {
			t.Fatal(err)
		}
		if err := n.Process(32); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	var capturedAt string
	if err := db.QueryRow(`SELECT COUNT(*),COALESCE(MAX(created_at),'') FROM graph_edges WHERE edge_type='llm_call'`).Scan(&count, &capturedAt); err != nil {
		t.Fatal(err)
	}
	if count != 1 || capturedAt != "2026-09-19T00:00:00.1Z" {
		t.Fatalf("late TLS call count=%d captured_at=%s", count, capturedAt)
	}
}

func TestNativeCleanupFailureRetainsCapacityAndRetriesWithoutReplay(t *testing.T) {
	db, paths := nativeTestStore(t)
	// Leave a second batch slot available so rejection must account for bytes
	// retained by failed cleanup, rather than merely hitting the batch limit.
	n := nativeTestStream(t, db, paths, NativeStreamOptions{BatchEvents: 1, BatchBytes: 1024, MaxQueuedBytes: 1024, MaxQueuedBatches: 2})
	nativeWrite(t, n, "untracked", "/tmp/first")
	removals := 0
	n.removeFile = func(path string) error {
		removals++
		if removals <= 2 {
			return errors.New("transient unlink failure")
		}
		return os.Remove(path)
	}
	if err := n.Process(1); err == nil {
		t.Fatal("expected initial cleanup error")
	}
	var firstID string
	if err := db.QueryRow(`SELECT id FROM events`).Scan(&firstID); err != nil {
		t.Fatal(err)
	}
	status, err := ReadNativeStreamStatus(db)
	if err != nil {
		t.Fatal(err)
	}
	if status.CleanupPendingBatches != 1 || status.QueuedBatches != 1 || status.QueuedBytes <= 0 || status.PendingEvents != 0 || status.LastError == "" {
		t.Fatalf("cleanup backlog invisible: %+v", status)
	}
	nativeWrite(t, n, "untracked", "/tmp/rejected")
	status, err = ReadNativeStreamStatus(db)
	if err != nil {
		t.Fatal(err)
	}
	if status.Counters["dropped_queue_full"] != 1 || status.Counters["captured"] != 1 {
		t.Fatalf("cleanup leaked headroom: %+v", status)
	}
	// A subsequent live sweep retries deletion, including repeated failure,
	// without reopening the already committed batch for ingestion.
	retryNativeNow(t, db)
	if err := n.Process(1); err == nil {
		t.Fatal("expected transient retry cleanup error")
	}
	retryNativeNow(t, db)
	if err := n.Process(1); err != nil {
		t.Fatal(err)
	}
	status, err = ReadNativeStreamStatus(db)
	if err != nil {
		t.Fatal(err)
	}
	if status.CleanupPendingBatches != 0 || status.QueuedBytes != 0 || status.LastError != "" {
		t.Fatalf("cleanup failed to release capacity: %+v", status)
	}
	nativeWrite(t, n, "untracked", "/tmp/second")
	if err := n.Process(1); err != nil {
		t.Fatal(err)
	}
	var events, firstCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE id=?`, firstID).Scan(&firstCount); err != nil {
		t.Fatal(err)
	}
	if events != 2 || firstCount != 1 {
		t.Fatalf("cleanup replayed evidence: events=%d first=%d", events, firstCount)
	}
}
