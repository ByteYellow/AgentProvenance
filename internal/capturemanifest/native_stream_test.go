package capturemanifest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/observability"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/sensor"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func passiveStream(t *testing.T, db *sql.DB, paths store.Paths) *telemetry.NativeStream {
	t.Helper()
	n, err := telemetry.NewNativeStream(db, paths, telemetry.NativeStreamOptions{
		Ingest: telemetry.JSONLIngestOptions{DropUncorrelated: true}, OnCapture: observability.NativeCaptureObserver(db, paths)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

func passiveCapability(t *testing.T, n *telemetry.NativeStream, revision uint64) {
	t.Helper()
	at := time.Now().UTC()
	state := "attached"
	if revision == 2 {
		state = "failed"
	}
	report := caps(at, state)
	report.CollectorID, report.Revision = "original-node-collector", revision
	report.ChangedAt = report.UpdatedAt
	report.Producer = &sensor.CapabilityProducer{Name: "agentprov-sensor", Version: "captured-version", Commit: "captured-commit",
		OS: "linux", Architecture: "arm64", Kernel: "captured-kernel", BootID: "captured-boot", Placement: "host_kernel", PlacementBasis: "operator_configuration"}
	if err := n.ObserveCapabilities(report); err != nil {
		t.Fatal(err)
	}
}

func passiveBind(t *testing.T, db *sql.DB, run string) {
	t.Helper()
	_, err := correlation.RecordBinding(db, correlation.Binding{RunID: run, SessionID: "pod-" + run, CgroupID: run,
		StartedAt: "2026-01-01T00:00:00Z", BindingSource: correlation.BindingSourceK8sCgroup})
	if err != nil {
		t.Fatal(err)
	}
}

func passiveWrite(t *testing.T, n *telemetry.NativeStream, run string) {
	t.Helper()
	_, err := fmt.Fprintf(n, "{\"event_type\":\"file_write\",\"cgroup_id\":%q,\"path\":\"/captured/output.csv\",\"timestamp\":%q}\n", run, timestamp(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
}

func TestPassiveNativeCapabilitiesSurviveLateBindingsAndRestart(t *testing.T) {
	db, paths := testStore(t)
	n := passiveStream(t, db, paths)
	passiveCapability(t, n, 1)
	passiveWrite(t, n, "pod-a")
	passiveCapability(t, n, 2)
	passiveCapability(t, n, 3)
	passiveWrite(t, n, "pod-b")
	if err := n.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := n.Process(32); err != nil {
		t.Fatal(err)
	}
	if got := all(t, db, "pod-a", 1); len(got) != 0 {
		t.Fatalf("unbound run gained evidence: %+v", got)
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	passiveBind(t, db, "pod-a")
	passiveBind(t, db, "pod-b")
	n = passiveStream(t, db, paths)
	if _, err := db.Exec("UPDATE telemetry_spool_batches SET retry_at=0"); err != nil {
		t.Fatal(err)
	}
	if err := n.Process(32); err != nil {
		t.Fatal(err)
	}
	for _, run := range []string{"pod-a", "pod-b"} {
		got := all(t, db, run, 1)
		if len(got) != 4 || got[0].EvidenceKind != "batch" || got[0].Source != "telemetry_jsonl" {
			t.Fatalf("want one processing receipt and all three original revisions, got %+v", got)
		}
		for _, r := range got[1:] {
			if r.Placement != "host_kernel" || r.ProducerVersion != "captured-version" || r.Identity["collector_id"] != "original-node-collector" || r.IntervalBasis != "collector_receive_window" || r.Identity["batch_id"] == "" || r.Identity["receiver_id"] == r.Identity["collector_id"] {
				t.Fatalf("collector window identity changed: %+v", r)
			}
		}
		if !reflect.DeepEqual(got, all(t, db, run, 50)) {
			t.Fatal("paging changed observations")
		}
		if checked, err := provenance.Verify(db, run); err != nil || checked.ErrorCount != 0 {
			t.Fatalf("verify: %+v %v", checked, err)
		}
	}
	before := all(t, db, "pod-a", 3)
	if err := n.Process(32); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, all(t, db, "pod-a", 1)) {
		t.Fatal("retry duplicated windows")
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key}).ExportBundle("pod-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, pub); err != nil {
		t.Fatal(err)
	}
	dst, dest := testStore(t)
	if _, err := (forensics.Service{DB: dst, Paths: dest}).ImportBundle(bundle.Path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(paths.Logs, paths.Logs+"-held"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(paths.Provenance, paths.Provenance+"-held"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, all(t, dst, "pod-a", 1)) {
		t.Fatal("signed import lost captured producer history")
	}
}

func TestPassiveNativeCapabilityFailureRollsBackEventsAndReceipts(t *testing.T) {
	db, paths := testStore(t)
	n := passiveStream(t, db, paths)
	passiveBind(t, db, "pod-a")
	passiveCapability(t, n, 1)
	passiveWrite(t, n, "pod-a")
	if err := n.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TRIGGER reject_capability BEFORE INSERT ON provenance_objects WHEN NEW.object_type='sensor_capability_interval' BEGIN SELECT RAISE(ABORT,'fixture capability failure'); END"); err != nil {
		t.Fatal(err)
	}
	if err := n.Process(32); err == nil || !strings.Contains(err.Error(), "fixture capability failure") {
		t.Fatalf("missing write failure: %v", err)
	}
	for _, table := range []string{"events", "telemetry_native_rows", "telemetry_batches", "provenance_objects"} {
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s count=%d err=%v", table, count, err)
		}
	}
	if _, err := db.Exec("DROP TRIGGER reject_capability; UPDATE telemetry_spool_batches SET retry_at=0"); err != nil {
		t.Fatal(err)
	}
	if err := n.Process(32); err != nil {
		t.Fatal(err)
	}
	if got := all(t, db, "pod-a", 1); len(got) != 2 || got[0].EvidenceKind != "batch" || got[1].IntervalBasis != "collector_receive_window" {
		t.Fatalf("retry did not preserve original capture: %+v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (Service{DB: db}).List(ctx, Options{RunID: "pod-a"}); err == nil {
		t.Fatal("cancel ignored")
	}
}

func TestPassiveNativeMissingHistoryRetainsPendingEvidence(t *testing.T) {
	db, paths := testStore(t)
	n := passiveStream(t, db, paths)
	passiveBind(t, db, "pod-a")
	passiveCapability(t, n, 1)
	passiveWrite(t, n, "pod-a")
	// A missing intermediate revision is not replaced by either endpoint.
	passiveCapability(t, n, 3)
	if err := n.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := n.Process(32); err == nil {
		t.Fatal("missing history silently accepted")
	}
	var events, receipts int
	if err := db.QueryRow("SELECT COUNT(*) FROM events").Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM telemetry_native_rows").Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if events != 0 || receipts != 0 || len(all(t, db, "pod-a", 1)) != 0 {
		t.Fatal("partial capability history committed")
	}
	status, err := telemetry.ReadNativeStreamStatus(db)
	if err != nil || status.QueuedBatches != 1 {
		t.Fatalf("pending evidence disappeared: %+v %v", status, err)
	}
}

func TestPassiveNativeDelayedCapabilityAfterBatchSeal(t *testing.T) {
	db, paths := testStore(t)
	n := passiveStream(t, db, paths)
	passiveBind(t, db, "pod-a")
	first := caps(time.Now().Add(-2*time.Second), "attached")
	first.CollectorID, first.Revision, first.ChangedAt = "delayed-collector", 1, first.UpdatedAt
	last := caps(time.Now().Add(-time.Second), "failed")
	last.CollectorID, last.Revision, last.ChangedAt = first.CollectorID, 2, last.UpdatedAt
	if err := n.ObserveCapabilities(first); err != nil {
		t.Fatal(err)
	}
	passiveWrite(t, n, "pod-a")
	if err := n.Flush(); err != nil {
		t.Fatal(err)
	}
	// The report was created before sealing but its callback arrived afterward.
	if err := n.ObserveCapabilities(last); err != nil {
		t.Fatal(err)
	}
	passiveWrite(t, n, "pod-a")
	if err := n.Flush(); err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := db.QueryRow(`SELECT native_options FROM telemetry_spool_batches ORDER BY created_at DESC LIMIT 1`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var opts telemetry.NativeStreamOptions
	if err := json.Unmarshal([]byte(raw), &opts); err != nil || opts.CaptureWindow == nil {
		t.Fatalf("saved receive window: %v", err)
	}
	window := opts.CaptureWindow
	changed, _ := time.Parse(time.RFC3339Nano, last.ChangedAt)
	if !changed.Before(window.StartedAt) {
		t.Fatal("fixture did not delay the callback past the batch boundary")
	}
	if err := n.Process(32); err != nil {
		t.Fatal(err)
	}
	status, err := telemetry.ReadNativeStreamStatus(db)
	if err != nil || status.PendingEvents != 0 || status.QueuedBatches != 0 {
		t.Fatalf("delayed report blocked ingestion: %+v %v", status, err)
	}
	var events int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id='pod-a'`).Scan(&events); err != nil || events != 2 {
		t.Fatalf("events: %d %v", events, err)
	}
	got := all(t, db, "pod-a", 1)
	seen := map[string]Record{}
	for _, record := range got {
		if record.Identity["batch_id"] == window.BatchID && record.IntervalBasis == "collector_receive_window" {
			seen[record.Identity["capability_revision"]] = record
		}
	}
	if len(seen) != 2 || seen["1"].ObservedAt != first.ChangedAt || seen["2"].ObservedAt != last.ChangedAt ||
		seen["1"].StartedAt != timestamp(window.StartedAt) || seen["1"].EndedAt != timestamp(window.StartedAt) ||
		seen["2"].StartedAt != timestamp(window.StartedAt) || seen["2"].EndedAt != timestamp(window.EndedAt) {
		t.Fatalf("original reports or clipped intervals changed: %+v", seen)
	}
	if err := n.Process(32); err != nil || !reflect.DeepEqual(got, all(t, db, "pod-a", 1)) {
		t.Fatalf("retry changed observations: %v", err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key}).ExportBundle("pod-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, pub); err != nil {
		t.Fatal(err)
	}
	dst, dest := testStore(t)
	if _, err := (forensics.Service{DB: dst, Paths: dest}).ImportBundle(bundle.Path); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, all(t, dst, "pod-a", 1)) {
		t.Fatal("signed import changed delayed capability evidence")
	}
}

func TestPassiveNativeUnsealedWindowReportsUnknownEnd(t *testing.T) {
	db, paths := testStore(t)
	at := time.Now().Add(-time.Minute).UTC()
	report := caps(at, "attached")
	report.CollectorID, report.Revision, report.ChangedAt = "crashed-collector", 1, report.UpdatedAt
	if err := sensor.SaveCapabilityChange(paths.Logs, report); err != nil {
		t.Fatal(err)
	}
	err := store.WithWriteTx(context.Background(), db, func(tx *sql.Tx) error {
		return observability.NativeCaptureObserver(db, paths)(context.Background(), tx, "crashed-run", telemetry.NativeCaptureWindow{
			SchemaVersion: telemetry.NativeCaptureWindowSchema, BatchID: "crashed-batch", StreamID: "crashed-receiver",
			StartedAt: at, First: report, Last: report})
	})
	if err != nil {
		t.Fatal(err)
	}
	got := all(t, db, "crashed-run", 1)
	if len(got) != 1 || !reflect.DeepEqual(got[0].Issues, []string{"collector_receive_window_unsealed"}) ||
		got[0].StartedAt != got[0].EndedAt {
		t.Fatalf("crash gained a confirmed receive interval: %+v", got)
	}
}

func TestPassiveNativeOneWindowPerRunAcrossTransactionChunks(t *testing.T) {
	db, paths := testStore(t)
	n := passiveStream(t, db, paths)
	passiveCapability(t, n, 1)
	passiveBind(t, db, "pod-a")
	for i := 0; i < 40; i++ {
		passiveWrite(t, n, "pod-a")
	}
	if err := n.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := n.Process(32); err != nil {
		t.Fatal(err)
	}
	// The time budget can seal a transaction before its row limit, especially
	// under race instrumentation. Check every saved receipt and one window.
	var receipts, largest, covered int
	if err := db.QueryRow(`SELECT COUNT(*),MAX(ingested_count),SUM(ingested_count)
		FROM telemetry_batches WHERE run_id='pod-a'`).Scan(&receipts, &largest, &covered); err != nil {
		t.Fatal(err)
	}
	if receipts < 3 || largest > 16 || covered != 40 {
		t.Fatalf("invalid transaction coverage: receipts=%d largest=%d covered=%d", receipts, largest, covered)
	}
	got := all(t, db, "pod-a", 1)
	if len(got) != receipts+1 || got[len(got)-1].IntervalBasis != "collector_receive_window" {
		t.Fatalf("capture window count differs from one: observations=%d receipts=%d", len(got), receipts)
	}
	for _, record := range got[:receipts] {
		var saved int
		if err := db.QueryRow(`SELECT COUNT(*) FROM telemetry_batches WHERE run_id='pod-a' AND id=?`, record.Identity["batch_id"]).Scan(&saved); err != nil {
			t.Fatal(err)
		}
		if record.EvidenceKind != "batch" || saved != 1 {
			t.Fatalf("missing transaction receipt: %s", record.ID)
		}
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM events WHERE run_id='pod-a'").Scan(&count); err != nil || count != 40 {
		t.Fatalf("lost events: %d %v", count, err)
	}
}
