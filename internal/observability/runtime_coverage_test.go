package observability

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/sensor"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func coverageDB(t *testing.T) (*sql.DB, store.Paths) {
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

func capturePair() (CaptureSnapshot, CaptureSnapshot) {
	now := time.Now().UTC()
	before := CaptureSnapshot{ObservedAt: now,
		Native:       &telemetry.NativeStreamStatus{Counters: map[string]int64{"kernel_dropped_events": 100}},
		Capabilities: &sensor.CapabilityReport{Ready: true, Status: "ready"}}
	after := CaptureSnapshot{ObservedAt: now.Add(time.Second),
		Native:       &telemetry.NativeStreamStatus{Counters: map[string]int64{"kernel_dropped_events": 100}},
		Capabilities: &sensor.CapabilityReport{Status: "stopped"}}
	return before, after
}

func TestRuntimeCaptureKeepsNodeLossSeparateFromRun(t *testing.T) {
	before, after := capturePair()
	r := BuildRuntimeCapture("run", "observed", before, after, true)
	if r.Status != "ok" || r.RunDroppedEvents != nil || r.NodeCounterDelta["kernel_dropped_events"] != 0 || r.RunImpact != "no_node_loss_reported" {
		t.Fatalf("historical node losses charged to run: %+v", r)
	}
	after.Native.Counters["kernel_dropped_events"] = 107
	r = BuildRuntimeCapture("run", "observed", before, after, true)
	if r.Status != "partial" || r.RunImpact != "unknown" || r.RunDroppedEvents != nil || r.NodeCounterDelta["kernel_dropped_events"] != 7 {
		t.Fatalf("node losses falsely attributed to run: %+v", r)
	}
	after.Native.Counters["kernel_dropped_events"] = 2
	r = BuildRuntimeCapture("run", "observed", before, after, true)
	if r.Status != "partial" || r.RunImpact != "unknown" {
		t.Fatalf("counter reset hidden: %+v", r)
	}
	if _, exists := r.NodeCounterDelta["kernel_dropped_events"]; exists {
		t.Fatal("reset delta should be unknown, not zero")
	}
}

func TestRuntimeCaptureMissingDisabledAndFailedCollector(t *testing.T) {
	before, after := capturePair()
	for _, state := range []string{"disabled", "unavailable"} {
		r := BuildRuntimeCapture("run", state, before, after, false)
		if r.NodeCounterDelta != nil || r.NodePendingEvents != nil || r.RunDroppedEvents != nil || r.CapabilitiesStart != nil {
			t.Fatalf("unobserved capture invented data: %+v", r)
		}
	}
	for _, mutate := range []func(*CaptureSnapshot){
		func(s *CaptureSnapshot) { s.Native = nil },
		func(s *CaptureSnapshot) { s.Capabilities = nil },
		func(s *CaptureSnapshot) { s.Native.PendingEvents = 1 },
		func(s *CaptureSnapshot) { s.Capabilities.Status = "failed" },
	} {
		before, after := capturePair()
		mutate(&after)
		r := BuildRuntimeCapture("run", "observed", before, after, true)
		if r.Status != "partial" || r.RunImpact != "unknown" {
			t.Fatalf("hidden degradation: %+v", r)
		}
	}
	r := BuildRuntimeCapture("run", "observed", before, after, false)
	if r.Status != "partial" {
		t.Fatalf("unconfirmed stop reported healthy: %+v", r)
	}
}

func TestRuntimeCaptureSeparatesCapabilityLimitsAndCleanup(t *testing.T) {
	before, after := capturePair()
	before.Capabilities.Status = "degraded"
	before.Capabilities.TLSDiscovery.Enabled = true
	before.Capabilities.TLSDiscovery.UnreadableProcesses = 38
	before.Capabilities.Probes = []sensor.ProbeCapability{
		{Name: "exec", Required: true, Status: "attached"},
		{Name: "rename", Status: "not_applicable"},
		{Name: "dns", Status: "failed"},
	}
	after.Native.QueuedBytes = 100
	after.Native.CleanupPendingBatches = 1
	r := BuildRuntimeCapture("run", "observed", before, after, true)
	if len(r.Issues) != 0 || len(r.Limitations) != 2 || r.RunImpact != "no_node_loss_reported" || r.RunDroppedEvents != nil {
		t.Fatalf("limits/cleanup falsely became run loss: %+v", r)
	}
	before.Capabilities.Probes[0].Status = "failed"
	r = BuildRuntimeCapture("run", "observed", before, after, true)
	if len(r.Issues) == 0 || r.RunImpact != "unknown" {
		t.Fatalf("required probe failure hidden: %+v", r)
	}
}

func TestRuntimeCaptureReadIsSavedNotLive(t *testing.T) {
	db, paths := coverageDB(t)
	ctx := context.Background()
	legacy, err := ReadRuntimeCoverage(ctx, db, "legacy")
	if err != nil || legacy.Capture.Status != "legacy_not_recorded" || legacy.Capture.RunDroppedEvents != nil {
		t.Fatalf("legacy: %+v %v", legacy, err)
	}
	before, after := capturePair()
	r := BuildRuntimeCapture("run", "observed", before, after, true)
	if err := SaveRuntimeCapture(db, paths, &r); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO telemetry_native_counters(name,value) VALUES ('kernel_dropped_events',9999)`); err != nil {
		t.Fatal(err)
	}
	got, err := ReadRuntimeCoverage(ctx, db, "run")
	if err != nil || !reflect.DeepEqual(got.Capture, r) {
		t.Fatalf("read altered historical capture: %+v %v", got, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRuntimeCoverage(ctx, db, "run"); err == nil {
		t.Fatal("database failure hidden as legacy coverage")
	}
}

func TestCaptureRejectsStaleAndOversizedProbeSnapshots(t *testing.T) {
	db, paths := coverageDB(t)
	start := time.Now().UTC().Add(-time.Second)
	for _, tc := range []struct {
		time time.Time
		want bool
	}{
		{start.Add(-time.Second), false}, {start.Add(time.Millisecond), true}, {start.Add(time.Hour), false},
	} {
		raw, _ := json.Marshal(sensor.CapabilityReport{SchemaVersion: "agentprovenance.sensor_capabilities/v1", UpdatedAt: tc.time.Format(time.RFC3339Nano)})
		if err := os.WriteFile(filepath.Join(paths.Logs, "sensor-capabilities.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
		s := ObserveCapture(context.Background(), db, paths, start)
		if (s.Capabilities != nil) != tc.want {
			t.Fatalf("capability freshness: %+v", s)
		}
	}
	if err := os.WriteFile(filepath.Join(paths.Logs, "sensor-capabilities.json"), make([]byte, (1<<20)+1), 0600); err != nil {
		t.Fatal(err)
	}
	if s := ObserveCapture(context.Background(), db, paths, start); s.Capabilities != nil {
		t.Fatal("oversized capabilities accepted")
	}
}

func TestCoverageStreamsAllNativeEventsWithBoundedExamples(t *testing.T) {
	db, _ := coverageDB(t)
	db.SetMaxOpenConns(1)
	_, err := db.Exec(`WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<1201)
		INSERT INTO events(id,run_id,source,event_type,payload,created_at)
		SELECT 'event-'||x,'native-run','agentprov_ebpf','execve','invalid JSON is not needed for coverage','2026-09-28T00:00:00Z' FROM n`)
	if err != nil {
		t.Fatal(err)
	}
	r, err := BuildCoverage(db, CoverageOptions{RunID: "native-run", Limit: 25})
	if err != nil || r.Summary.RuntimeEvents != 1201 || r.Summary.CorrelationGapCount != 1201 || len(r.Gaps) != 25 {
		t.Fatalf("truncated totals: %+v %v", r, err)
	}
	r, err = BuildCoverage(db, CoverageOptions{RunID: "absent"})
	if err != nil || r.Summary.RuntimeEvents != 0 {
		t.Fatalf("cross-run event leak: %+v %v", r, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := BuildCoverageContext(ctx, db, CoverageOptions{RunID: "native-run"}); err == nil {
		t.Fatal("ignored cancellation")
	}
}
