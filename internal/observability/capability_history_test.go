package observability

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/sensor"
)

func TestRuntimeHistoryPreservesIntermediateFailure(t *testing.T) {
	db, paths := coverageDB(t)
	before, after := capturePair()
	start := before.ObservedAt
	after.ObservedAt = start.Add(3 * time.Second)
	for i, status := range []string{"ready", "degraded", "ready", "stopped"} {
		at := start.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano)
		c := sensor.CapabilityReport{SchemaVersion: "agentprovenance.sensor_capabilities/v1", CollectorID: "history", Revision: uint64(i + 1), ChangedAt: at, UpdatedAt: at, Ready: status == "ready", Status: status}
		if i == 0 {
			before.Capabilities = &c
		}
		if i == 3 {
			after.Capabilities = &c
		}
		if err := sensor.SaveCapabilityChange(paths.Logs, c); err != nil {
			t.Fatal(err)
		}
	}
	r := BuildRuntimeCapture("history-run", "observed", before, after, true)
	if r.Status != "ok" {
		t.Fatalf("boundary control changed: %+v", r)
	}
	if err := SaveRuntimeCapabilityHistory(context.Background(), db, paths, &r); err != nil {
		t.Fatal(err)
	}
	if r.Status != "partial" || r.CapabilityHistory.Status != "recorded" || r.CapabilityHistory.Saved != 4 || !slices.Contains(r.Issues, "probe_coverage_degraded") {
		t.Fatalf("intermediate failure hidden: %+v", r)
	}
	if err := SaveRuntimeCapture(db, paths, &r); err != nil {
		t.Fatal(err)
	}
	if err := SaveRuntimeCapabilityHistory(context.Background(), db, paths, &r); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM provenance_objects WHERE run_id='history-run' AND object_type='sensor_capability_interval'`).Scan(&count); err != nil || count != 4 {
		t.Fatalf("retry changed history: %d %v", count, err)
	}
	if err := os.RemoveAll(filepath.Join(paths.Logs, "sensor-capabilities")); err != nil {
		t.Fatal(err)
	}
	coverage, err := ReadRuntimeCoverage(context.Background(), db, "history-run")
	if err != nil || coverage.Capture.CapabilityHistory.Saved != 4 {
		t.Fatalf("historical query read removed live journal: %+v %v", coverage, err)
	}
	var hash string
	if err := db.QueryRow(`SELECT hash FROM provenance_objects WHERE run_id='history-run' AND object_type='sensor_capability_interval' LIMIT 1`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	var value CapabilityInterval
	if err := provenance.ReadObjectPayload(db, "history-run", hash, &value); err != nil || value.Basis != "recorded_capability_changes" {
		t.Fatalf("saved interval: %+v %v", value, err)
	}
	if err := SaveRuntimeCapabilityHistory(context.Background(), db, paths, &r); err == nil || r.CapabilityHistory.Status != "incomplete" || !slices.Contains(r.Issues, "capability_history_incomplete") {
		t.Fatalf("missing journal hidden: %+v %v", r, err)
	}
}

func TestRuntimeHistoryCleanStopEndsActiveInterval(t *testing.T) {
	for _, clean := range []bool{true, false} {
		db, paths := coverageDB(t)
		before, after := capturePair()
		start := before.ObservedAt
		stopped := start.Add(time.Second)
		after.ObservedAt = stopped.Add(time.Second)
		for i, status := range []string{"ready", "stopped"} {
			at := start.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano)
			c := sensor.CapabilityReport{SchemaVersion: "agentprovenance.sensor_capabilities/v1", CollectorID: "clean-stop", Revision: uint64(i + 1), ChangedAt: at, UpdatedAt: at, Ready: i == 0, Status: status}
			if i == 0 {
				before.Capabilities = &c
			} else {
				after.Capabilities = &c
			}
			if err := sensor.SaveCapabilityChange(paths.Logs, c); err != nil {
				t.Fatal(err)
			}
		}
		r := BuildRuntimeCapture("stop-run", "observed", before, after, clean)
		if err := SaveRuntimeCapabilityHistory(context.Background(), db, paths, &r); err != nil {
			t.Fatal(err)
		}
		if clean && (r.Status != "ok" || len(r.Issues) != 0) {
			t.Fatalf("normal shutdown became degraded: %+v", r)
		}
		if !clean && (r.Status != "partial" || !slices.Contains(r.Issues, "collector_exit_unconfirmed")) {
			t.Fatalf("unconfirmed shutdown hidden: %+v", r)
		}
	}
}
