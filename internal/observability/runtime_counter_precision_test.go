package observability

import (
	"context"
	"testing"
)

func TestRuntimeCapturePreservesLargeSavedCounters(t *testing.T) {
	db, paths := coverageDB(t)
	const count = int64(9007199254740993)
	r := RuntimeCaptureReport{SchemaVersion: RuntimeCaptureSchema, RunID: "precision", Status: "partial", NodeCounterDelta: map[string]int64{"kernel_dropped_events": count}}
	if err := SaveRuntimeCapture(db, paths, &r); err != nil {
		t.Fatal(err)
	}
	got, err := ReadRuntimeCoverage(context.Background(), db, "precision")
	if err != nil || got.Capture.NodeCounterDelta["kernel_dropped_events"] != count {
		t.Fatalf("counter rounded: %+v %v", got.Capture, err)
	}
}
