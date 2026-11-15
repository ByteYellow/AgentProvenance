package telemetry

import (
	"context"
	"database/sql"
	"reflect"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/sensor"
)

func nativeCapability(revision uint64) sensor.CapabilityReport {
	at := time.Now().UTC().Format(time.RFC3339Nano)
	return sensor.CapabilityReport{SchemaVersion: "agentprovenance.sensor_capabilities/v1",
		CollectorID: "capturing-sensor", Revision: revision, UpdatedAt: at, ChangedAt: at, Status: "ready", Ready: true,
		Probes: []sensor.ProbeCapability{{Name: "sys_enter_openat", Status: "attached"}}}
}

func TestNativeCapabilityCrashKeepsUnsealedOriginalWindow(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{Ingest: JSONLIngestOptions{DropUncorrelated: true}})
	first := nativeCapability(1)
	if err := n.ObserveCapabilities(first); err != nil {
		t.Fatal(err)
	}
	nativeWrite(t, n, "scope", "/captured.csv")
	last := nativeCapability(2)
	last.Ready, last.Status = false, "degraded"
	if err := n.ObserveCapabilities(last); err != nil {
		t.Fatal(err)
	}
	want := *n.captureWindow
	if err := n.file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := n.lock.Close(); err != nil {
		t.Fatal(err)
	}
	n.closed = true
	var observed []NativeCaptureWindow
	n = nativeTestStream(t, db, paths, NativeStreamOptions{OnCapture: func(_ context.Context, _ *sql.Tx, _ string, w NativeCaptureWindow) error {
		observed = append(observed, w)
		return nil
	}})
	nativeBind(t, db, "scope", "run")
	current := nativeCapability(1)
	current.CollectorID = "new-sensor"
	if err := n.ObserveCapabilities(current); err != nil {
		t.Fatal(err)
	}
	if err := n.Process(32); err != nil {
		t.Fatal(err)
	}
	if len(observed) != 1 || !reflect.DeepEqual(observed[0], want) || !observed[0].EndedAt.IsZero() {
		t.Fatalf("recovery rewrote original unsealed window: %+v", observed)
	}
}

func TestNativeCapabilitiesRejectConflictsAndOwnReportMemory(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{})
	report := nativeCapability(1)
	if err := n.ObserveCapabilities(report); err != nil {
		t.Fatal(err)
	}
	report.Probes[0].Status = "failed"
	if n.capabilities.Probes[0].Status != "attached" {
		t.Fatal("caller mutated saved capability")
	}
	if err := n.ObserveCapabilities(report); err == nil {
		t.Fatal("same revision conflict accepted")
	}
	other := nativeCapability(2)
	other.CollectorID = "another-sensor"
	if err := n.ObserveCapabilities(other); err == nil {
		t.Fatal("collector substitution accepted")
	}
	if err := n.ObserveCapabilities(nativeCapability(3)); err != nil {
		t.Fatal(err)
	}
	if err := n.ObserveCapabilities(nativeCapability(2)); err == nil {
		t.Fatal("backwards revision accepted")
	}
}
