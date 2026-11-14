package telemetry

import (
	"context"
	"slices"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/seccheck/wire"
)

func TestProducerHealthIncludesSentryWithoutClaimingComplete(t *testing.T) {
	db, _ := nativeTestStore(t)
	if _, err := db.Exec(`INSERT INTO events(id,run_id,source,event_type,payload,correlation_method,created_at)
		VALUES ('sentry-health','sentry-run','gvisor_seccheck','file_open','{}','runtime_scope','2026-11-14T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	report, err := BuildProducerHealth(db, ProducerHealthOptions{RunID: "sentry-run"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Events.RuntimeEvents != 1 || report.Events.BySource["gvisor_seccheck"] != 1 {
		t.Fatalf("Sentry observations missing from producer health: %+v", report.Events)
	}
	if report.Coverage.Complete {
		t.Fatal("a registered Sentry scope was promoted to complete capture")
	}
}

func TestSecCheckRestartGapDoesNotInventLossCount(t *testing.T) {
	db, paths := nativeTestStore(t)
	s, err := NewSecCheckStream(db, paths, NativeStreamOptions{BatchEvents: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r := secCheckTestRecord(t, &wire.Open{ContextData: secCheckTestContext()}, wire.MessageType_MESSAGE_SYSCALL_OPEN, 1)
	r.Kind, r.Reason, r.Packet, r.DroppedDelta = "stream", "stale_endpoint_recovered", nil, nil
	for i := 0; i < 2; i++ {
		if err := s.Sink("sentry-run", r.Registration)(context.Background(), r); err != nil {
			t.Fatal(err)
		}
		if err := s.Drain(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	report, err := BuildProducerHealth(db, ProducerHealthOptions{RunID: "sentry-run"})
	if err != nil {
		t.Fatal(err)
	}
	if report.SecCheckCapture.Counters["stale_endpoint_recovered"] != 1 || report.SecCheckCapture.Counters["reported_dropped_events"] != 0 || report.Events.SensorDroppedEvents != 0 || report.Coverage.HasSensorDrops || report.Coverage.Complete || !slices.Contains(report.Coverage.Issues, "sentry_node_receiver_restart_gap") {
		t.Fatalf("unknown restart gap misreported: %+v", report)
	}
}

func TestSecCheckHealthCountersAreDurableAndDeduplicated(t *testing.T) {
	db, paths := nativeTestStore(t)
	s, err := NewSecCheckStream(db, paths, NativeStreamOptions{BatchEvents: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c := secCheckTestContext()
	c.ThreadStartTimeNs = 0
	r := secCheckTestRecord(t, &wire.Open{ContextData: c, Pathname: "/tmp/report"}, wire.MessageType_MESSAGE_SYSCALL_OPEN, 1)
	drops := uint64(7)
	r.DroppedDelta = &drops
	for i := 0; i < 2; i++ {
		if err := s.Sink("sentry-run", r.Registration)(context.Background(), r); err != nil {
			t.Fatal(err)
		}
		if err := s.Drain(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	report, err := BuildProducerHealth(db, ProducerHealthOptions{RunID: "sentry-run"})
	if err != nil {
		t.Fatal(err)
	}
	if report.SecCheckCapture.Counters["reported_dropped_events"] != 7 || report.SecCheckCapture.Counters["identity_gap_records"] != 1 || report.NativeCapture.Counters["reported_dropped_events"] != 0 || !report.Coverage.HasSensorDrops || report.Coverage.Complete {
		t.Fatalf("incorrect source counters: %+v", report)
	}
	other, err := BuildProducerHealth(db, ProducerHealthOptions{RunID: "other-run"})
	if err != nil || other.Events.RuntimeEvents != 0 || other.Events.SensorDroppedEvents != 0 || !other.Coverage.HasSensorDrops {
		t.Fatalf("node loss assigned to a run: %+v %v", other, err)
	}
}
