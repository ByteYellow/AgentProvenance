package handoff

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/byteyellow/agentprovenance/internal/sensor"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

type fixtureBoundary struct{ sequence uint64 }

func (f *fixtureBoundary) Checkpoint(ctx context.Context, callback func(sensor.CaptureBoundary) error) (sensor.CaptureBoundary, error) {
	if err := ctx.Err(); err != nil {
		return sensor.CaptureBoundary{}, err
	}
	f.sequence++
	b := sensor.CaptureBoundary{SchemaVersion: "agentprovenance.sensor_boundary/v1", Boundary: "ring_and_decoder",
		CollectorID: "fixture-collector", Sequence: f.sequence, KernelTimeNS: f.sequence, ObservedAt: time.Now().UTC()}
	return b, callback(b)
}

func TestNativeCaptureFixedPoints(t *testing.T) {
	e, _, _ := testExecutor(t)
	stream, err := telemetry.NewNativeStream(e.Ledger.DB, e.Paths, telemetry.NativeStreamOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	n := &NativeCapture{Checkpointer: &fixtureBoundary{}, Stream: stream,
		Capabilities: func() sensor.CapabilityReport { return sensor.CapabilityReport{Ready: true, Status: "ready"} }}
	scope := record.ExecutionScope{RunID: "fixture-run", BindingID: "fixture-binding", ScopeKind: "cgroup", CgroupID: "42"}
	start, err := n.Begin(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	empty := true
	r := record.Result{Scope: &scope, RootPID: 42, EndEventID: "fixture-end", ScopeObservation: &record.ScopeObservation{
		ScopeKind: "cgroup", CgroupID: "42", Empty: &empty, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}}
	report := n.Finish(context.Background(), *start, r)
	if report.State != Sealed || report.End.Sensor.Sequence != 2 || report.Progress.State != "settled" || len(report.Issues) != 0 {
		t.Fatalf("fixed capture: %+v", report)
	}
	startRaw, _ := json.Marshal(start)
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	report = n.Finish(context.Background(), *start, r)
	if report.State != Incomplete || report.Error == "" || report.End != nil || report.Issues[0] != "sensor_checkpoint_failed" {
		t.Fatalf("closed capture became sealed: %+v", report)
	}
	retained, _ := json.Marshal(report.Start)
	if string(startRaw) != string(retained) {
		t.Fatal("end failure changed the initial boundary")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := n.Begin(ctx, scope); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled begin: %v", err)
	}
	scope.ScopeKind = "logical_process_scope"
	if _, err := n.Begin(context.Background(), scope); err == nil {
		t.Fatal("logical scope accepted as native capture")
	}
}

func TestNativeCaptureIssueMatrix(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*NativeCapturePoint, *record.ScopeObservation, *telemetry.NativePrefixProgress)
		issue  string
	}{
		{"clean", func(*NativeCapturePoint, *record.ScopeObservation, *telemetry.NativePrefixProgress) {}, ""},
		{"populated", func(_ *NativeCapturePoint, o *record.ScopeObservation, _ *telemetry.NativePrefixProgress) {
			*o.Empty = false
		}, "scope_still_populated"},
		{"unknown", func(_ *NativeCapturePoint, o *record.ScopeObservation, _ *telemetry.NativePrefixProgress) {
			o.Empty = nil
		}, "scope_population_unknown"},
		{"observe_error", func(_ *NativeCapturePoint, o *record.ScopeObservation, _ *telemetry.NativePrefixProgress) {
			o.Error = "permission denied"
		}, "scope_population_unknown"},
		{"other_scope", func(_ *NativeCapturePoint, o *record.ScopeObservation, _ *telemetry.NativePrefixProgress) {
			o.CgroupID = "other"
		}, "scope_population_unknown"},
		{"collector_restart", func(p *NativeCapturePoint, _ *record.ScopeObservation, _ *telemetry.NativePrefixProgress) {
			p.Sensor.CollectorID = "new"
		}, "collector_boundary_changed"},
		{"spool_restart", func(p *NativeCapturePoint, _ *record.ScopeObservation, _ *telemetry.NativePrefixProgress) {
			p.Spool.CollectorID = "new"
		}, "collector_boundary_changed"},
		{"repeated_marker", func(p *NativeCapturePoint, _ *record.ScopeObservation, _ *telemetry.NativePrefixProgress) {
			p.Sensor.Sequence = 1
		}, "collector_boundary_changed"},
		{"kernel_loss", func(p *NativeCapturePoint, _ *record.ScopeObservation, _ *telemetry.NativePrefixProgress) {
			p.Sensor.KernelDrops++
		}, "shared_collector_loss"},
		{"state_loss", func(p *NativeCapturePoint, _ *record.ScopeObservation, _ *telemetry.NativePrefixProgress) {
			p.Sensor.StateQueueDrops++
		}, "shared_collector_loss"},
		{"tls_pending", func(p *NativeCapturePoint, _ *record.ScopeObservation, _ *telemetry.NativePrefixProgress) {
			p.Sensor.PendingTLSBytes = 7
		}, "shared_tls_pending"},
		{"tls_reassembly_loss", func(p *NativeCapturePoint, _ *record.ScopeObservation, _ *telemetry.NativePrefixProgress) {
			if err := json.Unmarshal([]byte(`{"tls_lost_streams":1,"tls_lost_bytes":31}`), &p.Sensor); err != nil {
				t.Fatal(err)
			}
		}, "shared_tls_loss"},
		{"queue_loss", func(p *NativeCapturePoint, _ *record.ScopeObservation, _ *telemetry.NativePrefixProgress) {
			p.Spool.Counters["dropped_queue_full"] = 1
		}, "shared_spool_loss"},
		{"pending", func(_ *NativeCapturePoint, _ *record.ScopeObservation, p *telemetry.NativePrefixProgress) {
			p.State, p.Pending = "pending", 1
		}, "shared_prefix_pending"},
		{"expired", func(_ *NativeCapturePoint, _ *record.ScopeObservation, p *telemetry.NativePrefixProgress) {
			p.Dropped = 1
		}, "shared_prefix_loss"},
		{"invalid", func(_ *NativeCapturePoint, _ *record.ScopeObservation, p *telemetry.NativePrefixProgress) {
			p.Failed = 1
		}, "shared_prefix_loss"},
	} {
		t.Run(test.name, func(t *testing.T) {
			start := NativeCapturePoint{Scope: record.ExecutionScope{CgroupID: "42"},
				Sensor: sensor.CaptureBoundary{CollectorID: "sensor", Sequence: 1, KernelTimeNS: 10, DecodedRecords: 5, KernelDrops: 2},
				Spool:  telemetry.NativePrefix{CollectorID: "spool", Sequence: 5, Counters: map[string]int64{}}}
			end := start
			end.Sensor.Sequence, end.Sensor.KernelTimeNS = 2, 20
			end.Spool.Counters = map[string]int64{}
			empty := true
			o := record.ScopeObservation{ScopeKind: "cgroup", CgroupID: "42", Empty: &empty}
			p := telemetry.NativePrefixProgress{State: "settled"}
			test.change(&end, &o, &p)
			got := strings.Join(nativeCaptureIssues(start, end, &o, p), ",")
			if got != test.issue {
				t.Fatalf("issue=%s want=%s", got, test.issue)
			}
		})
	}
}

func TestExecutorCaptureReadinessPreventsLaunch(t *testing.T) {
	e, p, r := testExecutor(t)
	e.Capture = &NativeCapture{}
	a, _, err := e.Ledger.Admit(context.Background(), p, r)
	if err != nil {
		t.Fatal(err)
	}
	startExecutor(t, e)
	report := waitExecution(t, e, p, a.ID, Failed)
	if report.Attempt.State.Capture != Incomplete || report.Checkpoint.Error == "" {
		t.Fatalf("missing capture preflight: %+v", report)
	}
	var count int
	if err := e.Ledger.DB.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id=? AND event_type='exec_start'`, a.LocalRunID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("command started before capture ready: %d %v", count, err)
	}
}

func TestExecutorRecoversInterruptedCapture(t *testing.T) {
	e, p, request := testExecutor(t)
	a, _, _ := e.Ledger.Admit(context.Background(), p, request)
	stop := startExecutor(t, e)
	r := waitExecution(t, e, p, a.ID, Succeeded)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	c := *r.Checkpoint
	c.Reason, c.Capture = "capture_fixture", &NativeCaptureReport{SchemaVersion: nativeCaptureSchema, State: Draining, Issues: []string{}}
	if _, err := e.saveCheckpoint(context.Background(), r.Attempt, c); err != nil {
		t.Fatal(err)
	}
	startExecutor(t, e)
	r, err := e.Ledger.Report(context.Background(), p, a.ID)
	if err != nil || r.Attempt.State.Capture != Incomplete || r.Attempt.State.Execution != Succeeded ||
		r.Checkpoint.Capture.State != Incomplete || r.Checkpoint.Stdout.Ref != c.Stdout.Ref || r.Checkpoint.Result.EndEventID != c.Result.EndEventID {
		t.Fatalf("capture restart lost execution evidence: %+v %v", r, err)
	}
	if rowCount(t, e.Ledger.DB, "tool_calls") != 1 {
		t.Fatal("capture recovery reexecuted command")
	}
}

func TestCaptureCompletionPreservesConcurrentDelivery(t *testing.T) {
	f := testDelivery(t)
	e := &Executor{Ledger: f.sender.Ledger, Paths: f.sender.Paths}
	c := *f.report.Checkpoint
	c.Reason, c.State.Capture = "capture_finished", Sealed
	c.Capture = &NativeCaptureReport{SchemaVersion: nativeCaptureSchema, State: Sealed, Issues: []string{}}
	delivery := f.prepare(t, "while-capture-drains")
	raw := f.receive(t, delivery)
	if _, err := f.sender.Acknowledge(context.Background(), f.principal, delivery.Manifest.ID, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := e.commitCheckpoint(context.Background(), f.report.Attempt, c, true); err != nil {
		t.Fatal(err)
	}
	r, err := e.Ledger.Report(context.Background(), f.principal, f.report.Attempt.ID)
	if err != nil || r.Attempt.State.Capture != Sealed || r.Attempt.State.Delivery != Acknowledged {
		t.Fatalf("capture completion overwrote delivery: %+v %v", r, err)
	}
	if _, err := e.commitCheckpoint(context.Background(), f.report.Attempt, c, true); !errors.Is(err, ErrStale) {
		t.Fatalf("repeated stale capture changed committed state: %v", err)
	}
	f.report = r
	checkCaptureDelivery(t, f)
}

func checkCaptureDelivery(t *testing.T, f deliveryFixture) {
	t.Helper()
	d := f.prepare(t, "capture-evidence")
	f.receive(t, d)
	if err := f.receiver.DB.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.receiver.DB, err = store.Open(f.receiver.Paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.receiver.DB.Close() })
	var c Checkpoint
	if err := provenance.ReadObjectPayload(f.receiver.DB, f.report.Attempt.LocalRunID, d.Manifest.CheckpointRef, &c); err != nil {
		t.Fatal(err)
	}
	if c.Capture == nil || c.Result == nil || c.Result.ScopeObservation == nil {
		t.Fatalf("delivered checkpoint lost capture or scope observation: %+v", c)
	}
	for name, pair := range map[string][2]any{
		"capture": {f.report.Checkpoint.Capture, c.Capture},
		"scope":   {f.report.Checkpoint.Result.ScopeObservation, c.Result.ScopeObservation},
	} {
		want, _ := json.Marshal(pair[0])
		got, _ := json.Marshal(pair[1])
		if !bytes.Equal(want, got) {
			t.Fatalf("signed delivery changed %s: %s != %s", name, got, want)
		}
	}
	var raw string
	if err := f.receiver.DB.QueryRow(`SELECT json_extract(payload,'$.scope_observation') FROM events WHERE id=?`, c.Result.EndEventID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var observation record.ScopeObservation
	if err := json.Unmarshal([]byte(raw), &observation); err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(observation)
	want, _ := json.Marshal(c.Result.ScopeObservation)
	if !bytes.Equal(got, want) {
		t.Fatal("end event and signed checkpoint disagree on scope population")
	}
}
