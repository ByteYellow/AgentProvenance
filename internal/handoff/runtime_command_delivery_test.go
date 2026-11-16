package handoff

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/runtimeadapter"
	"github.com/byteyellow/agentprovenance/internal/seccheck"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

// This stub exercises checkpoint/export storage; real identity/closure and
// receiver behavior are tested by runtimeadapter's native and fault fixtures.
type commandCaptureFixture struct{ fakeRuntimeCapture }

func (f *commandCaptureFixture) FinishCommand(_ context.Context, r runtimeadapter.Request, x runtimeadapter.Execution, start runtimeadapter.CapturePoint) runtimeadapter.CaptureReport {
	root := runtimeadapter.SentryProcess{PID: x.SentryPID, StartNS: x.SentryStartNS}
	wait := int32(7 << 8)
	watermark := &runtimeadapter.CommandWatermark{Root: root, RootWaitStatus: wait, EventCount: 1, ProcessCount: 1}
	return runtimeadapter.CaptureReport{ObservationLayer: "sentry", State: "sealed", Start: &start, Gaps: []string{}, Command: watermark,
		Evidence: &runtimeadapter.CommandEvidence{SchemaVersion: "agentprovenance.sentry_command_evidence/v1", DerivationRule: "unit-storage-fixture",
			Receiver: seccheck.Target{RunID: "original-receiver-run", Registration: seccheck.Registration{Namespace: r.Target.ProducerID, InstanceID: r.Target.InstanceID, Generation: r.Target.Generation}},
			Root:     root, RangeSHA256: strings.Repeat("a", 64), RootWaitStatus: &wait, Watermark: watermark,
			Events: []telemetry.EventRecord{{ID: "original-event", RunID: "original-receiver-run", Payload: `{"group_start_ns":1794839095305113409}`}}}}
}

func TestRuntimeCommandEvidenceSurvivesSignedDelivery(t *testing.T) {
	e, p, r, f := testRuntimeExecutor(t)
	f.beforeStart = func(x *runtimeadapter.Execution) {
		x.SentryPID = 10
		x.SentryStartNS = 1794839095305113409
		x.GateReleased = true
		x.SentryPIDBasis = "private_exec_fd_gate_and_runsc_procfs"
	}
	f.behavior = func(_ context.Context, _ runtimeadapter.Request, x runtimeadapter.Execution) (runtimeadapter.Execution, error) {
		x.State = "unknown"
		x.ExitCode = nil
		return x, errors.New("fixture lost runtime reply")
	}
	e.RuntimeCapture = &commandCaptureFixture{}
	a, _, err := e.Ledger.Admit(context.Background(), p, r)
	if err != nil {
		t.Fatal(err)
	}
	stop := startExecutor(t, e)
	report := waitExecution(t, e, p, a.ID, Failed)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if report.Attempt.State.Capture != Sealed || report.Checkpoint.Runtime.Execution.ExitCode == nil || *report.Checkpoint.Runtime.Execution.ExitCode != 7 {
		t.Fatalf("native outcome not preserved: %+v", report)
	}
	ref := report.Checkpoint.Runtime.Capture.EvidenceRef
	if ref == "" || report.Checkpoint.Runtime.Capture.Evidence != nil {
		t.Fatal("checkpoint did not persist the separate evidence object")
	}
	delivery := deliveryFromReport(t, e, p, report, "")
	package1 := delivery.prepare(t, "command-evidence")
	delivery.receive(t, package1)
	delivery.receive(t, package1)
	var evidence runtimeadapter.CommandEvidence
	if err := provenance.ReadObjectPayload(delivery.receiver.DB, a.LocalRunID, ref, &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence.Root.StartNS != 1794839095305113409 || len(evidence.Events) != 1 || evidence.Events[0].RunID != "original-receiver-run" || evidence.Events[0].Payload != `{"group_start_ns":1794839095305113409}` {
		t.Fatalf("source evidence changed during delivery: %+v", evidence)
	}
	if err := provenance.VerifyRun(delivery.receiver.DB, a.LocalRunID, io.Discard); err != nil {
		t.Fatal(err)
	}
	if f.runs.Load() != 1 {
		t.Fatal("delivery repeated workload")
	}
}
