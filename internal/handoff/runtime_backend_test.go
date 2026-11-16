package handoff

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/byteyellow/agentprovenance/internal/runtimeadapter"
	"github.com/byteyellow/agentprovenance/internal/sensor"
)

type fakeRuntime struct {
	binding     runtimeadapter.Binding
	runs        atomic.Int32
	behavior    func(context.Context, runtimeadapter.Request, runtimeadapter.Execution) (runtimeadapter.Execution, error)
	admitError  error
	beforeStart func(*runtimeadapter.Execution)
}

func (f *fakeRuntime) Admit(ctx context.Context, r runtimeadapter.Request) error {
	if f.admitError != nil {
		return f.admitError
	}
	_, err := f.binding.Resolve(ctx, r.Target)
	return err
}

func (f *fakeRuntime) Run(ctx context.Context, r runtimeadapter.Request, started func(runtimeadapter.Execution) error) (runtimeadapter.Execution, error) {
	f.runs.Add(1)
	e := runtimeadapter.NewExecution(f.binding, r)
	e.State, e.Started = "running", true
	if f.beforeStart != nil {
		f.beforeStart(&e)
	}
	if err := started(e); err != nil {
		return e, err
	}
	if f.behavior != nil {
		return f.behavior(ctx, r, e)
	}
	fmt.Fprint(r.Command.Stdout, "runtime output")
	fmt.Fprint(r.Command.Stderr, "runtime diagnostics")
	zero := 0
	e.State, e.ExitCode = "succeeded", &zero
	return e, nil
}

func testRuntimeExecutor(t *testing.T) (*Executor, Principal, Request, *fakeRuntime) {
	t.Helper()
	e, p, r := testExecutor(t)
	b := runtimeadapter.Binding{Target: runtimeadapter.Target(r.Target), Mode: "runsc", ContainerID: "container", StateCreated: "2026-11-16T00:00:00Z"}
	f := &fakeRuntime{binding: b}
	e.Binding, e.Backend, e.Concurrency = &b, f, 1
	return e, p, r, f
}

func TestRuntimeGateDeniedAfterIdentityCheckpointIsKnownFailure(t *testing.T) {
	e, p, r, f := testRuntimeExecutor(t)
	f.beforeStart = func(x *runtimeadapter.Execution) {
		x.Started = false
		x.SentryPID, x.SentryStartNS = 3, 123456789
		x.SentryPIDBasis = "private_exec_fd_gate_and_runsc_procfs"
	}
	f.behavior = func(_ context.Context, _ runtimeadapter.Request, x runtimeadapter.Execution) (runtimeadapter.Execution, error) {
		x.State = "failed"
		x.Gaps = append(x.Gaps, "controlled_gate_not_released")
		return x, errors.New("fixture gate denied before release")
	}
	a, _, err := e.Ledger.Admit(context.Background(), p, r)
	if err != nil {
		t.Fatal(err)
	}
	stop := startExecutor(t, e)
	report := waitExecution(t, e, p, a.ID, Failed)
	if report.Checkpoint.Runtime.Execution.Started || report.Checkpoint.Runtime.Execution.GateReleased {
		t.Fatal("denied gate became a started workload")
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeBackendUsesLedgerForIdempotencyAndQuery(t *testing.T) {
	e, p, r, f := testRuntimeExecutor(t)
	a, _, err := e.Ledger.Admit(context.Background(), p, r)
	if err != nil {
		t.Fatal(err)
	}
	stop := startExecutor(t, e)
	report := waitExecution(t, e, p, a.ID, Succeeded)
	if report.Checkpoint.Runtime == nil || report.Checkpoint.Runtime.Execution.AttemptID != a.ID || report.Checkpoint.Scope != nil || report.Checkpoint.Result != nil {
		t.Fatalf("runtime identity was borrowed from native: %+v", report.Checkpoint)
	}
	if report.Attempt.State.Capture != Incomplete || report.Attempt.State.Delivery != Pending {
		t.Fatalf("mixed state axes: %+v", report.Attempt.State)
	}
	text, err := provenance.ReadTextContentPage(e.Ledger.DB, a.LocalRunID, report.Checkpoint.Stdout.Ref, 0, 1024)
	if err != nil || text.Content != "runtime output" {
		t.Fatalf("output: %+v %v", text, err)
	}
	for i := 0; i < 3; i++ {
		reused, duplicate, err := e.Ledger.Admit(context.Background(), p, r)
		if err != nil || !duplicate || reused.ID != a.ID {
			t.Fatalf("duplicate: %+v %v", reused, err)
		}
		if _, err := e.Ledger.Report(context.Background(), p, a.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	startExecutor(t, e)
	if f.runs.Load() != 1 || rowCount(t, e.Ledger.DB, "tool_calls") != 0 {
		t.Fatal("query or restart re-executed runtime command")
	}
}

func TestRuntimeFailuresPreserveKnownAndUnknown(t *testing.T) {
	for _, mode := range []string{"admit", "failed", "lost", "wrong_target", "wrong_attempt"} {
		t.Run(mode, func(t *testing.T) {
			e, p, r, f := testRuntimeExecutor(t)
			want := Unknown
			if mode == "admit" {
				f.admitError = errors.New("runtime unavailable")
				want = Failed
			}
			if mode == "failed" {
				want = Failed
			}
			f.behavior = func(ctx context.Context, r runtimeadapter.Request, x runtimeadapter.Execution) (runtimeadapter.Execution, error) {
				switch mode {
				case "failed":
					code := 9
					x.State, x.ExitCode = "failed", &code
				case "lost":
					return x, errors.New("transport disconnected")
				case "wrong_target":
					x.Binding.Target.Generation = "restored"
					zero := 0
					x.State, x.ExitCode = "succeeded", &zero
				case "wrong_attempt":
					x.AttemptID = "other"
					zero := 0
					x.State, x.ExitCode = "succeeded", &zero
				}
				return x, nil
			}
			a, _, err := e.Ledger.Admit(context.Background(), p, r)
			if err != nil {
				t.Fatal(err)
			}
			startExecutor(t, e)
			report := waitExecution(t, e, p, a.ID, want)
			if report.Attempt.State.Capture != Incomplete {
				t.Fatal(report.Attempt.State)
			}
			if want == Unknown && report.Checkpoint.Runtime.Execution.ExitCode != nil {
				t.Fatal("unknown carries an exit code")
			}
			if mode == "admit" && f.runs.Load() != 0 {
				t.Fatal("admission failure launched a command")
			}
		})
	}
}

func TestRuntimeCancellationIsDurableAndFencesGeneration(t *testing.T) {
	e, p, r, f := testRuntimeExecutor(t)
	f.behavior = func(ctx context.Context, _ runtimeadapter.Request, x runtimeadapter.Execution) (runtimeadapter.Execution, error) {
		<-ctx.Done()
		x.State = "unknown"
		return x, ctx.Err()
	}
	a, _, err := e.Ledger.Admit(context.Background(), p, r)
	if err != nil {
		t.Fatal(err)
	}
	stop := startExecutor(t, e)
	waitExecution(t, e, p, a.ID, Running)
	if _, err := e.Ledger.RequestStop(context.Background(), p, a.ID, "stop-runtime"); err != nil {
		t.Fatal(err)
	}
	unknown := waitExecution(t, e, p, a.ID, Unknown)
	if !unknown.StopRequested || unknown.Checkpoint.Runtime.Execution.ExitCode != nil {
		t.Fatal(unknown)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	f.behavior = nil
	r.DispatchID, r.OperationID = "next-dispatch", "next-operation"
	b, _, err := e.Ledger.Admit(context.Background(), p, r)
	if err != nil {
		t.Fatal(err)
	}
	startExecutor(t, e)
	blocked := waitExecution(t, e, p, b.ID, Failed)
	if !strings.Contains(blocked.Checkpoint.Error, "unresolved attempt") || f.runs.Load() != 1 {
		t.Fatalf("unresolved generation ran again: %+v runs=%d", blocked.Checkpoint, f.runs.Load())
	}
}

func TestRuntimeRestartNeverUsesNativeRecoveryOrExec(t *testing.T) {
	e, p, r, f := testRuntimeExecutor(t)
	a, _, err := e.Ledger.Admit(context.Background(), p, r)
	if err != nil {
		t.Fatal(err)
	}
	state := a.State
	state.Execution = Starting
	x := runtimeadapter.NewExecution(*e.Binding, runtimeadapter.Request{Target: runtimeadapter.Target(r.Target), OperationID: r.OperationID, AttemptID: a.ID})
	x.RunID = a.LocalRunID
	if _, err := e.saveCheckpoint(context.Background(), a, Checkpoint{State: state, Reason: "runtime_prepared", Runtime: &RuntimeReport{Execution: x}}); err != nil {
		t.Fatal(err)
	}
	startExecutor(t, e)
	report := waitExecution(t, e, p, a.ID, Unknown)
	if f.runs.Load() != 0 || report.Checkpoint.Runtime.Execution.State != "unknown" || report.Checkpoint.Stdout.State != "unknown" {
		t.Fatalf("restart invented result: %+v", report)
	}
	if !strings.Contains(strings.Join(report.Checkpoint.Runtime.Execution.Gaps, ","), "executor_restart_result_unknown") {
		t.Fatal(report.Checkpoint.Runtime)
	}
}

func TestRuntimeGenerationAndConcurrencyRejectedBeforeStart(t *testing.T) {
	for _, mode := range []string{"generation", "producer", "instance", "concurrency", "native_capture"} {
		t.Run(mode, func(t *testing.T) {
			e, _, _, f := testRuntimeExecutor(t)
			switch mode {
			case "generation":
				e.Binding.Target.Generation = "restored"
			case "producer":
				e.Binding.Target.ProducerID = "other"
			case "instance":
				e.Binding.Target.InstanceID = "clone"
			case "concurrency":
				e.Concurrency = 2
			case "native_capture":
				e.Capture = &NativeCapture{}
			}
			if close, err := e.Start(context.Background()); err == nil {
				close()
				t.Fatal("invalid runtime configuration started")
			}
			if f.runs.Load() != 0 {
				t.Fatal("invalid configuration ran")
			}
		})
	}
}

func TestGuestUsesExistingNativeCollectorContract(t *testing.T) {
	e, _, r := testExecutor(t)
	b := runtimeadapter.Binding{Target: runtimeadapter.Target(r.Target), Mode: "guest"}
	e.Binding = &b
	if err := e.validateBackend(context.Background(), 2); err == nil {
		t.Fatal("guest accepted missing capture")
	}
	e.Capture = &NativeCapture{Capabilities: func() sensor.CapabilityReport {
		return sensor.CapabilityReport{Producer: &sensor.CapabilityProducer{Placement: "host_kernel"}}
	}}
	if err := e.validateBackend(context.Background(), 2); err == nil {
		t.Fatal("guest accepted host capture")
	}
	e.Capture = &NativeCapture{Capabilities: func() sensor.CapabilityReport {
		return sensor.CapabilityReport{Producer: &sensor.CapabilityProducer{Placement: "guest_kernel"}}
	}}
	if err := e.validateBackend(context.Background(), 2); err != nil {
		t.Fatal(err)
	}
	if e.Backend != nil {
		t.Fatal("guest replaced the native execution pipeline")
	}
}

type fakeRuntimeCapture struct {
	probeErr         error
	probes, finishes atomic.Int32
}

func (f *fakeRuntimeCapture) Probe(_ context.Context, target runtimeadapter.Target) (runtimeadapter.CapturePoint, error) {
	f.probes.Add(1)
	return runtimeadapter.CapturePoint{Target: target}, f.probeErr
}

func (f *fakeRuntimeCapture) Finish(_ context.Context, _ runtimeadapter.Target, start runtimeadapter.CapturePoint) runtimeadapter.CaptureReport {
	f.finishes.Add(1)
	return runtimeadapter.CaptureReport{ObservationLayer: "sentry", State: "sealed", Start: &start}
}

func TestRuntimeCaptureAdmissionAndCompletionAreSeparate(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(fmt.Sprint(reject), func(t *testing.T) {
			e, p, r, f := testRuntimeExecutor(t)
			capture := &fakeRuntimeCapture{}
			want := Succeeded
			if reject {
				capture.probeErr = errors.New("receiver generation mismatch")
				want = Failed
			}
			e.RuntimeCapture = capture
			a, _, err := e.Ledger.Admit(context.Background(), p, r)
			if err != nil {
				t.Fatal(err)
			}
			startExecutor(t, e)
			report := waitExecution(t, e, p, a.ID, want)
			if report.Attempt.State.Capture != Incomplete || capture.probes.Load() != 1 {
				t.Fatal(report)
			}
			if reject {
				if f.runs.Load() != 0 || capture.finishes.Load() != 0 {
					t.Fatal("unready capture launched execution")
				}
			} else {
				if f.runs.Load() != 1 || capture.finishes.Load() != 1 || report.Checkpoint.Runtime.Capture.State != "incomplete" || len(report.Checkpoint.Runtime.Capture.Gaps) != 2 {
					t.Fatalf("receiver promoted uncorrelated command to sealed: %+v", report)
				}
			}
		})
	}
}

func TestRuntimeNewGenerationRejectsOldRequestsAndRunsNew(t *testing.T) {
	e, p, r, f := testRuntimeExecutor(t)
	old := r
	e.Ledger.Target.Generation = "new-generation"
	e.Binding.Target.Generation = "new-generation"
	f.binding = *e.Binding
	p.AllowedTargets = []Target{e.Ledger.Target}
	if _, _, err := e.Ledger.Admit(context.Background(), p, old); !errors.Is(err, ErrForbidden) {
		t.Fatalf("old generation: %v", err)
	}
	r.Target = e.Ledger.Target
	a, _, err := e.Ledger.Admit(context.Background(), p, r)
	if err != nil {
		t.Fatal(err)
	}
	startExecutor(t, e)
	report := waitExecution(t, e, p, a.ID, Succeeded)
	if report.Checkpoint.Runtime.Execution.Binding.Target.Generation != "new-generation" || f.runs.Load() != 1 {
		t.Fatal(report)
	}
}

func TestPlatformBindingSurvivesCheckpointsAndRejectsReconfiguration(t *testing.T) {
	e, p, r := testExecutor(t)
	g := runtimeadapter.GuestIdentity{RuntimeClass: "kata-qemu", RuntimeHandler: "kata-qemu-runtime-rs", PodUID: "pod", ContainerID: "container", GuestBootID: "boot"}
	b := (runtimeadapter.Binding{Target: runtimeadapter.Target(r.Target), Mode: "guest"}).WithGuest(g)
	e.Binding = &b
	a, _, err := e.Ledger.Admit(context.Background(), p, r)
	if err != nil {
		t.Fatal(err)
	}
	state := a.State
	state.Execution = Starting
	a, err = e.saveCheckpoint(context.Background(), a, Checkpoint{State: state, Reason: "executor_claim"})
	if err != nil {
		t.Fatal(err)
	}
	state.Execution, state.Capture = Unknown, Incomplete
	if _, err := e.saveCheckpoint(context.Background(), a, Checkpoint{State: state, Reason: "executor_restarted_unknown"}); err != nil {
		t.Fatal(err)
	}
	report, err := e.Ledger.Report(context.Background(), p, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if report.Checkpoint.PlatformBinding == nil || *report.Checkpoint.PlatformBinding != b || report.Checkpoint.Runtime == nil || report.Checkpoint.Runtime.Execution.Binding != b || report.Checkpoint.Runtime.Capture != nil {
		t.Fatalf("guest platform projection was lost: %+v", report.Checkpoint)
	}
	if err := e.validateSavedPlatformBinding(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.Binding.PodUID = "new-pod"
	if err := e.validateSavedPlatformBinding(context.Background()); err == nil {
		t.Fatal("same generation accepted a new Pod")
	}
}

func TestGuestRuntimeProjectionKeepsNativeCompletionRecovery(t *testing.T) {
	e, p, r := testExecutor(t)
	b := (runtimeadapter.Binding{Target: runtimeadapter.Target(r.Target), Mode: "guest"}).WithGuest(runtimeadapter.GuestIdentity{
		RuntimeClass: "kata-qemu", RuntimeHandler: "kata-qemu-runtime-rs", PodUID: "pod", ContainerID: "container", GuestBootID: "boot"})
	e.Binding = &b
	e.Capture = &NativeCapture{Capabilities: func() sensor.CapabilityReport {
		return sensor.CapabilityReport{Producer: &sensor.CapabilityProducer{Placement: "guest_kernel"}}
	}}
	a, _, err := e.Ledger.Admit(context.Background(), p, r)
	if err != nil {
		t.Fatal(err)
	}
	state := a.State
	state.Execution = Starting
	a, err = e.saveCheckpoint(context.Background(), a, Checkpoint{State: state, Reason: "executor_claim"})
	if err != nil {
		t.Fatal(err)
	}
	svc := record.Service{DB: e.Ledger.DB, Paths: e.Paths, Lifecycle: &record.Lifecycle{Prepared: func(scope record.ExecutionScope) error {
		var err error
		a, err = e.saveCheckpoint(context.Background(), a, Checkpoint{State: a.State, Reason: "scope_prepared", Scope: &scope})
		return err
	}}}
	result, err := svc.Run(record.Request{RunID: a.LocalRunID, Command: []string{"true"}, DisableSnapshot: true, PostRootGraceMS: 1})
	if err != nil {
		t.Fatal(err)
	}
	startExecutor(t, e)
	report := waitExecution(t, e, p, a.ID, Succeeded)
	if report.Checkpoint.Reason != "execution_end_recovered" || report.Checkpoint.Result == nil || report.Checkpoint.Result.EndEventID != result.EndEventID || report.Checkpoint.Runtime.Execution.Binding != b || report.Checkpoint.Runtime.Execution.State != "succeeded" {
		t.Fatalf("guest lost native recovery: %+v", report.Checkpoint)
	}
	if report.Checkpoint.Stdout.State != "unknown" || !report.Checkpoint.Runtime.Execution.Started || report.Checkpoint.Runtime.Execution.ExitCode == nil || *report.Checkpoint.Runtime.Execution.ExitCode != 0 {
		t.Fatal("guest recovery fabricated or lost output evidence")
	}
}
