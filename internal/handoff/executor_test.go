package handoff

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func testExecutor(t *testing.T) (*Executor, Principal, Request) {
	t.Helper()
	l, p, r, paths := testLedger(t)
	r.Command = Command{Argv: []string{"printf", "hello from executor"}, DisableSnapshot: true, PostRootGraceMS: 1}
	return &Executor{Ledger: l, Paths: paths, PollInterval: 5 * time.Millisecond}, p, r
}

func startExecutor(t *testing.T, e *Executor) func() error {
	t.Helper()
	stop, err := e.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := stop(); err != nil {
			t.Error(err)
		}
	})
	return stop
}

func waitExecution(t *testing.T, e *Executor, p Principal, id string, state ExecutionState) Report {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var r Report
	for time.Now().Before(deadline) {
		var err error
		r, err = e.Ledger.Report(context.Background(), p, id)
		if err != nil {
			t.Fatal(err)
		}
		if r.Attempt.State.Execution == state {
			return r
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("execution did not reach %s: %+v", state, r)
	return r
}

func TestExecutorRunsAdmittedCommandOnce(t *testing.T) {
	e, p, request := testExecutor(t)
	ctx := context.Background()
	a, _, err := e.Ledger.Admit(ctx, p, request)
	if err != nil {
		t.Fatal(err)
	}
	stop := startExecutor(t, e)
	r := waitExecution(t, e, p, a.ID, Succeeded)
	if r.Checkpoint == nil || r.Checkpoint.Scope == nil || r.Checkpoint.Result.EndEventID == "" || r.CheckpointRef == "" {
		t.Fatalf("missing actual execution evidence: %+v", r)
	}
	if r.Attempt.State.Capture != Draining || r.Attempt.State.Delivery != Pending {
		t.Fatalf("command exit prematurely sealed or acknowledged evidence: %+v", r.Attempt.State)
	}
	if r.Checkpoint.Stdout.State != "stored" || *r.Checkpoint.Stdout.ObservedBytes != 19 {
		t.Fatalf("stdout: %+v", r.Checkpoint.Stdout)
	}
	page, err := provenance.ReadTextContentPage(e.Ledger.DB, a.LocalRunID, r.Checkpoint.Stdout.Ref, 0, 1024)
	if err != nil || page.Content != "hello from executor" {
		t.Fatalf("saved stdout: %+v %v", page, err)
	}
	if replay, reused, err := e.Ledger.Admit(ctx, p, request); err != nil || !reused || replay.ID != a.ID {
		t.Fatalf("replay admission: %+v %t %v", replay, reused, err)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if count := rowCount(t, e.Ledger.DB, "tool_calls"); count != 1 {
		t.Fatalf("same operation ran %d times", count)
	}
	startExecutor(t, e)
	if count := rowCount(t, e.Ledger.DB, "tool_calls"); count != 1 {
		t.Fatalf("restart reran terminal operation %d times", count)
	}
}

func TestExecutorStopIsDurableAndIdempotent(t *testing.T) {
	for _, beforeStart := range []bool{true, false} {
		t.Run(fmt.Sprintf("before_start_%t", beforeStart), func(t *testing.T) {
			e, p, r := testExecutor(t)
			r.Command.Argv = []string{"sleep", "60"}
			a, _, err := e.Ledger.Admit(context.Background(), p, r)
			if err != nil {
				t.Fatal(err)
			}
			if !beforeStart {
				startExecutor(t, e)
				waitExecution(t, e, p, a.ID, Running)
			}
			receipt, err := e.Ledger.RequestStop(context.Background(), p, a.ID, "stop-1")
			if err != nil || receipt.State != "requested" {
				t.Fatalf("stop receipt: %+v %v", receipt, err)
			}
			again, err := e.Ledger.RequestStop(context.Background(), p, a.ID, "stop-1")
			if err != nil || again != receipt || rowCount(t, e.Ledger.DB, "execution_stop_requests") != 1 {
				t.Fatalf("repeated stop: %+v %v", again, err)
			}
			if beforeStart {
				// Reopen the actual database before starting its worker.
				if err := e.Ledger.DB.Close(); err != nil {
					t.Fatal(err)
				}
				e.Ledger.DB, err = store.Open(e.Paths)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { e.Ledger.DB.Close() })
				startExecutor(t, e)
			}
			report := waitExecution(t, e, p, a.ID, Cancelled)
			if !report.StopRequested {
				t.Fatal("stop request disappeared")
			}
			if beforeStart && rowCount(t, e.Ledger.DB, "tool_calls") != 0 {
				t.Fatal("cancelled queued command started")
			}
			if !beforeStart && (report.Checkpoint.Result.ExitCode != 130 || report.Checkpoint.Result.EndEventID == "") {
				t.Fatalf("stop lacks observed completion: %+v", report.Checkpoint)
			}
		})
	}
}

func TestStopAuthorizationAndOperationConflict(t *testing.T) {
	e, p, r := testExecutor(t)
	ctx := context.Background()
	a, _, _ := e.Ledger.Admit(ctx, p, r)
	foreign := p
	foreign.ID = "other-router"
	if _, err := e.Ledger.RequestStop(ctx, foreign, a.ID, "stop"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("foreign stop: %v", err)
	}
	if _, err := e.Ledger.RequestStop(ctx, p, a.ID, "stop"); err != nil {
		t.Fatal(err)
	}
	r.DispatchID, r.OperationID = "d2", "o2"
	b, _, _ := e.Ledger.Admit(ctx, p, r)
	if _, err := e.Ledger.RequestStop(ctx, p, b.ID, "stop"); !errors.Is(err, ErrConflict) {
		t.Fatalf("stop key reused across attempts: %v", err)
	}
	if _, err := e.Ledger.Report(ctx, foreign, a.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("foreign report: %v", err)
	}
}

func TestWorkerLockPreventsLiveRecovery(t *testing.T) {
	e, p, r := testExecutor(t)
	r.Command.Argv = []string{"sleep", "60"}
	a, _, _ := e.Ledger.Admit(context.Background(), p, r)
	stop := startExecutor(t, e)
	before := waitExecution(t, e, p, a.ID, Running)
	if other, err := e.Start(context.Background()); err == nil {
		other()
		t.Fatal("second worker acquired the store")
	}
	after, err := e.Ledger.Get(context.Background(), p, a.ID)
	if err != nil || after.Revision != before.Attempt.Revision || after.State.Execution != Running {
		t.Fatalf("second worker changed active state: %+v %v", after, err)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	finished := waitExecution(t, e, p, a.ID, Cancelled)
	if finished.Checkpoint.Result.EndEventID == "" {
		t.Fatal("shutdown returned before completion was saved")
	}
}

func TestExecutorUnknownClaimDoesNotRerun(t *testing.T) {
	e, p, r := testExecutor(t)
	a, _, _ := e.Ledger.Admit(context.Background(), p, r)
	if _, err := e.Ledger.AdvanceExecution(context.Background(), a.ID, a.Revision, Starting, "simulated_start_gap", nil); err != nil {
		t.Fatal(err)
	}
	startExecutor(t, e)
	report := waitExecution(t, e, p, a.ID, Unknown)
	if report.Checkpoint.Reason != "executor_restarted_unknown" || rowCount(t, e.Ledger.DB, "tool_calls") != 0 {
		t.Fatalf("unknown start was replayed: %+v", report)
	}
	// Only a new explicit operation may execute again.
	r.OperationID, r.PreviousAttemptID = "explicit-retry", a.ID
	b, _, err := e.Ledger.Admit(context.Background(), p, r)
	if err != nil || b.ID == a.ID || b.Number != 2 {
		t.Fatalf("explicit retry: %+v %v", b, err)
	}
	waitExecution(t, e, p, b.ID, Succeeded)
	if rowCount(t, e.Ledger.DB, "tool_calls") != 1 {
		t.Fatal("explicit retry executed more than once")
	}
}

func TestExecutorRecoversSavedEndWithoutReexecution(t *testing.T) {
	for _, savedStart := range []bool{false, true} {
		t.Run(fmt.Sprintf("saved_start_%t", savedStart), func(t *testing.T) {
			testRecoveredCompletion(t, savedStart)
		})
	}
}

func TestObservedExecutionDoesNotDeclarePopulatedScopeStopped(t *testing.T) {
	for _, status := range []string{"cancelled", "failed", "passed"} {
		empty := false
		r := record.Result{Status: status, RootPID: 42, EndEventID: "end", ExitCode: 130,
			Stop: &record.StopReport{Method: "cgroup_kill", SignalSent: true, ScopeEmpty: &empty}}
		got, err := observedExecution(r)
		if err != nil || got != Unknown {
			t.Fatalf("populated scope became terminal %s: %s %v", status, got, err)
		}
	}
}

func TestExecutorRecoversStopReport(t *testing.T) {
	e, p, request := testExecutor(t)
	request.Command.Argv = []string{"sleep", "60"}
	a, _, err := e.Ledger.Admit(context.Background(), p, request)
	if err != nil {
		t.Fatal(err)
	}
	state := a.State
	state.Execution = Starting
	a, err = e.saveCheckpoint(context.Background(), a, Checkpoint{State: state, Reason: "executor_claim"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc := record.Service{DB: e.Ledger.DB, Paths: e.Paths, Lifecycle: &record.Lifecycle{
		Prepared: func(scope record.ExecutionScope) error {
			var err error
			a, err = e.saveCheckpoint(context.Background(), a, Checkpoint{State: a.State, Reason: "scope_prepared", Scope: &scope})
			return err
		},
		Started: func(record.ExecutionScope) error { cancel(); return nil },
	}}
	r, err := svc.RunContext(ctx, record.Request{RunID: a.LocalRunID, Command: request.Command.Argv,
		DisableSnapshot: true, PostRootGraceMS: 1, Stdout: io.Discard, Stderr: io.Discard})
	if err != nil || r.Stop == nil {
		t.Fatalf("stopped result: %+v %v", r, err)
	}
	startExecutor(t, e)
	report := waitExecution(t, e, p, a.ID, Cancelled)
	want, _ := json.Marshal(r.Stop)
	got, _ := json.Marshal(report.Checkpoint.Result.Stop)
	if string(want) != string(got) || report.Attempt.State.Capture != Incomplete {
		t.Fatalf("recovery changed stop evidence: %s -> %s", want, got)
	}
}

func testRecoveredCompletion(t *testing.T, savedStart bool) {
	t.Helper()
	e, p, request := testExecutor(t)
	e.Options.AllowShell = true
	request.Command.Argv = []string{"sh", "-c", "printf x >> marker"}
	a, _, _ := e.Ledger.Admit(context.Background(), p, request)
	state := a.State
	state.Execution = Starting
	a, err := e.saveCheckpoint(context.Background(), a, Checkpoint{State: state, Reason: "executor_claim"})
	if err != nil {
		t.Fatal(err)
	}
	// Save scope and start normally, but omit the handoff completion to model
	// a crash after record committed exec_end and before the worker caught up.
	svc := record.Service{DB: e.Ledger.DB, Paths: e.Paths, Options: e.Options, Lifecycle: &record.Lifecycle{
		Prepared: func(scope record.ExecutionScope) error {
			var err error
			a, err = e.saveCheckpoint(context.Background(), a, Checkpoint{State: a.State, Reason: "scope_prepared", Scope: &scope})
			return err
		},
		Started: func(scope record.ExecutionScope) error {
			if !savedStart {
				return nil
			}
			state := a.State
			state.Execution, state.Capture = Running, Collecting
			var err error
			a, err = e.saveCheckpoint(context.Background(), a, Checkpoint{State: state, Reason: "execution_started", Scope: &scope})
			return err
		},
	}}
	result, err := svc.Run(record.Request{RunID: a.LocalRunID, Command: request.Command.Argv, DisableSnapshot: true,
		PostRootGraceMS: 1, Stdout: io.Discard, Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	startExecutor(t, e)
	report := waitExecution(t, e, p, a.ID, Succeeded)
	if report.Checkpoint.Result.EndEventID != result.EndEventID || report.Checkpoint.Reason != "execution_end_recovered" ||
		report.Checkpoint.Stdout.State != "unknown" || report.Checkpoint.Stdout.ObservedBytes != nil || report.Attempt.State.Capture != Incomplete {
		t.Fatalf("recovery lost evidence boundaries: %+v", report.Checkpoint)
	}
	marker, err := os.ReadFile(filepath.Join(result.Workdir, "marker"))
	if err != nil || string(marker) != "x" {
		t.Fatalf("recovery repeated side effect: %q %v", marker, err)
	}
}

func TestUpgradeLedger21PreservesPendingExecution(t *testing.T) {
	e, p, request := testExecutor(t)
	ctx := context.Background()
	a, _, err := e.Ledger.Admit(ctx, p, request)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`DROP TABLE execution_stop_requests`,
		`DELETE FROM schema_versions WHERE version>21`,
	} {
		if _, err := e.Ledger.DB.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Ledger.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Init(e.Paths.Root); err != nil {
		t.Fatal(err)
	}
	e.Ledger.DB, err = store.Open(e.Paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Ledger.DB.Close() })
	retained, reused, err := e.Ledger.Admit(ctx, p, request)
	if err != nil || !reused || retained.ID != a.ID || retained.RequestHash != a.RequestHash || retained.Revision != a.Revision {
		t.Fatalf("upgrade changed pending execution: %+v %t %v", retained, reused, err)
	}
	if rowCount(t, e.Ledger.DB, "execution_attempt_history") != 1 {
		t.Fatal("upgrade changed execution history")
	}
	if _, err := e.Ledger.RequestStop(ctx, p, a.ID, "stop-after-upgrade"); err != nil {
		t.Fatal(err)
	}
	startExecutor(t, e)
	waitExecution(t, e, p, a.ID, Cancelled)
	if rowCount(t, e.Ledger.DB, "tool_calls") != 0 {
		t.Fatal("upgrade reexecuted a stopped operation")
	}
}

func TestExecutorRetentionAndOutputLimit(t *testing.T) {
	for _, preset := range []string{"basic", "detailed"} {
		t.Run(preset, func(t *testing.T) {
			e, p, r := testExecutor(t)
			r.Command.CapturePreset = preset
			a, _, _ := e.Ledger.Admit(context.Background(), p, r)
			startExecutor(t, e)
			report := waitExecution(t, e, p, a.ID, Succeeded)
			out := report.Checkpoint.Stdout
			if preset == "basic" && (out.Ref != "" || out.State != "omitted" || out.Reason != "capture_policy") {
				t.Fatalf("basic retained body: %+v", out)
			}
			if preset == "detailed" && (out.Ref == "" || out.State != "stored") {
				t.Fatalf("detailed lost body: %+v", out)
			}
			buffer := &outputBuffer{retain: true}
			input := strings.Repeat("a", maxExecutionOutput+123)
			if n, err := buffer.Write([]byte(input)); err != nil || n != len(input) || len(buffer.data) != maxExecutionOutput {
				t.Fatal("output buffer was not bounded or blocked the producer")
			}
			output, err := e.saveOutput(a, "large", buffer)
			if err != nil || output.State != "truncated" || *output.ObservedBytes != int64(len(input)) || *output.RetainedBytes > maxExecutionOutput {
				t.Fatalf("truncation lost: %+v %v", output, err)
			}
		})
	}
}

func TestExecutorConcurrentCommandsStayInSeparateRuns(t *testing.T) {
	e, p, r := testExecutor(t)
	r.Command.Argv = []string{"sleep", "60"}
	var attempts []Attempt
	for i := 0; i < 3; i++ {
		r.DispatchID, r.OperationID, r.Source.ToolCallID = fmt.Sprint("d", i), fmt.Sprint("o", i), fmt.Sprint("t", i)
		a, _, err := e.Ledger.Admit(context.Background(), p, r)
		if err != nil {
			t.Fatal(err)
		}
		attempts = append(attempts, a)
	}
	startExecutor(t, e)
	a := waitExecution(t, e, p, attempts[0].ID, Running)
	b := waitExecution(t, e, p, attempts[1].ID, Running)
	c, err := e.Ledger.Get(context.Background(), p, attempts[2].ID)
	if err != nil || c.State.Execution != Accepted {
		t.Fatalf("concurrency bound exceeded: %+v %v", c, err)
	}
	if a.Checkpoint.Scope.RootPID == b.Checkpoint.Scope.RootPID || a.Checkpoint.Scope.ToolCallID == b.Checkpoint.Scope.ToolCallID ||
		a.Checkpoint.Scope.RunID == b.Checkpoint.Scope.RunID || a.Checkpoint.Source.ToolCallID == b.Checkpoint.Source.ToolCallID {
		t.Fatal("same-command identity collided")
	}
	for _, attempt := range attempts {
		if _, err := e.Ledger.RequestStop(context.Background(), p, attempt.ID, "stop-"+attempt.ID); err != nil {
			t.Fatal(err)
		}
	}
	for _, attempt := range attempts {
		waitExecution(t, e, p, attempt.ID, Cancelled)
	}
}

func TestExecutorCheckpointFailurePreventsLaunch(t *testing.T) {
	e, p, r := testExecutor(t)
	a, _, _ := e.Ledger.Admit(context.Background(), p, r)
	if _, err := e.Ledger.DB.Exec(`CREATE TRIGGER fail_execution_checkpoint BEFORE INSERT ON provenance_objects
		WHEN NEW.object_type='execution_checkpoint' AND NEW.source_id LIKE '%/00000000000000000003'
		BEGIN SELECT RAISE(ABORT,'checkpoint unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	stop, err := e.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Scope preparation creates the local records; the failing checkpoint must
	// stop launch and leave the claimed attempt available to restart recovery.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var count int
		if err := e.Ledger.DB.QueryRow(`SELECT COUNT(*) FROM events WHERE event_type='exec_error'`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := stop(); err == nil || !strings.Contains(err.Error(), "checkpoint unavailable") {
		t.Fatalf("worker lost checkpoint failure: %v", err)
	}
	var started int
	if err := e.Ledger.DB.QueryRow(`SELECT COUNT(*) FROM events WHERE event_type='exec_start'`).Scan(&started); err != nil || started != 0 {
		t.Fatalf("command started without checkpoint: %d %v", started, err)
	}
	if _, err := e.Ledger.DB.Exec(`DROP TRIGGER fail_execution_checkpoint`); err != nil {
		t.Fatal(err)
	}
	startExecutor(t, e)
	waitExecution(t, e, p, a.ID, Unknown)
}

func TestExecutorRejectsExpiredQueueAndPreservesOtherGeneration(t *testing.T) {
	e, p, r := testExecutor(t)
	a, _, err := e.Ledger.Admit(context.Background(), p, r)
	if err != nil {
		t.Fatal(err)
	}
	e.Ledger.Now = func() time.Time { return r.ValidUntil.Add(time.Second) }
	stop := startExecutor(t, e)
	failed := waitExecution(t, e, p, a.ID, Failed)
	if failed.Checkpoint.Reason != "expired_before_start" || rowCount(t, e.Ledger.DB, "tool_calls") != 0 {
		t.Fatal("expired queued command started")
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	e.Ledger.Now = func() time.Time { return r.ValidUntil.Add(-time.Hour) }
	r.DispatchID, r.OperationID = "other-generation", "other-generation"
	b, _, err := e.Ledger.Admit(context.Background(), p, r)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Ledger.AdvanceExecution(context.Background(), b.ID, b.Revision, Starting, "old_generation_claim", nil)
	if err != nil {
		t.Fatal(err)
	}
	e.Ledger.Target.Generation = "new-generation"
	stopNew := startExecutor(t, e)
	if err := stopNew(); err != nil {
		t.Fatal(err)
	}
	unchanged, err := e.Ledger.Get(context.Background(), p, b.ID)
	if err != nil || unchanged.State.Execution != Starting || unchanged.Revision != 2 {
		t.Fatalf("new generation recovered another generation: %+v %v", unchanged, err)
	}
}
