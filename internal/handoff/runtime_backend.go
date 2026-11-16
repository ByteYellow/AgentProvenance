package handoff

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/byteyellow/agentprovenance/internal/runtimeadapter"
)

type RuntimeReport struct {
	Execution runtimeadapter.Execution      `json:"execution"`
	Capture   *runtimeadapter.CaptureReport `json:"capture,omitempty"`
}

// Guest uses the native scope and capture report. This projection carries the
// trusted platform identity through the same query/export contract as runsc.
func guestRuntimeReport(a Attempt, c Checkpoint, binding runtimeadapter.Binding) *RuntimeReport {
	x := runtimeadapter.NewExecution(binding, runtimeadapter.Request{Target: binding.Target, OperationID: a.Request.OperationID,
		AttemptID: a.ID, Command: record.Request{RunID: a.LocalRunID}})
	x.State = string(c.State.Execution)
	if c.Runtime != nil && c.Runtime.Execution.Binding.Mode == "guest" {
		x.Started, x.ExitCode = c.Runtime.Execution.Started, c.Runtime.Execution.ExitCode
	}
	if c.Scope != nil && c.Scope.RootPID > 0 {
		x.Started = true
	}
	if c.Result != nil && c.Result.RootPID > 0 {
		x.Started = true
	}
	if c.Result != nil && c.Result.EndEventID != "" {
		code := c.Result.ExitCode
		x.ExitCode = &code
	}
	if c.State.Execution == Unknown || c.State.Execution == Starting || c.State.Execution == Running {
		x.ExitCode = nil
	}
	return &RuntimeReport{Execution: x}
}

func (e *Executor) runtimeBinding() runtimeadapter.Binding {
	if e.Binding != nil {
		return *e.Binding
	}
	return runtimeadapter.Binding{Target: runtimeadapter.Target(e.Ledger.Target), Mode: "native"}
}

func (e *Executor) validateSavedPlatformBinding(ctx context.Context) error {
	var after int64
	for {
		attempts, err := e.attempts(ctx, []ExecutionState{Accepted, Starting, Running, Succeeded, Failed, Cancelled, Unknown}, after, 100)
		if err != nil || len(attempts) == 0 {
			return err
		}
		for _, a := range attempts {
			after = a.Sequence
			c, _, err := readCheckpoint(ctx, e.Ledger.DB, a)
			if err != nil {
				return err
			}
			if c != nil && c.PlatformBinding != nil && *c.PlatformBinding != e.runtimeBinding() {
				return fmt.Errorf("execution platform binding changed without a new target generation")
			}
		}
	}
}

func (e *Executor) validateBackend(ctx context.Context, concurrency int) error {
	b := e.runtimeBinding()
	if _, err := b.Resolve(ctx, runtimeadapter.Target(e.Ledger.Target)); err != nil {
		return err
	}
	if e.Backend == nil {
		if b.Mode == "runsc" || e.RuntimeCapture != nil {
			return fmt.Errorf("runtime execution backend is not configured")
		}
		if b.Mode == "guest" {
			if e.Capture == nil || e.Capture.Capabilities == nil {
				return fmt.Errorf("guest execution requires guest_kernel capture placement")
			}
			producer := e.Capture.Capabilities().Producer
			if producer == nil || producer.Placement != "guest_kernel" {
				return fmt.Errorf("guest execution requires guest_kernel capture placement")
			}
		}
		return nil
	}
	if b.Mode != "runsc" || concurrency != 1 || e.Capture != nil {
		return fmt.Errorf("runsc requires concurrency=1 and a separate SecCheck receiver, without native host capture")
	}
	return nil
}

func interruptedRuntime(r RuntimeReport) *RuntimeReport {
	r.Execution.State, r.Execution.ExitCode = "unknown", nil
	r.Execution.Gaps = append(append([]string{}, r.Execution.Gaps...), "executor_restart_result_unknown")
	if r.Capture != nil {
		copy := *r.Capture
		copy.State = "incomplete"
		copy.Gaps = append(append([]string{}, copy.Gaps...), "executor_restart_capture_unknown")
		r.Capture = &copy
	}
	return &r
}

func (e *Executor) executeBackend(ctx context.Context, a Attempt) error {
	policy, err := agentcontext.NewCapturePolicy(a.Request.Command.CapturePreset, a.Request.Command.ToolResults)
	if err != nil {
		return e.failAttempt(a, record.Result{}, err)
	}
	if _, err := (agentcontext.Service{DB: e.Ledger.DB, Paths: e.Paths, CapturePolicy: &policy}).EnsureCapturePolicy(ctx, a.LocalRunID); err != nil {
		return e.failAttempt(a, record.Result{}, err)
	}
	stdout, stderr := &outputBuffer{retain: policy.ToolResults}, &outputBuffer{retain: policy.ToolResults}
	cmd := a.Request.Command
	r := runtimeadapter.Request{Target: runtimeadapter.Target(a.Request.Target), OperationID: a.Request.OperationID, AttemptID: a.ID,
		Command: record.Request{RunID: a.LocalRunID, Name: "remote execution", Command: cmd.Argv, Workdir: cmd.Workdir,
			DisableSnapshot: cmd.DisableSnapshot, SampleIntervalMS: cmd.SampleIntervalMS, PostRootGraceMS: cmd.PostRootGraceMS,
			Stdout: stdout, Stderr: stderr}}
	// A lost runtime transport may leave a workload running. Serialization alone
	// is insufficient after restart: retain this fence in the authoritative ledger.
	unknown, err := e.attempts(ctx, []ExecutionState{Unknown}, 0, 1)
	if err != nil {
		return err
	}
	if len(unknown) != 0 {
		return e.failAttempt(a, record.Result{}, fmt.Errorf("runtime target has an unresolved attempt; retire its generation before executing again"))
	}
	if err := e.Backend.Admit(ctx, r); err != nil {
		return e.failAttempt(a, record.Result{}, err)
	}
	report := RuntimeReport{Execution: runtimeadapter.NewExecution(e.runtimeBinding(), r)}
	var start *runtimeadapter.CapturePoint
	if e.RuntimeCapture != nil {
		p, err := e.RuntimeCapture.Probe(ctx, r.Target)
		if err != nil {
			return e.failAttempt(a, record.Result{}, fmt.Errorf("runtime capture admission: %w", err))
		}
		start = &p
		report.Capture = &runtimeadapter.CaptureReport{ObservationLayer: "sentry", State: "collecting", Start: &p, Gaps: []string{"shared_call_identity_unavailable"}}
	} else {
		report.Capture = &runtimeadapter.CaptureReport{ObservationLayer: "sentry", State: "incomplete", Gaps: []string{"receiver_not_configured", "shared_call_identity_unavailable"}}
	}
	a, err = e.saveCheckpoint(ctx, a, Checkpoint{State: a.State, Reason: "runtime_prepared", Runtime: &report})
	if err != nil {
		return err
	}
	dispatched := false
	result, runErr := e.Backend.Run(ctx, r, func(observation runtimeadapter.Execution) error {
		dispatched = true
		if !observation.Matches(r) || observation.Binding != e.runtimeBinding() {
			return fmt.Errorf("runtime execution identity mismatch")
		}
		report.Execution = observation
		state := a.State
		state.Execution, state.Capture = Running, Collecting
		updated, err := e.saveCheckpoint(context.Background(), a, Checkpoint{State: state, Reason: "runtime_dispatched", Runtime: &report})
		if err == nil {
			a = updated
		}
		return err
	})
	validResult := result.Matches(r) && result.Binding == e.runtimeBinding()
	if !validResult {
		runErr = errors.Join(runErr, fmt.Errorf("runtime result identity mismatch"))
		result = report.Execution
		result.Gaps = append(result.Gaps, "runtime_result_identity_mismatch")
		result.State, result.ExitCode = "unknown", nil
	}
	state := a.State
	state.Execution, state.Capture = Unknown, Incomplete
	gateDenied := result.SentryPIDBasis == "private_exec_fd_gate_and_runsc_procfs" &&
		!result.Started && !result.GateReleased && result.State == "failed"
	if validResult && ((!dispatched && !result.Started) || gateDenied) {
		state.Execution = Failed
		if errors.Is(runErr, context.Canceled) {
			state.Execution = Cancelled
		}
	} else if runErr == nil && result.State == "succeeded" && result.ExitCode != nil && *result.ExitCode == 0 {
		state.Execution = Succeeded
	} else if runErr == nil && result.State == "failed" && result.ExitCode != nil && *result.ExitCode != 0 {
		state.Execution = Failed
	} else if runErr == nil && result.State == "cancelled" {
		state.Execution = Cancelled
	}
	result.State = string(state.Execution)
	if state.Execution == Unknown {
		result.ExitCode = nil
	}
	report.Execution = result
	if start != nil {
		if a.State.Capture == Collecting {
			draining := report
			draining.Execution.State, draining.Execution.ExitCode = string(a.State.Execution), nil
			capture := *draining.Capture
			capture.State = "draining"
			draining.Capture = &capture
			drainState := a.State
			drainState.Capture = Draining
			a, err = e.saveCheckpoint(context.Background(), a, Checkpoint{State: drainState, Reason: "runtime_draining", Runtime: &draining})
			if err != nil {
				return err
			}
		}
		finishCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		var capture runtimeadapter.CaptureReport
		if scoped, ok := e.RuntimeCapture.(runtimeadapter.CommandCaptureBackend); ok {
			capture = scoped.FinishCommand(finishCtx, r, result, *start)
		} else {
			capture = e.RuntimeCapture.Finish(finishCtx, r.Target, *start)
			capture.State = "incomplete"
			for _, gap := range []string{"shared_call_identity_unavailable", "command_capture_watermark_unavailable"} {
				if !slices.Contains(capture.Gaps, gap) {
					capture.Gaps = append(capture.Gaps, gap)
				}
			}
		}
		cancel()
		if capture.State == "sealed" && capture.Command != nil && capture.Evidence != nil && len(capture.Gaps) == 0 {
			state.Capture = Sealed
			// A native group-exit record resolves a failed/lost control
			// transport. Keep signal termination distinct from exit status 0.
			wait := capture.Command.RootWaitStatus
			code := -1
			if wait&0x7f == 0 {
				code = int((wait >> 8) & 0xff)
			}
			state.Execution = Failed
			if code == 0 {
				state.Execution = Succeeded
			}
			report.Execution.State, report.Execution.ExitCode = string(state.Execution), &code
			report.Execution.Gaps = slices.DeleteFunc(report.Execution.Gaps, func(gap string) bool {
				return gap == "command_capture_watermark_unavailable" || gap == "workload_completion_unknown" || gap == "transport_stopped_workload_stop_unconfirmed"
			})
		}
		report.Capture = &capture
	}
	out, outErr := e.saveOutput(a, "stdout", stdout)
	errout, errErr := e.saveOutput(a, "stderr", stderr)
	c := Checkpoint{State: state, Reason: "runtime_completed", Runtime: &report, Stdout: &out, Stderr: &errout}
	if err := errors.Join(runErr, outErr, errErr); err != nil {
		c.Error = err.Error()
	}
	_, err = e.saveCheckpoint(context.Background(), a, c)
	return err
}
