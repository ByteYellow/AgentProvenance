package handoff

import (
	"context"
	"time"

	"github.com/byteyellow/agentprovenance/internal/record"
)

type recoveredExecution struct {
	attempt  Attempt
	scope    *record.RecoveredScope
	deadline time.Time
}

func recoverScope(scope record.ExecutionScope) (*record.RecoveredScope, *ScopeRecoveryReport) {
	live, err := record.OpenRecoveredScope(scope)
	if err != nil {
		return nil, &ScopeRecoveryReport{Observation: &record.ScopeObservation{
			ScopeKind: scope.ScopeKind, CgroupID: scope.CgroupID, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), Error: err.Error(),
		}}
	}
	o := live.Observe()
	if o.Empty == nil || *o.Empty {
		live.Close()
		return nil, &ScopeRecoveryReport{Observation: o}
	}
	return live, &ScopeRecoveryReport{Observation: o}
}

// After a crash the new worker can observe and stop the owned scope, but it
// cannot wait on the old root or recover lost stdout/exit status from a PID.
func (e *Executor) monitorRecovered(ctx context.Context, task recoveredExecution, interval time.Duration) error {
	defer task.scope.Close()
	if !task.deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, task.deadline)
		defer cancel()
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var stop *record.StopReport
	var observation *record.ScopeObservation
	for {
		if ctx.Err() != nil {
			stop = task.scope.Stop()
		}
		observation = task.scope.Observe()
		if stop != nil || observation.Empty == nil || *observation.Empty {
			break
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
	state := task.attempt.State
	state.Execution, state.Capture = Unknown, Incomplete
	reason := "recovered_scope_ended_unknown"
	if stop != nil {
		reason = "recovered_scope_stop_unconfirmed"
		if stop.SignalSent && stop.ScopeEmpty != nil && *stop.ScopeEmpty {
			state.Execution, reason = Cancelled, "recovered_scope_stopped"
			if ctx.Err() == context.DeadlineExceeded {
				state.Execution, reason = Failed, "recovered_scope_timed_out"
			}
		}
	}
	c := Checkpoint{State: state, Reason: reason, Recovery: &ScopeRecoveryReport{Observation: observation, Stop: stop},
		Stdout: &Output{State: "unknown", Reason: "executor_restart"}, Stderr: &Output{State: "unknown", Reason: "executor_restart"}}
	if _, err := e.saveCheckpoint(context.Background(), task.attempt, c); err != nil {
		return err
	}
	return nil
}
