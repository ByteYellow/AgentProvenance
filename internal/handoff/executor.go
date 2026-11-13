package handoff

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/byteyellow/agentprovenance/internal/store"
)

const maxExecutionOutput = 1 << 20

// Executor owns durable jobs, independently of HTTP requests. The database is
// the queue; only the bounded set of running commands occupies memory.
type Executor struct {
	Ledger       Ledger
	Paths        store.Paths
	Options      record.Options
	Concurrency  int
	PollInterval time.Duration
	running      atomic.Bool
}

// Start takes an exclusive store lock before recovery. Close waits for active
// commands to be reaped and their final observations to be persisted.
func (e *Executor) Start(ctx context.Context) (func() error, error) {
	if e.Ledger.DB == nil || e.Paths.Root == "" || e.Ledger.Target.Validate() != nil || e.Options.Foreground {
		return nil, fmt.Errorf("invalid execution worker configuration")
	}
	concurrency, interval := e.Concurrency, e.PollInterval
	if concurrency == 0 {
		concurrency = 2
	}
	if interval == 0 {
		interval = 100 * time.Millisecond
	}
	if concurrency < 1 || concurrency > 32 || interval < time.Millisecond || interval > time.Second {
		return nil, fmt.Errorf("invalid execution worker bounds")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	lock, err := lockExecutor(e.Paths.Root)
	if err != nil {
		return nil, err
	}
	if err := e.recover(ctx); err != nil {
		lock.Close()
		return nil, err
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	var result error
	e.running.Store(true)
	go func() {
		defer close(done)
		defer lock.Close()
		defer e.running.Store(false)
		result = e.loop(runCtx, concurrency, interval)
	}()
	var once sync.Once
	return func() error {
		once.Do(cancel)
		<-done
		return result
	}, nil
}

func (e *Executor) Running() bool { return e.running.Load() }

type executionDone struct {
	id  string
	err error
}

func (e *Executor) loop(ctx context.Context, concurrency int, interval time.Duration) (result error) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	done := make(chan executionDone, concurrency)
	active := map[string]context.CancelFunc{}
	defer func() {
		if result == context.Canceled && ctx.Err() != nil {
			result = nil
		}
		for _, cancel := range active {
			cancel()
		}
		for range active {
			finished := <-done
			result = errors.Join(result, finished.err)
		}
	}()
	for {
		if ctx.Err() != nil {
			return nil
		}
		for id, cancel := range active {
			stop, err := e.Ledger.stopRequested(ctx, id)
			if err != nil {
				return err
			}
			if stop {
				cancel()
			}
		}
		if len(active) < concurrency {
			pending, err := e.attempts(ctx, []ExecutionState{Accepted}, 0, concurrency-len(active))
			if err != nil {
				return err
			}
			for _, a := range pending {
				stop, err := e.Ledger.stopRequested(ctx, a.ID)
				if err != nil {
					return err
				}
				state, reason := a.State, "executor_claim"
				state.Execution = Starting
				if stop {
					state.Execution, state.Capture, reason = Cancelled, Incomplete, "cancelled_before_start"
				} else if !e.Ledger.now().Before(a.Request.ValidUntil) {
					state.Execution, state.Capture, reason = Failed, Incomplete, "expired_before_start"
				}
				a, err = e.saveCheckpoint(ctx, a, Checkpoint{State: state, Reason: reason})
				if err != nil {
					return err
				}
				if state.Execution != Starting {
					continue
				}
				execCtx, cancel := context.WithCancel(ctx)
				active[a.ID] = cancel
				go func(a Attempt) { done <- executionDone{a.ID, e.execute(execCtx, a)} }(a)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case finished := <-done:
			active[finished.id]()
			delete(active, finished.id)
			if finished.err != nil {
				return finished.err
			}
		case <-ticker.C:
		}
	}
}

func (e *Executor) attempts(ctx context.Context, states []ExecutionState, after int64, limit int) ([]Attempt, error) {
	placeholders := make([]string, len(states))
	args := []any{e.Ledger.Target.ProducerID, e.Ledger.Target.InstanceID, e.Ledger.Target.Generation, after}
	for i, state := range states {
		placeholders[i] = "?"
		args = append(args, state)
	}
	args = append(args, limit)
	rows, err := e.Ledger.DB.QueryContext(ctx, attemptSelect+` WHERE json_extract(a.request_json,'$.target.producer_id')=?
		AND json_extract(a.request_json,'$.target.instance_id')=? AND json_extract(a.request_json,'$.target.generation')=?
		AND a.sequence>? AND a.execution_state IN (`+strings.Join(placeholders, ",")+`) ORDER BY a.sequence LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Attempt{}
	for rows.Next() {
		a, err := scanAttempt(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, a)
	}
	return result, rows.Err()
}

func (e *Executor) execute(ctx context.Context, a Attempt) error {
	policy, err := agentcontext.NewCapturePolicy(a.Request.Command.CapturePreset, a.Request.Command.ToolResults)
	if err != nil {
		return e.failAttempt(a, record.Result{}, err)
	}
	if _, err := (agentcontext.Service{DB: e.Ledger.DB, Paths: e.Paths, CapturePolicy: &policy}).EnsureCapturePolicy(ctx, a.LocalRunID); err != nil {
		return e.failAttempt(a, record.Result{}, err)
	}
	stdout, stderr := &outputBuffer{retain: policy.ToolResults}, &outputBuffer{retain: policy.ToolResults}
	svc := record.Service{DB: e.Ledger.DB, Paths: e.Paths, Options: e.Options, Lifecycle: &record.Lifecycle{
		Prepared: func(scope record.ExecutionScope) error {
			stop, err := e.Ledger.stopRequested(ctx, a.ID)
			if err != nil {
				return err
			}
			if stop {
				return context.Canceled
			}
			updated, err := e.saveCheckpoint(ctx, a, Checkpoint{State: a.State, Reason: "scope_prepared", Scope: &scope})
			if err == nil {
				a = updated
			}
			return err
		},
		Started: func(scope record.ExecutionScope) error {
			state := a.State
			state.Execution, state.Capture = Running, Collecting
			updated, err := e.saveCheckpoint(context.Background(), a, Checkpoint{State: state, Reason: "execution_started", Scope: &scope})
			if err == nil {
				a = updated
			}
			return err
		},
	}}
	cmd := a.Request.Command
	r, err := svc.RunContext(ctx, record.Request{RunID: a.LocalRunID, Name: "remote execution", Command: cmd.Argv,
		Workdir: cmd.Workdir, DisableSnapshot: cmd.DisableSnapshot, SampleIntervalMS: cmd.SampleIntervalMS,
		PostRootGraceMS: cmd.PostRootGraceMS, Stdout: stdout, Stderr: stderr})
	if err != nil {
		return e.failAttempt(a, r, err)
	}
	state := a.State
	state.Execution, err = observedExecution(r)
	if err != nil {
		return e.failAttempt(a, r, err)
	}
	state.Capture = Incomplete
	if a.State.Capture == Collecting {
		// A record end is not a native collector watermark. Sealing is a
		// subsequent capture operation, with its own evidence and timeout.
		state.Capture = Draining
	}
	if r.Stop != nil && (r.Stop.ScopeEmpty == nil || !*r.Stop.ScopeEmpty) {
		state.Capture = Incomplete
	}
	out, outErr := e.saveOutput(a, "stdout", stdout)
	errout, errErr := e.saveOutput(a, "stderr", stderr)
	c := Checkpoint{State: state, Reason: "execution_completed", Scope: r.Scope, Result: &r, Stdout: &out, Stderr: &errout}
	if err := errors.Join(outErr, errErr); err != nil {
		c.State.Capture, c.Error = Incomplete, err.Error()
	}
	_, err = e.saveCheckpoint(context.Background(), a, c)
	return err
}

func observedExecution(r record.Result) (ExecutionState, error) {
	if r.Stop != nil && r.Stop.ScopeEmpty != nil && !*r.Stop.ScopeEmpty {
		return Unknown, nil
	}
	switch r.Status {
	case "passed":
		if r.RootPID > 0 && r.EndEventID != "" && r.ExitCode == 0 {
			return Succeeded, nil
		}
	case "failed":
		if r.ExitCode != 0 && (r.RootPID == 0 || r.EndEventID != "") {
			return Failed, nil
		}
	case "cancelled":
		if r.RootPID == 0 || r.EndEventID != "" {
			return Cancelled, nil
		}
	}
	return Unknown, fmt.Errorf("execution result lacks terminal evidence")
}

func (e *Executor) failAttempt(a Attempt, r record.Result, cause error) error {
	state := a.State
	state.Execution, state.Capture = Failed, Incomplete
	if r.RootPID > 0 {
		state.Execution = Unknown
	} else if errors.Is(cause, context.Canceled) {
		state.Execution = Cancelled
	}
	_, err := e.saveCheckpoint(context.Background(), a, Checkpoint{State: state, Reason: "execution_interrupted",
		Scope: r.Scope, Result: &r, Error: cause.Error()})
	return err
}

func (e *Executor) recover(ctx context.Context) error {
	var after int64
	for {
		attempts, err := e.attempts(ctx, []ExecutionState{Starting, Running}, after, 100)
		if err != nil {
			return err
		}
		if len(attempts) == 0 {
			return nil
		}
		for _, a := range attempts {
			after = a.Sequence
			previous, _, err := readCheckpoint(ctx, e.Ledger.DB, a)
			if err != nil {
				return err
			}
			state := a.State
			state.Execution, state.Capture = Unknown, Incomplete
			c := Checkpoint{State: state, Reason: "executor_restarted_unknown"}
			if previous != nil && previous.Scope != nil {
				r, err := e.recoverCompletion(ctx, a, *previous.Scope)
				if err != nil {
					return err
				}
				if r != nil {
					c.Result, c.Reason = r, "execution_end_recovered"
					c.State.Execution, err = observedExecution(*r)
					if err != nil {
						return err
					}
					c.Stdout = &Output{State: "unknown", Reason: "executor_restart"}
					c.Stderr = &Output{State: "unknown", Reason: "executor_restart"}
				}
			}
			if _, err := e.saveCheckpoint(ctx, a, c); err != nil {
				return err
			}
		}
	}
}

// Recovery reads immutable local event identities, never kills a process by a
// stale PID, and never starts another command for an unresolved attempt.
func (e *Executor) recoverCompletion(ctx context.Context, a Attempt, scope record.ExecutionScope) (*record.Result, error) {
	var id, raw, ended string
	var pid int64
	err := e.Ledger.DB.QueryRowContext(ctx, `SELECT id,payload,created_at,pid FROM events
		WHERE run_id=? AND process_id=? AND tool_call_id=? AND session_id=? AND source='record' AND event_type='exec_end'`,
		a.LocalRunID, scope.ProcessID, scope.ToolCallID, scope.SessionID).Scan(&id, &raw, &ended, &pid)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var payload struct {
		AttemptID string             `json:"attempt_id"`
		Status    string             `json:"status"`
		ExitCode  int                `json:"exit_code"`
		WallMS    int64              `json:"wall_ms"`
		Stop      *record.StopReport `json:"stop_report"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil, err
	}
	if payload.AttemptID != scope.AttemptID || scope.RunID != a.LocalRunID || pid <= 0 {
		return nil, fmt.Errorf("recovered execution identity mismatch")
	}
	var startID string
	if err := e.Ledger.DB.QueryRowContext(ctx, `SELECT id FROM events WHERE run_id=? AND process_id=? AND tool_call_id=?
		AND session_id=? AND pid=? AND source='record' AND event_type='exec_start' AND json_extract(payload,'$.attempt_id')=?`,
		a.LocalRunID, scope.ProcessID, scope.ToolCallID, scope.SessionID, pid, scope.AttemptID).Scan(&startID); err != nil {
		return nil, err
	}
	scope.RootPID, scope.StartEventID = pid, startID
	return &record.Result{RunID: a.LocalRunID, RolloutID: scope.RolloutID, AttemptID: scope.AttemptID,
		SessionID: scope.SessionID, ToolCallID: scope.ToolCallID, ProcessID: scope.ProcessID, RootPID: pid,
		Workdir: scope.Workdir, StartedAt: scope.StartedAt, EndedAt: ended, EndEventID: id, Scope: &scope,
		Status: payload.Status, ExitCode: payload.ExitCode, WallMS: payload.WallMS, Stop: payload.Stop}, nil
}

type outputBuffer struct {
	retain bool
	data   []byte
	total  int64
}

func (b *outputBuffer) Write(p []byte) (int, error) {
	b.total += int64(len(p))
	if b.retain && len(b.data) < maxExecutionOutput {
		n := len(p)
		if n > maxExecutionOutput-len(b.data) {
			n = maxExecutionOutput - len(b.data)
		}
		b.data = append(b.data, p[:n]...)
	}
	return len(p), nil
}

func (e *Executor) saveOutput(a Attempt, stream string, b *outputBuffer) (Output, error) {
	observed, retained := b.total, int64(0)
	out := Output{State: "omitted", ObservedBytes: &observed, RetainedBytes: &retained, Reason: "capture_policy"}
	if !b.retain {
		return out, nil
	}
	obj, err := (provenance.ObjectStore{DB: e.Ledger.DB, Paths: e.Paths}).PutTextContent(provenance.TextContentInput{
		RunID: a.LocalRunID, SourceID: a.ID + "/" + stream, Text: strings.ToValidUTF8(string(b.data), "\uFFFD"),
	})
	if err != nil {
		out.State, out.Reason = "unavailable", "output_storage_failed"
		return out, err
	}
	out.State, out.Reason, out.Ref, out.RetainedBytes = "stored", "", obj.Ref, &obj.Bytes
	if b.total > int64(len(b.data)) {
		out.State, out.Reason = "truncated", "execution_output_limit"
	}
	return out, nil
}
