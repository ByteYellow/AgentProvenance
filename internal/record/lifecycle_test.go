package record

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestExecutionLifecycleRunsAfterSavedBindings(t *testing.T) {
	paths, db := newPolicyTestStore(t)
	prepared, started, completed := false, false, false
	var scope ExecutionScope
	svc := Service{DB: db, Paths: paths, Lifecycle: &Lifecycle{
		Prepared: func(s ExecutionScope) error {
			prepared, scope = true, s
			if s.RootPID != 0 || s.StartEventID != "" || s.BindingID == "" || s.CgroupID == "" {
				t.Fatalf("invalid prepared scope: %+v", s)
			}
			var process, call, cgroup string
			if err := db.QueryRow(`SELECT process_id,tool_call_id,cgroup_id FROM execution_context_bindings WHERE id=?`, s.BindingID).Scan(&process, &call, &cgroup); err != nil {
				return err
			}
			if process != s.ProcessID || call != s.ToolCallID || cgroup != s.CgroupID {
				t.Fatalf("scope did not match persisted binding: %+v", s)
			}
			return nil
		},
		Started: func(s ExecutionScope) error {
			started = true
			if !prepared || scope.BindingID != s.BindingID || s.RootPID <= 0 || s.StartEventID == "" {
				t.Fatalf("invalid started scope: %+v", s)
			}
			var pid int64
			if err := db.QueryRow(`SELECT pid FROM events WHERE id=? AND event_type='exec_start' AND run_id=?`, s.StartEventID, s.RunID).Scan(&pid); err != nil {
				return err
			}
			if pid != s.RootPID {
				t.Fatalf("saved PID %d != observed %d", pid, s.RootPID)
			}
			return nil
		},
		Completed: func(r Result) error {
			completed = true
			if !started || r.Scope == nil || r.Scope.BindingID != scope.BindingID || r.EndEventID == "" {
				t.Fatalf("invalid completed scope: %+v", r)
			}
			var ended string
			if err := db.QueryRow(`SELECT ended_at FROM execution_context_bindings WHERE id=?`, scope.BindingID).Scan(&ended); err != nil {
				return err
			}
			if ended == "" {
				t.Fatal("completion callback preceded persisted end")
			}
			return nil
		},
	}}
	r, err := svc.Run(Request{RunID: "lifecycle", Command: []string{"true"}, DisableSnapshot: true, PostRootGraceMS: 1, Stdout: io.Discard, Stderr: io.Discard})
	if err != nil || !prepared || !started || !completed || r.Scope == nil || r.EndEventID == "" || r.Status != "passed" {
		t.Fatalf("lifecycle: %+v %v prepared=%t started=%t completed=%t", r, err, prepared, started, completed)
	}
	var terminal string
	if err := db.QueryRow(`SELECT event_type FROM events WHERE id=?`, r.EndEventID).Scan(&terminal); err != nil || terminal != "exec_end" {
		t.Fatalf("missing completion reference: %s %v", terminal, err)
	}
}

func TestCompletedHookFailurePreservesExecutionResult(t *testing.T) {
	for _, command := range []string{"true", "false"} {
		t.Run(command, func(t *testing.T) {
			paths, db := newPolicyTestStore(t)
			failed := errors.New("capture completion unavailable")
			calls := 0
			svc := Service{DB: db, Paths: paths, Lifecycle: &Lifecycle{Completed: func(Result) error {
				calls++
				return failed
			}}}
			r, err := svc.Run(Request{RunID: "completion-error", Command: []string{command}, DisableSnapshot: true, PostRootGraceMS: 1})
			if !errors.Is(err, failed) || calls != 1 || r.EndEventID == "" {
				t.Fatalf("completion error lost: calls=%d result=%+v err=%v", calls, r, err)
			}
			var saved int
			if err := db.QueryRow(`SELECT json_extract(payload,'$.exit_code') FROM events WHERE id=?`, r.EndEventID).Scan(&saved); err != nil || saved != r.ExitCode {
				t.Fatalf("saved execution result changed: %d %+v %v", saved, r, err)
			}
		})
	}
}

func TestPreparedFailurePreventsLaunch(t *testing.T) {
	paths, db := newPolicyTestStore(t)
	refused := errors.New("handoff preparation failed")
	svc := Service{DB: db, Paths: paths, Options: Options{AllowShell: true}, Lifecycle: &Lifecycle{
		Prepared:  func(ExecutionScope) error { return refused },
		Started:   func(ExecutionScope) error { t.Fatal("started after refusal"); return nil },
		Completed: func(Result) error { t.Fatal("completed after refusal"); return nil },
	}}
	r, err := svc.Run(Request{RunID: "refused", Command: []string{"sh", "-c", "printf ran > marker"}, DisableSnapshot: true})
	if !errors.Is(err, refused) || r.Scope == nil || r.RootPID != 0 {
		t.Fatalf("preparation refusal: %+v %v", r, err)
	}
	if _, err := os.Stat(filepath.Join(paths.Workspaces, "refused", "marker")); !os.IsNotExist(err) {
		t.Fatalf("command ran: %v", err)
	}
	var ended string
	if err := db.QueryRow(`SELECT ended_at FROM execution_context_bindings WHERE id=?`, r.Scope.BindingID).Scan(&ended); err != nil || ended == "" {
		t.Fatalf("refused scope remained open: %q %v", ended, err)
	}
}

func TestStartedFailureReapsProcess(t *testing.T) {
	paths, db := newPolicyTestStore(t)
	failed := errors.New("start checkpoint unavailable")
	var pid int64
	svc := Service{DB: db, Paths: paths, Lifecycle: &Lifecycle{Started: func(scope ExecutionScope) error { pid = scope.RootPID; return failed }}}
	r, err := svc.Run(Request{RunID: "started-failure", Command: []string{"sleep", "60"}, DisableSnapshot: true})
	if !errors.Is(err, failed) || pid <= 0 || r.RootPID != pid || r.Scope.StartEventID == "" {
		t.Fatalf("start failure: %+v %v", r, err)
	}
	if err := syscall.Kill(int(pid), 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("started child still exists after callback failure: %v", err)
	}
}

func TestExecutionContextCancellation(t *testing.T) {
	paths, db := newPolicyTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc := Service{DB: db, Paths: paths, Options: Options{Timeout: time.Minute}, Lifecycle: &Lifecycle{
		Started: func(ExecutionScope) error { cancel(); return nil },
	}}
	r, err := svc.RunContext(ctx, Request{RunID: "cancel-execution", Command: []string{"sleep", "60"},
		DisableSnapshot: true, PostRootGraceMS: 1, Stdout: io.Discard, Stderr: io.Discard})
	if err != nil || r.Status != "cancelled" || r.ExitCode != 130 || r.EndEventID == "" || strings.Contains(r.FailureReason, "timed out") {
		t.Fatalf("cancelled job: %+v %v", r, err)
	}
	var payload string
	if err := db.QueryRow(`SELECT payload FROM events WHERE id=?`, r.EndEventID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload, `"cancelled":true`) || !strings.Contains(payload, `"timed_out":false`) {
		t.Fatalf("cancellation lost in completion evidence: %s", payload)
	}
	var saved struct {
		Stop *StopReport `json:"stop_report"`
	}
	if err := json.Unmarshal([]byte(payload), &saved); err != nil || saved.Stop == nil || r.Stop == nil ||
		saved.Stop.Method != r.Stop.Method || saved.Stop.RequestedAt != r.Stop.RequestedAt || saved.Stop.ObservedAt != r.Stop.ObservedAt {
		t.Fatalf("stop evidence was not saved with completion: %+v %v", saved.Stop, err)
	}
	if err := syscall.Kill(int(r.RootPID), 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("cancelled child still exists: %v", err)
	}
}

func TestCancelledExecutionContextHasNoSideEffects(t *testing.T) {
	paths, db := newPolicyTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (Service{DB: db, Paths: paths}).RunContext(ctx, Request{Command: []string{"true"}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled request: %v", err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM tool_calls`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("cancelled context created tools: %d %v", count, err)
	}
}

func TestExecutionCancelledAfterPreparation(t *testing.T) {
	paths, db := newPolicyTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc := Service{DB: db, Paths: paths, Lifecycle: &Lifecycle{
		Prepared: func(ExecutionScope) error { cancel(); return nil },
		Started:  func(ExecutionScope) error { t.Fatal("started a cancelled command"); return nil },
	}}
	r, err := svc.RunContext(ctx, Request{RunID: "prepared-cancel", Command: []string{"true"}, DisableSnapshot: true})
	if err != nil || r.RootPID != 0 || r.Status != "cancelled" || r.ExitCode != 130 {
		t.Fatalf("cancel before exec: %+v %v", r, err)
	}
	var status string
	if err := db.QueryRow(`SELECT status FROM tool_calls WHERE id=?`, r.ToolCallID).Scan(&status); err != nil || status != "cancelled" {
		t.Fatalf("stored cancellation: %s %v", status, err)
	}
}
