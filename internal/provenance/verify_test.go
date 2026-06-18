package provenance

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/effects"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestVerifyCleanRun(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	workspace := filepath.Join(root, "attempt-1")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(paths.Artifacts, "fix.patch")
	if err := os.MkdirAll(filepath.Dir(artifact), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifact, []byte("patch"), 0o644); err != nil {
		t.Fatal(err)
	}
	insertTraceSnapshot(t, db, "snap-1", "ready", now)
	if _, err := db.Exec(`INSERT INTO rollouts
		(id, run_id, base_snapshot_id, status, fanout, winner_attempt_id, promotion_id, risk_status, created_at, updated_at)
		VALUES ('rollout-1', 'run-1', 'snap-1', 'completed', 1, 'attempt-1', 'promo-1', 'clean', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO fork_attempts
		(id, rollout_id, tool_call_id, snapshot_id, workspace_path, fork_ms, status, risk_status, is_winner, artifact_result, created_at)
		VALUES ('attempt-1', 'rollout-1', 'tool-1', 'snap-1', ?, 1, 'passed', 'clean', 1, ?, ?)`, workspace, artifact, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO leases
		(id, run_id, task_path, task_yaml, status, created_at, updated_at)
		VALUES ('lease-1', 'run-1', 'task.yaml', '{}', 'allocated', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO sessions
		(id, lease_id, run_id, workspace_host_path, status, created_at, updated_at)
		VALUES ('session-1', 'lease-1', 'run-1', ?, 'stopped', ?, ?)`, workspace, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO processes
		(id, session_id, tool_call_id, command, status, exit_code, started_at, ended_at)
		VALUES ('process-1', 'session-1', 'tool-1', 'pytest -q', 'exited', 0, ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tool_calls
		(id, run_id, rollout_id, attempt_id, session_id, command, status, exit_code, result_ref, created_at)
		VALUES ('tool-1', 'run-1', 'rollout-1', 'attempt-1', 'session-1', 'pytest -q', 'passed', 0, ?, ?)`, artifact, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO promotions
		(id, rollout_id, attempt_id, base_snapshot_id, status, risk_status, reason, created_at, updated_at)
		VALUES ('promo-1', 'rollout-1', 'attempt-1', 'snap-1', 'promoted', 'clean', 'ok', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO events
		(id, run_id, session_id, tool_call_id, process_id, snapshot_id, source, event_type, payload, created_at, correlation_method, correlation_confidence)
		VALUES ('evt-1', 'run-1', 'session-1', 'tool-1', 'process-1', 'snap-1', 'wrapper', 'execve', '{}', ?, 'process_id:process_id', 1.0)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO execution_context_bindings
		(id, run_id, session_id, attempt_id, tool_call_id, process_id, started_at, ended_at, binding_source, confidence, created_at)
		VALUES ('bind-1', 'run-1', 'session-1', 'attempt-1', 'tool-1', 'process-1', ?, ?, 'test', 1.0, ?)`, now, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := effects.RecordEffect(db, effects.CreateInput{
		RunID:      "run-1",
		AttemptID:  "attempt-1",
		SessionID:  "session-1",
		ToolCallID: "tool-1",
		ProcessID:  "process-1",
		EffectType: "api_call",
		Target:     "api.example.com",
		Mode:       "dry-run",
		Decision:   "audit",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := (ObjectStore{DB: db, Paths: paths}).MaterializeRun("run-1"); err != nil {
		t.Fatal(err)
	}

	result, err := Verify(db, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if result.ErrorCount != 0 {
		t.Fatalf("verify errors=%d issues=%+v", result.ErrorCount, result.Issues)
	}
	if result.SchemaVersion != "agentprovenance.verify/v1" || result.Status != "ok" {
		t.Fatalf("unexpected verify manifest header: %+v", result)
	}

	var out bytes.Buffer
	if err := PrintVerifyResultJSON(&out, result); err != nil {
		t.Fatal(err)
	}
	var decoded VerifyResult
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SchemaVersion != "agentprovenance.verify/v1" || decoded.RunID != "run-1" || decoded.Status != "ok" {
		t.Fatalf("unexpected verify json: %+v", decoded)
	}
}

func TestVerifyRejectsContextDrift(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	workspace := filepath.Join(root, "attempt-1")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	insertTraceSnapshot(t, db, "snap-1", "ready", now)
	if _, err := db.Exec(`INSERT INTO rollouts
		(id, run_id, base_snapshot_id, status, fanout, winner_attempt_id, promotion_id, risk_status, created_at, updated_at)
		VALUES ('rollout-1', 'run-1', 'snap-1', 'completed', 1, 'attempt-1', 'promo-1', 'clean', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO fork_attempts
		(id, rollout_id, tool_call_id, snapshot_id, workspace_path, fork_ms, status, risk_status, is_winner, created_at)
		VALUES ('attempt-1', 'rollout-1', 'tool-1', 'snap-1', ?, 1, 'passed', 'clean', 1, ?)`, workspace, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO leases
		(id, run_id, task_path, task_yaml, status, created_at, updated_at)
		VALUES ('lease-1', 'run-1', 'task.yaml', '{}', 'allocated', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO sessions
		(id, lease_id, run_id, workspace_host_path, status, created_at, updated_at)
		VALUES ('session-1', 'lease-1', 'run-1', ?, 'stopped', ?, ?)`, workspace, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tool_calls
		(id, run_id, rollout_id, attempt_id, session_id, command, status, exit_code, created_at)
		VALUES ('tool-1', 'run-1', 'rollout-1', 'attempt-1', 'session-1', 'pytest -q', 'passed', 0, ?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tool_calls
		(id, run_id, rollout_id, attempt_id, session_id, command, status, exit_code, created_at)
		VALUES ('tool-2', 'run-1', 'rollout-1', 'attempt-1', 'session-1', 'other', 'passed', 0, ?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO processes
		(id, session_id, tool_call_id, command, status, exit_code, started_at, ended_at)
		VALUES ('process-1', 'session-1', 'tool-1', 'pytest -q', 'exited', 0, ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO promotions
		(id, rollout_id, attempt_id, base_snapshot_id, status, risk_status, reason, created_at, updated_at)
		VALUES ('promo-1', 'rollout-1', 'attempt-1', 'snap-1', 'promoted', 'clean', 'ok', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO execution_context_bindings
		(id, run_id, session_id, attempt_id, tool_call_id, process_id, started_at, ended_at, binding_source, confidence, created_at)
		VALUES ('bind-1', 'run-1', 'session-1', 'attempt-1', 'tool-2', 'process-1', ?, ?, 'test', 1.0, ?)`, now, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO events
		(id, run_id, session_id, tool_call_id, process_id, snapshot_id, source, event_type, payload, created_at, correlation_method, correlation_confidence)
		VALUES ('evt-1', 'run-1', 'session-1', 'tool-2', 'process-1', 'snap-1', 'wrapper', 'execve', '{}', ?, 'process_id:process_id', 1.0)`, now); err != nil {
		t.Fatal(err)
	}

	result, err := Verify(db, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if result.ErrorCount == 0 {
		t.Fatalf("expected context drift errors, got %+v", result)
	}
	var foundBinding, foundEvent bool
	for _, issue := range result.Issues {
		if issue.Kind == "binding_process_tool_call_mismatch" {
			foundBinding = true
		}
		if issue.Kind == "event_process_tool_call_mismatch" {
			foundEvent = true
		}
	}
	if !foundBinding || !foundEvent {
		t.Fatalf("expected binding and event mismatch issues, got %+v", result.Issues)
	}
}

func TestVerifyRejectsTaintedWinner(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	insertTraceSnapshot(t, db, "snap-1", "ready", now)
	if _, err := db.Exec(`INSERT INTO rollouts
		(id, run_id, base_snapshot_id, status, fanout, winner_attempt_id, risk_status, created_at, updated_at)
		VALUES ('rollout-1', 'run-1', 'snap-1', 'completed', 1, 'attempt-1', 'clean', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO fork_attempts
		(id, rollout_id, snapshot_id, workspace_path, fork_ms, status, risk_status, is_winner, created_at)
		VALUES ('attempt-1', 'rollout-1', 'snap-1', ?, 1, 'quarantined', 'tainted', 1, ?)`, filepath.Join(root, "attempt-1"), now); err != nil {
		t.Fatal(err)
	}

	result, err := Verify(db, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if result.ErrorCount == 0 {
		t.Fatalf("expected tainted winner error, got %+v", result)
	}
	if result.Status != "failed" {
		t.Fatalf("expected failed status, got %+v", result)
	}
	found := false
	for _, issue := range result.Issues {
		if issue.Kind == "tainted_winner" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected tainted_winner issue, got %+v", result.Issues)
	}
}
