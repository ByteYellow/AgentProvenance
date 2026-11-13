package record

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"

	"github.com/byteyellow/agentprovenance/internal/ids"
	"github.com/byteyellow/agentprovenance/internal/store"
)

// ExecutionScope is prepared before exec and then enriched with the observed
// root PID and saved start event. A logical fallback cgroup is not a kernel ID.
type ExecutionScope struct {
	RunID          string `json:"run_id"`
	RolloutID      string `json:"rollout_id"`
	AttemptID      string `json:"attempt_id"`
	SessionID      string `json:"session_id"`
	ToolCallID     string `json:"tool_call_id"`
	ProcessID      string `json:"process_id"`
	BaseSnapshotID string `json:"base_snapshot_id"`
	BindingID      string `json:"binding_id"`
	CgroupID       string `json:"cgroup_id"`
	ScopeKind      string `json:"scope_kind"`
	Workdir        string `json:"workdir"`
	StartedAt      string `json:"started_at"`
	RootPID        int64  `json:"root_pid,omitempty"`
	StartEventID   string `json:"start_event_id,omitempty"`
}

// Lifecycle hooks are trusted in-process integration points, never decoded
// from an API request. A failing Prepared hook prevents command launch. A
// failing Started hook terminates and reaps the already-started process.
type Lifecycle struct {
	Prepared func(ExecutionScope) error
	Started  func(ExecutionScope) error
}

func (s Service) persistStart(scope ExecutionScope, command string) (string, error) {
	eventID := ids.New("evt")
	err := store.WithWriteTx(context.Background(), s.DB, func(tx *sql.Tx) error {
		if err := updateOne(tx, `UPDATE execution_context_bindings SET root_pid=?,pid=? WHERE id=?`,
			scope.RootPID, scope.RootPID, scope.BindingID); err != nil {
			return err
		}
		payload, err := json.Marshal(map[string]any{"attempt_id": scope.AttemptID, "command": command, "mode": "zero_sdk"})
		if err != nil {
			return err
		}
		_, err = tx.Exec(`INSERT INTO events (id,run_id,session_id,tool_call_id,process_id,source,event_type,pid,ppid,payload,created_at)
			VALUES (?,?,?,?,?,'record','exec_start',?,?,?,?)`, eventID, scope.RunID, scope.SessionID, scope.ToolCallID,
			scope.ProcessID, scope.RootPID, os.Getpid(), string(payload), scope.StartedAt)
		return err
	})
	if err != nil {
		return "", err
	}
	return eventID, nil
}

func (s Service) persistCompletion(r Result, timedOut, cancelled bool) (string, error) {
	eventID := ids.New("evt")
	err := store.WithWriteTx(context.Background(), s.DB, func(tx *sql.Tx) error {
		cost := float64(r.WallMS) / 1000.0 * 0.001
		updates := []struct {
			sql  string
			args []any
		}{
			{`UPDATE processes SET status=?,exit_code=?,ended_at=? WHERE id=?`, []any{processStatus(r.Status), r.ExitCode, r.EndedAt, r.ProcessID}},
			{`UPDATE sessions SET status='stopped',updated_at=? WHERE id=?`, []any{r.EndedAt, r.SessionID}},
			{`UPDATE tool_calls SET status=?,exit_code=?,wall_ms=?,cost_estimate=?,ended_at=? WHERE id=?`, []any{r.Status, r.ExitCode, r.WallMS, cost, r.EndedAt, r.ToolCallID}},
			{`UPDATE fork_attempts SET status=?,exit_code=?,wall_ms=?,score=?,cost_estimate=?,output_summary=?,is_winner=1 WHERE id=?`, []any{r.Status, r.ExitCode, r.WallMS, score(r.ExitCode, r.WallMS), cost, fmt.Sprintf("changed_files=%d", len(r.ChangedFiles)), r.AttemptID}},
			{`UPDATE rollouts SET status='completed',winner_attempt_id=?,cost_estimate=?,risk_status='clean',updated_at=? WHERE id=?`, []any{r.AttemptID, cost, r.EndedAt, r.RolloutID}},
		}
		for _, update := range updates {
			if err := updateOne(tx, update.sql, update.args...); err != nil {
				return err
			}
		}
		payload, err := json.Marshal(map[string]any{"attempt_id": r.AttemptID, "exit_code": r.ExitCode, "status": r.Status,
			"wall_ms": r.WallMS, "changed_files": len(r.ChangedFiles), "timed_out": timedOut, "cancelled": cancelled})
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO events (id,run_id,session_id,tool_call_id,process_id,source,event_type,pid,ppid,payload,created_at)
			VALUES (?,?,?,?,?,'record','exec_end',?,?,?,?)`, eventID, r.RunID, r.SessionID, r.ToolCallID, r.ProcessID,
			r.RootPID, os.Getpid(), string(payload), r.EndedAt); err != nil {
			return err
		}
		_, err = tx.Exec(`UPDATE execution_context_bindings SET ended_at=? WHERE process_id=? AND ended_at=''`, r.EndedAt, r.ProcessID)
		return err
	})
	if err != nil {
		return "", err
	}
	return eventID, nil
}

func updateOne(tx *sql.Tx, statement string, args ...any) error {
	result, err := tx.Exec(statement, args...)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("execution evidence update affected %d rows, expected 1", count)
	}
	return nil
}
