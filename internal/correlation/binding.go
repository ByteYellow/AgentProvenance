package correlation

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/byteyellow/agentprovenance/internal/ids"
)

type Binding struct {
	ID            string
	RunID         string
	SessionID     string
	AttemptID     string
	ToolCallID    string
	ProcessID     string
	ContainerID   string
	CgroupID      string
	RootPID       int64
	PID           int64
	StartedAt     string
	EndedAt       string
	BindingSource string
	Confidence    float64
}

type RawIdentity struct {
	ProcessID   string
	ContainerID string
	CgroupID    string
	PID         int64
	TGID        int64
	PPID        int64
	Timestamp   string
}

type Match struct {
	Binding
	Method     string
	Confidence float64
}

type BindingFilter struct {
	RunID      string
	SessionID  string
	AttemptID  string
	ToolCallID string
	ProcessID  string
}

func RecordBinding(db *sql.DB, binding Binding) (string, error) {
	if binding.StartedAt == "" {
		binding.StartedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if binding.BindingSource == "" {
		binding.BindingSource = "control_plane"
	}
	if binding.Confidence <= 0 {
		binding.Confidence = 1
	}
	if binding.ID == "" {
		binding.ID = ids.New("bind")
	}
	_, err := db.Exec(`INSERT INTO execution_context_bindings
		(id, run_id, session_id, attempt_id, tool_call_id, process_id, container_id, cgroup_id, root_pid, pid, started_at, ended_at, binding_source, confidence, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		binding.ID, binding.RunID, binding.SessionID, binding.AttemptID, binding.ToolCallID, binding.ProcessID, binding.ContainerID, binding.CgroupID, binding.RootPID, binding.PID, binding.StartedAt, binding.EndedAt, binding.BindingSource, binding.Confidence, time.Now().UTC().Format(time.RFC3339Nano))
	return binding.ID, err
}

func ListBindings(db *sql.DB, filter BindingFilter) ([]Binding, error) {
	query := `SELECT id, run_id, session_id, attempt_id, tool_call_id, process_id, container_id, cgroup_id, root_pid, pid, started_at, ended_at, binding_source, confidence
		FROM execution_context_bindings`
	args := []any{}
	clauses := []string{}
	if filter.RunID != "" {
		clauses = append(clauses, "run_id = ?")
		args = append(args, filter.RunID)
	}
	if filter.SessionID != "" {
		clauses = append(clauses, "session_id = ?")
		args = append(args, filter.SessionID)
	}
	if filter.AttemptID != "" {
		clauses = append(clauses, "attempt_id = ?")
		args = append(args, filter.AttemptID)
	}
	if filter.ToolCallID != "" {
		clauses = append(clauses, "tool_call_id = ?")
		args = append(args, filter.ToolCallID)
	}
	if filter.ProcessID != "" {
		clauses = append(clauses, "process_id = ?")
		args = append(args, filter.ProcessID)
	}
	if len(clauses) > 0 {
		query += " WHERE " + clauses[0]
		for i := 1; i < len(clauses); i++ {
			query += " AND " + clauses[i]
		}
	}
	query += " ORDER BY started_at ASC, created_at ASC"
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var bindings []Binding
	for rows.Next() {
		var binding Binding
		if err := rows.Scan(&binding.ID, &binding.RunID, &binding.SessionID, &binding.AttemptID, &binding.ToolCallID, &binding.ProcessID, &binding.ContainerID, &binding.CgroupID, &binding.RootPID, &binding.PID, &binding.StartedAt, &binding.EndedAt, &binding.BindingSource, &binding.Confidence); err != nil {
			return nil, err
		}
		bindings = append(bindings, binding)
	}
	return bindings, rows.Err()
}

func CloseBinding(db *sql.DB, processID, endedAt string) error {
	if processID == "" {
		return nil
	}
	if endedAt == "" {
		endedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	_, err := db.Exec(`UPDATE execution_context_bindings SET ended_at = ? WHERE process_id = ? AND ended_at = ''`, endedAt, processID)
	return err
}

func Resolve(db *sql.DB, raw RawIdentity) (Match, bool, error) {
	at := raw.Timestamp
	if at == "" {
		at = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if raw.ProcessID != "" {
		match, ok, err := resolveByProcess(db, raw.ProcessID)
		if err != nil || ok {
			return match, ok, err
		}
	}
	if raw.CgroupID != "" {
		match, ok, err := resolveByCgroup(db, raw.CgroupID, at)
		if err != nil || ok {
			return match, ok, err
		}
	}
	if raw.ContainerID != "" {
		match, ok, err := resolveByContainer(db, raw.ContainerID, at)
		if err != nil || ok {
			return match, ok, err
		}
	}
	if raw.PID != 0 {
		match, ok, err := resolveByPID(db, raw.PID, at)
		if err != nil || ok {
			return match, ok, err
		}
	}
	return Match{}, false, nil
}

func resolveByProcess(db *sql.DB, processID string) (Match, bool, error) {
	return scanOne(db, "process_id", "process_id", 1, `SELECT id, run_id, session_id, attempt_id, tool_call_id, process_id, container_id, cgroup_id, root_pid, pid, started_at, ended_at, binding_source, confidence
		FROM execution_context_bindings WHERE process_id = ? ORDER BY created_at DESC LIMIT 1`, processID)
}

func resolveByCgroup(db *sql.DB, cgroupID, at string) (Match, bool, error) {
	return scanOne(db, "cgroup_time_window", "cgroup_id+time", 0.98, `SELECT id, run_id, session_id, attempt_id, tool_call_id, process_id, container_id, cgroup_id, root_pid, pid, started_at, ended_at, binding_source, confidence
		FROM execution_context_bindings
		WHERE cgroup_id = ? AND started_at <= ? AND (ended_at = '' OR ended_at >= ?)
		ORDER BY started_at DESC LIMIT 1`, cgroupID, at, at)
}

func resolveByContainer(db *sql.DB, containerID, at string) (Match, bool, error) {
	return scanOne(db, "container_time_window", "container_id+time", 0.92, `SELECT id, run_id, session_id, attempt_id, tool_call_id, process_id, container_id, cgroup_id, root_pid, pid, started_at, ended_at, binding_source, confidence
		FROM execution_context_bindings
		WHERE container_id = ? AND started_at <= ? AND (ended_at = '' OR ended_at >= ?)
		ORDER BY started_at DESC LIMIT 1`, containerID, at, at)
}

func resolveByPID(db *sql.DB, pid int64, at string) (Match, bool, error) {
	return scanOne(db, "pid_time_window", "pid+time", 0.85, `SELECT id, run_id, session_id, attempt_id, tool_call_id, process_id, container_id, cgroup_id, root_pid, pid, started_at, ended_at, binding_source, confidence
		FROM execution_context_bindings
		WHERE (pid = ? OR root_pid = ?) AND started_at <= ? AND (ended_at = '' OR ended_at >= ?)
		ORDER BY started_at DESC LIMIT 1`, pid, pid, at, at)
}

func scanOne(db *sql.DB, method, source string, confidence float64, query string, args ...any) (Match, bool, error) {
	var item Binding
	err := db.QueryRow(query, args...).Scan(&item.ID, &item.RunID, &item.SessionID, &item.AttemptID, &item.ToolCallID, &item.ProcessID, &item.ContainerID, &item.CgroupID, &item.RootPID, &item.PID, &item.StartedAt, &item.EndedAt, &item.BindingSource, &item.Confidence)
	if err == sql.ErrNoRows {
		return Match{}, false, nil
	}
	if err != nil {
		return Match{}, false, err
	}
	if item.Confidence > 0 && item.Confidence < confidence {
		confidence = item.Confidence
	}
	return Match{Binding: item, Method: method + ":" + source, Confidence: confidence}, true, nil
}

func EventPayloadWithCorrelation(payload string, match Match, resolved bool) string {
	if payload == "" {
		payload = "{}"
	}
	if !resolved {
		return fmt.Sprintf(`{"raw":%s,"correlation":{"method":"unresolved","confidence":0}}`, payload)
	}
	return fmt.Sprintf(`{"raw":%s,"correlation":{"binding_id":%q,"method":%q,"confidence":%.2f}}`, payload, match.ID, match.Method, match.Confidence)
}
