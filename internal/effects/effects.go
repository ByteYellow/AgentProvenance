package effects

import (
	"database/sql"
	"fmt"
	"io"
	"time"

	"github.com/byteyellow/agentprovenance/internal/ids"
)

type Record struct {
	ID              string
	RunID           string
	RolloutID       string
	AttemptID       string
	SessionID       string
	ToolCallID      string
	ProcessID       string
	EffectType      string
	Target          string
	Mode            string
	Decision        string
	CompensationRef string
	Payload         string
	Status          string
	CreatedAt       string
}

type CreateInput struct {
	RunID           string
	RolloutID       string
	AttemptID       string
	SessionID       string
	ToolCallID      string
	ProcessID       string
	EffectType      string
	Target          string
	Mode            string
	Decision        string
	CompensationRef string
	Payload         string
}

type Filter struct {
	RunID      string
	AttemptID  string
	ToolCallID string
}

func RecordEffect(db *sql.DB, input CreateInput) (Record, error) {
	if input.RunID == "" {
		return Record{}, fmt.Errorf("run_id is required")
	}
	if input.EffectType == "" {
		return Record{}, fmt.Errorf("effect type is required")
	}
	if input.Target == "" {
		return Record{}, fmt.Errorf("target is required")
	}
	if !validMode(input.Mode) {
		return Record{}, fmt.Errorf("mode must be one of dry-run, mock, allowlist, compensation")
	}
	if !validDecision(input.Decision) {
		return Record{}, fmt.Errorf("decision must be one of allow, deny, audit")
	}
	if input.Payload == "" {
		input.Payload = "{}"
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	record := Record{
		ID:              ids.New("effect"),
		RunID:           input.RunID,
		RolloutID:       input.RolloutID,
		AttemptID:       input.AttemptID,
		SessionID:       input.SessionID,
		ToolCallID:      input.ToolCallID,
		ProcessID:       input.ProcessID,
		EffectType:      input.EffectType,
		Target:          input.Target,
		Mode:            input.Mode,
		Decision:        input.Decision,
		CompensationRef: input.CompensationRef,
		Payload:         input.Payload,
		Status:          "recorded",
		CreatedAt:       now,
	}
	if _, err := db.Exec(`INSERT INTO external_effects
		(id, run_id, rollout_id, attempt_id, session_id, tool_call_id, process_id, effect_type, target, mode, decision, compensation_ref, payload, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.ID, record.RunID, record.RolloutID, record.AttemptID, record.SessionID, record.ToolCallID, record.ProcessID,
		record.EffectType, record.Target, record.Mode, record.Decision, record.CompensationRef, record.Payload, record.Status, record.CreatedAt); err != nil {
		return Record{}, err
	}
	return record, nil
}

func List(db *sql.DB, filter Filter) ([]Record, error) {
	query := `SELECT id, run_id, rollout_id, attempt_id, session_id, tool_call_id, process_id, effect_type, target, mode, decision, compensation_ref, payload, status, created_at FROM external_effects`
	args := []any{}
	clauses := []string{}
	if filter.RunID != "" {
		clauses = append(clauses, "run_id = ?")
		args = append(args, filter.RunID)
	}
	if filter.AttemptID != "" {
		clauses = append(clauses, "attempt_id = ?")
		args = append(args, filter.AttemptID)
	}
	if filter.ToolCallID != "" {
		clauses = append(clauses, "tool_call_id = ?")
		args = append(args, filter.ToolCallID)
	}
	for i, clause := range clauses {
		if i == 0 {
			query += " WHERE "
		} else {
			query += " AND "
		}
		query += clause
	}
	query += " ORDER BY created_at ASC"
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []Record
	for rows.Next() {
		var record Record
		if err := rows.Scan(&record.ID, &record.RunID, &record.RolloutID, &record.AttemptID, &record.SessionID, &record.ToolCallID, &record.ProcessID,
			&record.EffectType, &record.Target, &record.Mode, &record.Decision, &record.CompensationRef, &record.Payload, &record.Status, &record.CreatedAt); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func Print(records []Record, out io.Writer) {
	for _, record := range records {
		fmt.Fprintf(out, "effect=%s run=%s attempt=%s tool_call=%s process=%s type=%s target=%s mode=%s decision=%s compensation_ref=%s status=%s created_at=%s payload=%s\n",
			record.ID, record.RunID, record.AttemptID, record.ToolCallID, record.ProcessID, record.EffectType, record.Target, record.Mode, record.Decision, record.CompensationRef, record.Status, record.CreatedAt, record.Payload)
	}
}

func validMode(mode string) bool {
	switch mode {
	case "dry-run", "mock", "allowlist", "compensation":
		return true
	default:
		return false
	}
}

func validDecision(decision string) bool {
	switch decision {
	case "allow", "deny", "audit":
		return true
	default:
		return false
	}
}
