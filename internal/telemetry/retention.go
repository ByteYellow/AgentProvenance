package telemetry

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

type RetentionOptions struct {
	RunID     string        `json:"run_id,omitempty"`
	OlderThan time.Duration `json:"-"`
	Cutoff    string        `json:"cutoff,omitempty"`
	MaxDelete int           `json:"max_delete"`
}

type RetentionResult struct {
	SchemaVersion string   `json:"schema_version"`
	RunID         string   `json:"run_id,omitempty"`
	Cutoff        string   `json:"cutoff"`
	MaxDelete     int      `json:"max_delete"`
	Scanned       int      `json:"scanned"`
	Deleted       int      `json:"deleted"`
	Protected     int      `json:"protected"`
	DeletedIDs    []string `json:"deleted_ids,omitempty"`
}

func PruneRawEvents(db *sql.DB, opts RetentionOptions) (RetentionResult, error) {
	if db == nil {
		return RetentionResult{}, fmt.Errorf("database is required")
	}
	if opts.MaxDelete <= 0 {
		opts.MaxDelete = 1000
	}
	if opts.Cutoff == "" {
		if opts.OlderThan <= 0 {
			return RetentionResult{}, fmt.Errorf("older_than or cutoff is required")
		}
		opts.Cutoff = time.Now().UTC().Add(-opts.OlderThan).Format(time.RFC3339Nano)
	}
	result := RetentionResult{
		SchemaVersion: "agentprovenance.telemetry_retention/v1",
		RunID:         opts.RunID,
		Cutoff:        opts.Cutoff,
		MaxDelete:     opts.MaxDelete,
	}
	candidates, err := retentionCandidates(db, opts)
	if err != nil {
		return RetentionResult{}, err
	}
	for _, id := range candidates {
		if result.Deleted >= opts.MaxDelete {
			break
		}
		result.Scanned++
		protected, err := eventProtected(db, id)
		if err != nil {
			return RetentionResult{}, err
		}
		if protected {
			result.Protected++
			continue
		}
		res, err := db.Exec(`DELETE FROM events WHERE id = ?`, id)
		if err != nil {
			return RetentionResult{}, err
		}
		affected, _ := res.RowsAffected()
		if affected > 0 {
			result.Deleted++
			result.DeletedIDs = append(result.DeletedIDs, id)
		}
	}
	return result, nil
}

func retentionCandidates(db *sql.DB, opts RetentionOptions) ([]string, error) {
	query := `SELECT id FROM events WHERE created_at < ?`
	args := []any{opts.Cutoff}
	if strings.TrimSpace(opts.RunID) != "" {
		query += ` AND run_id = ?`
		args = append(args, opts.RunID)
	}
	query += ` ORDER BY created_at ASC, id ASC LIMIT ?`
	args = append(args, opts.MaxDelete*10)
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func eventProtected(db *sql.DB, eventID string) (bool, error) {
	checks := []struct {
		query string
		args  []any
	}{
		{`SELECT 1 FROM policy_decisions WHERE event_id = ? LIMIT 1`, []any{eventID}},
		{`SELECT 1 FROM risk_signals WHERE event_id = ? LIMIT 1`, []any{eventID}},
		{`SELECT 1 FROM graph_edges WHERE source_event_id = ? OR from_id = ? OR to_id = ? LIMIT 1`, []any{eventID, "runtime_event/" + eventID, "runtime_event/" + eventID}},
		{`SELECT 1 FROM telemetry_batches WHERE event_ids_json LIKE ? LIMIT 1`, []any{"%" + eventID + "%"}},
	}
	for _, check := range checks {
		var one int
		err := db.QueryRow(check.query, check.args...).Scan(&one)
		if err == nil {
			return true, nil
		}
		if err != sql.ErrNoRows {
			return false, err
		}
	}
	return false, nil
}
