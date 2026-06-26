package telemetry

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type EventWindow struct {
	RunID           string `json:"run_id"`
	SessionID       string `json:"session_id,omitempty"`
	ToolCallID      string `json:"tool_call_id,omitempty"`
	Source          string `json:"source"`
	EventType       string `json:"event_type"`
	WindowSeconds   int    `json:"window_seconds"`
	WindowStart     string `json:"window_start"`
	EventCount      int    `json:"event_count"`
	ResolvedCount   int    `json:"resolved_count"`
	UnresolvedCount int    `json:"unresolved_count"`
	HighRiskCount   int    `json:"high_risk_count"`
	UpdatedAt       string `json:"updated_at"`
}

type EventWindowFilter struct {
	RunID         string `json:"run_id,omitempty"`
	SessionID     string `json:"session_id,omitempty"`
	ToolCallID    string `json:"tool_call_id,omitempty"`
	Type          string `json:"type,omitempty"`
	Source        string `json:"source,omitempty"`
	WindowSeconds int    `json:"window_seconds,omitempty"`
}

type EventWindowResult struct {
	SchemaVersion string            `json:"schema_version"`
	Filter        EventWindowFilter `json:"filter"`
	WindowCount   int               `json:"window_count"`
	ResultSetID   string            `json:"result_set_id"`
	PageHash      string            `json:"page_hash"`
	Windows       []EventWindow     `json:"windows"`
}

type windowAccumulator struct {
	EventWindow
}

func RebuildEventWindows(db *sql.DB, runID string) (int, error) {
	runID = strings.TrimSpace(runID)
	query := `SELECT id, COALESCE(run_id, ''), COALESCE(session_id, ''), COALESCE(tool_call_id, ''),
		COALESCE(source, ''), COALESCE(event_type, ''), COALESCE(correlation_method, ''), created_at
		FROM events`
	args := []any{}
	if runID != "" {
		query += ` WHERE run_id = ?`
		args = append(args, runID)
	}
	rows, err := db.Query(query, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	windows := map[string]*windowAccumulator{}
	for rows.Next() {
		var id, eventRunID, sessionID, toolCallID, source, eventType, method, createdAt string
		if err := rows.Scan(&id, &eventRunID, &sessionID, &toolCallID, &source, &eventType, &method, &createdAt); err != nil {
			return 0, err
		}
		if strings.TrimSpace(eventRunID) == "" {
			continue
		}
		ts, err := time.Parse(time.RFC3339Nano, createdAt)
		if err != nil {
			continue
		}
		for _, seconds := range []int{10, 60} {
			start := ts.Truncate(time.Duration(seconds) * time.Second).UTC().Format(time.RFC3339Nano)
			key := strings.Join([]string{eventRunID, sessionID, toolCallID, source, eventType, fmt.Sprint(seconds), start}, "\x00")
			acc := windows[key]
			if acc == nil {
				acc = &windowAccumulator{EventWindow: EventWindow{
					RunID:         eventRunID,
					SessionID:     sessionID,
					ToolCallID:    toolCallID,
					Source:        source,
					EventType:     eventType,
					WindowSeconds: seconds,
					WindowStart:   start,
				}}
				windows[key] = acc
			}
			acc.EventCount++
			if method == "" || method == "unresolved" {
				acc.UnresolvedCount++
			} else {
				acc.ResolvedCount++
			}
			if highRiskWindowEvent(eventType) {
				acc.HighRiskCount++
			}
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if runID != "" {
		if _, err := tx.Exec(`DELETE FROM telemetry_event_windows WHERE run_id = ?`, runID); err != nil {
			return 0, err
		}
	} else {
		if _, err := tx.Exec(`DELETE FROM telemetry_event_windows`); err != nil {
			return 0, err
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, acc := range windows {
		acc.UpdatedAt = now
		if _, err := tx.Exec(`INSERT INTO telemetry_event_windows
			(run_id, session_id, tool_call_id, source, event_type, window_seconds, window_start, event_count, resolved_count, unresolved_count, high_risk_count, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			acc.RunID, acc.SessionID, acc.ToolCallID, acc.Source, acc.EventType, acc.WindowSeconds, acc.WindowStart,
			acc.EventCount, acc.ResolvedCount, acc.UnresolvedCount, acc.HighRiskCount, acc.UpdatedAt); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(windows), nil
}

func ListEventWindows(db *sql.DB, filter EventWindowFilter) (EventWindowResult, error) {
	query := `SELECT run_id, session_id, tool_call_id, source, event_type, window_seconds, window_start,
		event_count, resolved_count, unresolved_count, high_risk_count, updated_at
		FROM telemetry_event_windows`
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
	if filter.ToolCallID != "" {
		clauses = append(clauses, "tool_call_id = ?")
		args = append(args, filter.ToolCallID)
	}
	if filter.Source != "" {
		clauses = append(clauses, "source = ?")
		args = append(args, filter.Source)
	}
	if filter.Type != "" {
		clauses = append(clauses, "event_type = ?")
		args = append(args, filter.Type)
	}
	if filter.WindowSeconds != 0 {
		clauses = append(clauses, "window_seconds = ?")
		args = append(args, filter.WindowSeconds)
	}
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += ` ORDER BY window_start ASC, run_id ASC, session_id ASC, tool_call_id ASC, source ASC, event_type ASC, window_seconds ASC`
	rows, err := db.Query(query, args...)
	if err != nil {
		return EventWindowResult{}, err
	}
	defer rows.Close()
	var windows []EventWindow
	for rows.Next() {
		var item EventWindow
		if err := rows.Scan(&item.RunID, &item.SessionID, &item.ToolCallID, &item.Source, &item.EventType, &item.WindowSeconds, &item.WindowStart, &item.EventCount, &item.ResolvedCount, &item.UnresolvedCount, &item.HighRiskCount, &item.UpdatedAt); err != nil {
			return EventWindowResult{}, err
		}
		windows = append(windows, item)
	}
	if err := rows.Err(); err != nil {
		return EventWindowResult{}, err
	}
	resultSetID, pageHash, err := eventWindowIntegrity(filter, windows)
	if err != nil {
		return EventWindowResult{}, err
	}
	return EventWindowResult{
		SchemaVersion: "agentprovenance.telemetry_event_windows/v1",
		Filter:        filter,
		WindowCount:   len(windows),
		ResultSetID:   resultSetID,
		PageHash:      pageHash,
		Windows:       windows,
	}, nil
}

func highRiskWindowEvent(eventType string) bool {
	switch eventType {
	case "metadata_ip", "private_cidr", "secret_path", "abnormal_process_tree", "resource_pressure":
		return true
	default:
		return false
	}
}

func eventWindowIntegrity(filter EventWindowFilter, windows []EventWindow) (string, string, error) {
	resultRaw, err := json.Marshal(struct {
		Kind   string            `json:"kind"`
		Filter EventWindowFilter `json:"filter"`
	}{
		Kind:   "telemetry_event_windows_result_set",
		Filter: filter,
	})
	if err != nil {
		return "", "", err
	}
	pageRaw, err := json.Marshal(struct {
		Kind    string            `json:"kind"`
		Filter  EventWindowFilter `json:"filter"`
		Windows []EventWindow     `json:"windows"`
	}{
		Kind:    "telemetry_event_windows_page",
		Filter:  filter,
		Windows: windows,
	})
	if err != nil {
		return "", "", err
	}
	resultSum := sha256.Sum256(resultRaw)
	pageSum := sha256.Sum256(pageRaw)
	return "sha256:" + base64.RawURLEncoding.EncodeToString(resultSum[:]), "sha256:" + base64.RawURLEncoding.EncodeToString(pageSum[:]), nil
}
