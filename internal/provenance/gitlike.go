package provenance

import (
	"database/sql"
	"fmt"
	"io"
	"sort"
)

type logEntry struct {
	At      string
	Kind    string
	ID      string
	Summary string
}

func Refs(db *sql.DB, runID string, out io.Writer) error {
	if runID == "" {
		return fmt.Errorf("run_id is required")
	}
	fmt.Fprintf(out, "run=%s\n", runID)

	rolloutRows, err := db.Query(`SELECT id, base_snapshot_id, winner_attempt_id, promotion_id, status, risk_status, created_at
		FROM rollouts WHERE run_id = ? ORDER BY created_at ASC`, runID)
	if err != nil {
		return err
	}
	defer rolloutRows.Close()
	fmt.Fprintln(out, "refs:")
	for rolloutRows.Next() {
		var rolloutID, baseSnapshotID, winnerAttemptID, promotionID, status, riskStatus, createdAt string
		if err := rolloutRows.Scan(&rolloutID, &baseSnapshotID, &winnerAttemptID, &promotionID, &status, &riskStatus, &createdAt); err != nil {
			return err
		}
		fmt.Fprintf(out, "  ref=rollouts/%s target=%s status=%s risk=%s created_at=%s\n", rolloutID, rolloutID, status, riskStatus, createdAt)
		if baseSnapshotID != "" {
			fmt.Fprintf(out, "  ref=snapshots/base/%s target=%s rollout=%s\n", rolloutID, baseSnapshotID, rolloutID)
		}
		if winnerAttemptID != "" {
			fmt.Fprintf(out, "  ref=attempts/winner/%s target=%s rollout=%s\n", rolloutID, winnerAttemptID, rolloutID)
		}
		if promotionID != "" {
			fmt.Fprintf(out, "  ref=promotions/%s target=%s rollout=%s\n", promotionID, promotionID, rolloutID)
		}
	}
	if err := rolloutRows.Err(); err != nil {
		return err
	}

	attemptRows, err := db.Query(`SELECT a.id, a.rollout_id, a.tool_call_id, a.snapshot_id, a.status, a.is_winner, COALESCE(a.artifact_result, '')
		FROM fork_attempts a JOIN rollouts r ON a.rollout_id = r.id
		WHERE r.run_id = ? ORDER BY a.created_at ASC`, runID)
	if err != nil {
		return err
	}
	defer attemptRows.Close()
	for attemptRows.Next() {
		var attemptID, rolloutID, toolCallID, snapshotID, status, artifactRef string
		var isWinner int
		if err := attemptRows.Scan(&attemptID, &rolloutID, &toolCallID, &snapshotID, &status, &isWinner, &artifactRef); err != nil {
			return err
		}
		fmt.Fprintf(out, "  ref=attempts/%s target=%s rollout=%s snapshot=%s tool_call=%s status=%s winner=%t\n",
			attemptID, attemptID, rolloutID, snapshotID, toolCallID, status, isWinner != 0)
		if artifactRef != "" {
			fmt.Fprintf(out, "  ref=artifacts/%s target=%s attempt=%s tool_call=%s\n", attemptID, artifactRef, attemptID, toolCallID)
		}
	}
	if err := attemptRows.Err(); err != nil {
		return err
	}

	toolRows, err := db.Query(`SELECT id, rollout_id, attempt_id, session_id, status, COALESCE(result_ref, '')
		FROM tool_calls WHERE run_id = ? ORDER BY created_at ASC`, runID)
	if err != nil {
		return err
	}
	defer toolRows.Close()
	for toolRows.Next() {
		var toolCallID, rolloutID, attemptID, sessionID, status, resultRef string
		if err := toolRows.Scan(&toolCallID, &rolloutID, &attemptID, &sessionID, &status, &resultRef); err != nil {
			return err
		}
		fmt.Fprintf(out, "  ref=tool_calls/%s target=%s rollout=%s attempt=%s session=%s status=%s result=%s\n",
			toolCallID, toolCallID, rolloutID, attemptID, sessionID, status, resultRef)
	}
	if err := toolRows.Err(); err != nil {
		return err
	}

	processRows, err := db.Query(`SELECT p.id, p.session_id, COALESCE(p.tool_call_id, ''), p.status, COALESCE(p.exit_code, 0)
		FROM processes p JOIN sessions s ON p.session_id = s.id
		WHERE s.run_id = ? ORDER BY p.started_at ASC`, runID)
	if err != nil {
		return err
	}
	defer processRows.Close()
	for processRows.Next() {
		var processID, sessionID, toolCallID, status string
		var exitCode int
		if err := processRows.Scan(&processID, &sessionID, &toolCallID, &status, &exitCode); err != nil {
			return err
		}
		fmt.Fprintf(out, "  ref=processes/%s target=%s session=%s tool_call=%s status=%s exit=%d\n",
			processID, processID, sessionID, toolCallID, status, exitCode)
	}
	return processRows.Err()
}

func Log(db *sql.DB, runID string, out io.Writer) error {
	if runID == "" {
		return fmt.Errorf("run_id is required")
	}
	entries := []logEntry{}
	if err := appendRolloutEntries(db, runID, &entries); err != nil {
		return err
	}
	if err := appendAttemptEntries(db, runID, &entries); err != nil {
		return err
	}
	if err := appendToolCallEntries(db, runID, &entries); err != nil {
		return err
	}
	if err := appendProcessEntries(db, runID, &entries); err != nil {
		return err
	}
	if err := appendPromotionEntries(db, runID, &entries); err != nil {
		return err
	}
	if err := appendEvidenceEntries(db, runID, &entries); err != nil {
		return err
	}
	if err := appendEventEntries(db, runID, &entries); err != nil {
		return err
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].At == entries[j].At {
			return entries[i].Kind < entries[j].Kind
		}
		return entries[i].At < entries[j].At
	})
	fmt.Fprintf(out, "run=%s\n", runID)
	fmt.Fprintln(out, "log:")
	for _, entry := range entries {
		fmt.Fprintf(out, "  %s %-12s %s %s\n", entry.At, entry.Kind, entry.ID, entry.Summary)
	}
	return nil
}

func appendRolloutEntries(db *sql.DB, runID string, entries *[]logEntry) error {
	rows, err := db.Query(`SELECT id, status, base_snapshot_id, fanout, winner_attempt_id, promotion_id, risk_status, cost_estimate, created_at, updated_at
		FROM rollouts WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, status, baseSnapshotID, winnerAttemptID, promotionID, riskStatus, createdAt, updatedAt string
		var fanout int
		var cost float64
		if err := rows.Scan(&id, &status, &baseSnapshotID, &fanout, &winnerAttemptID, &promotionID, &riskStatus, &cost, &createdAt, &updatedAt); err != nil {
			return err
		}
		*entries = append(*entries, logEntry{At: createdAt, Kind: "rollout", ID: id, Summary: fmt.Sprintf("start base=%s fanout=%d", baseSnapshotID, fanout)})
		*entries = append(*entries, logEntry{At: updatedAt, Kind: "rollout", ID: id, Summary: fmt.Sprintf("status=%s winner=%s promotion=%s risk=%s cost=%.6f", status, winnerAttemptID, promotionID, riskStatus, cost)})
	}
	return rows.Err()
}

func appendAttemptEntries(db *sql.DB, runID string, entries *[]logEntry) error {
	rows, err := db.Query(`SELECT a.id, a.rollout_id, a.tool_call_id, a.snapshot_id, a.status, a.score, a.cost_estimate, a.is_winner, a.created_at
		FROM fork_attempts a JOIN rollouts r ON a.rollout_id = r.id WHERE r.run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, rolloutID, toolCallID, snapshotID, status, createdAt string
		var score, cost float64
		var isWinner int
		if err := rows.Scan(&id, &rolloutID, &toolCallID, &snapshotID, &status, &score, &cost, &isWinner, &createdAt); err != nil {
			return err
		}
		*entries = append(*entries, logEntry{At: createdAt, Kind: "attempt", ID: id, Summary: fmt.Sprintf("rollout=%s snapshot=%s tool_call=%s status=%s score=%.3f cost=%.6f winner=%t", rolloutID, snapshotID, toolCallID, status, score, cost, isWinner != 0)})
	}
	return rows.Err()
}

func appendToolCallEntries(db *sql.DB, runID string, entries *[]logEntry) error {
	rows, err := db.Query(`SELECT id, rollout_id, attempt_id, session_id, status, COALESCE(exit_code, 0), wall_ms, COALESCE(result_ref, ''), created_at, COALESCE(ended_at, '')
		FROM tool_calls WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, rolloutID, attemptID, sessionID, status, resultRef, createdAt, endedAt string
		var exitCode int
		var wallMS int64
		if err := rows.Scan(&id, &rolloutID, &attemptID, &sessionID, &status, &exitCode, &wallMS, &resultRef, &createdAt, &endedAt); err != nil {
			return err
		}
		*entries = append(*entries, logEntry{At: createdAt, Kind: "tool_call", ID: id, Summary: fmt.Sprintf("rollout=%s attempt=%s session=%s status=%s", rolloutID, attemptID, sessionID, status)})
		if endedAt != "" {
			*entries = append(*entries, logEntry{At: endedAt, Kind: "tool_call", ID: id, Summary: fmt.Sprintf("exit=%d wall_ms=%d result=%s", exitCode, wallMS, resultRef)})
		}
	}
	return rows.Err()
}

func appendProcessEntries(db *sql.DB, runID string, entries *[]logEntry) error {
	rows, err := db.Query(`SELECT p.id, p.session_id, COALESCE(p.tool_call_id, ''), p.status, COALESCE(p.exit_code, 0), p.started_at, COALESCE(p.ended_at, '')
		FROM processes p JOIN sessions s ON p.session_id = s.id WHERE s.run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, sessionID, toolCallID, status, startedAt, endedAt string
		var exitCode int
		if err := rows.Scan(&id, &sessionID, &toolCallID, &status, &exitCode, &startedAt, &endedAt); err != nil {
			return err
		}
		*entries = append(*entries, logEntry{At: startedAt, Kind: "process", ID: id, Summary: fmt.Sprintf("session=%s tool_call=%s status=started", sessionID, toolCallID)})
		if endedAt != "" {
			*entries = append(*entries, logEntry{At: endedAt, Kind: "process", ID: id, Summary: fmt.Sprintf("session=%s tool_call=%s status=%s exit=%d", sessionID, toolCallID, status, exitCode)})
		}
	}
	return rows.Err()
}

func appendPromotionEntries(db *sql.DB, runID string, entries *[]logEntry) error {
	rows, err := db.Query(`SELECT p.id, p.rollout_id, p.attempt_id, p.status, p.risk_status, p.reason,
		COALESCE(p.telemetry_watermark, ''), COALESCE(p.drain_processed, 0), COALESCE(p.drain_pending_after, 0),
		p.created_at, p.updated_at
		FROM promotions p JOIN rollouts r ON p.rollout_id = r.id WHERE r.run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, rolloutID, attemptID, status, riskStatus, reason, watermark, createdAt, updatedAt string
		var drainProcessed, drainPendingAfter int
		if err := rows.Scan(&id, &rolloutID, &attemptID, &status, &riskStatus, &reason, &watermark, &drainProcessed, &drainPendingAfter, &createdAt, &updatedAt); err != nil {
			return err
		}
		*entries = append(*entries, logEntry{At: createdAt, Kind: "promotion", ID: id, Summary: fmt.Sprintf("rollout=%s attempt=%s candidate", rolloutID, attemptID)})
		*entries = append(*entries, logEntry{At: updatedAt, Kind: "promotion", ID: id, Summary: fmt.Sprintf("status=%s risk=%s watermark=%s drain_processed=%d drain_pending_after=%d reason=%q", status, riskStatus, watermark, drainProcessed, drainPendingAfter, reason)})
	}
	return rows.Err()
}

func appendEvidenceEntries(db *sql.DB, runID string, entries *[]logEntry) error {
	rows, err := db.Query(`SELECT id, rollout_id, attempt_id, tool_call_id, snapshot_id, event_type, priority, status, created_at
		FROM evidence_events WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, rolloutID, attemptID, toolCallID, snapshotID, eventType, priority, status, createdAt string
		if err := rows.Scan(&id, &rolloutID, &attemptID, &toolCallID, &snapshotID, &eventType, &priority, &status, &createdAt); err != nil {
			return err
		}
		*entries = append(*entries, logEntry{At: createdAt, Kind: "evidence", ID: id, Summary: fmt.Sprintf("type=%s priority=%s status=%s rollout=%s attempt=%s tool_call=%s snapshot=%s", eventType, priority, status, rolloutID, attemptID, toolCallID, snapshotID)})
	}
	return rows.Err()
}

func appendEventEntries(db *sql.DB, runID string, entries *[]logEntry) error {
	rows, err := db.Query(`SELECT id, event_type, source, COALESCE(session_id, ''), COALESCE(tool_call_id, ''), COALESCE(process_id, ''), COALESCE(snapshot_id, ''), created_at
		FROM events WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, eventType, source, sessionID, toolCallID, processID, snapshotID, createdAt string
		if err := rows.Scan(&id, &eventType, &source, &sessionID, &toolCallID, &processID, &snapshotID, &createdAt); err != nil {
			return err
		}
		*entries = append(*entries, logEntry{At: createdAt, Kind: "event", ID: id, Summary: fmt.Sprintf("type=%s source=%s session=%s tool_call=%s process=%s snapshot=%s", eventType, source, sessionID, toolCallID, processID, snapshotID)})
	}
	return rows.Err()
}
