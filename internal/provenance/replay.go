package provenance

import (
	"database/sql"
	"fmt"
	"io"
)

func ReplayRun(db *sql.DB, runID string, out io.Writer) error {
	if runID == "" {
		return fmt.Errorf("run_id is required")
	}
	rows, err := db.Query(`SELECT id FROM rollouts WHERE run_id = ? ORDER BY created_at ASC`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	fmt.Fprintf(out, "replay_run=%s mode=plan_only\n", runID)
	found := false
	for rows.Next() {
		found = true
		var rolloutID string
		if err := rows.Scan(&rolloutID); err != nil {
			return err
		}
		if err := printReplayRollout(db, rolloutID, out); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("run %q has no rollouts", runID)
	}
	return nil
}

func ReplayAttempt(db *sql.DB, attemptID string, out io.Writer) error {
	if attemptID == "" {
		return fmt.Errorf("attempt_id is required")
	}
	var rolloutID string
	if err := db.QueryRow(`SELECT rollout_id FROM fork_attempts WHERE id = ?`, attemptID).Scan(&rolloutID); err != nil {
		return err
	}
	fmt.Fprintf(out, "replay_attempt=%s mode=plan_only\n", attemptID)
	return printReplayAttempt(db, rolloutID, attemptID, out)
}

func printReplayRollout(db *sql.DB, rolloutID string, out io.Writer) error {
	var runID, baseSnapshotID, status, winnerAttemptID, promotionID, riskStatus string
	err := db.QueryRow(`SELECT run_id, base_snapshot_id, status, winner_attempt_id, promotion_id, risk_status
		FROM rollouts WHERE id = ?`, rolloutID).Scan(&runID, &baseSnapshotID, &status, &winnerAttemptID, &promotionID, &riskStatus)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "rollout=%s run=%s base_snapshot=%s status=%s winner=%s promotion=%s risk=%s\n",
		rolloutID, runID, baseSnapshotID, status, winnerAttemptID, promotionID, riskStatus)
	if err := printReplaySnapshot(db, baseSnapshotID, out); err != nil {
		return err
	}
	rows, err := db.Query(`SELECT id FROM fork_attempts WHERE rollout_id = ? ORDER BY is_winner DESC, created_at ASC`, rolloutID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var attemptID string
		if err := rows.Scan(&attemptID); err != nil {
			return err
		}
		if err := printReplayAttempt(db, rolloutID, attemptID, out); err != nil {
			return err
		}
	}
	return rows.Err()
}

func printReplaySnapshot(db *sql.DB, snapshotID string, out io.Writer) error {
	if snapshotID == "" {
		return nil
	}
	var name, kind, physicalType, path, manifestHash, status string
	var files, bytes, tainted int64
	err := db.QueryRow(`SELECT COALESCE(name, ''), kind, snapshot_physical_type, path, manifest_hash, file_count, bytes, status, COALESCE(tainted, 0)
		FROM snapshots WHERE id = ?`, snapshotID).Scan(&name, &kind, &physicalType, &path, &manifestHash, &files, &bytes, &status, &tainted)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "  base_snapshot name=%s kind=%s physical=%s status=%s tainted=%t files=%d bytes=%d manifest=%s path=%s\n",
		name, kind, physicalType, status, tainted != 0, files, bytes, manifestHash, path)
	return nil
}

func printReplayAttempt(db *sql.DB, rolloutID, attemptID string, out io.Writer) error {
	var snapshotID, toolCallID, workspace, strategy, command, status, risk, artifact string
	var isWinner, budgetExceeded int
	var score, cost float64
	err := db.QueryRow(`SELECT snapshot_id, tool_call_id, workspace_path, strategy, command, status, risk_status, COALESCE(artifact_result, ''),
			is_winner, budget_exceeded, score, cost_estimate
		FROM fork_attempts WHERE id = ? AND rollout_id = ?`, attemptID, rolloutID).
		Scan(&snapshotID, &toolCallID, &workspace, &strategy, &command, &status, &risk, &artifact, &isWinner, &budgetExceeded, &score, &cost)
	if err != nil {
		return err
	}
	blocked := status == "quarantined" || risk == "tainted" || budgetExceeded != 0
	fmt.Fprintf(out, "  attempt=%s snapshot=%s strategy=%s status=%s risk=%s winner=%t replay_blocked=%t score=%.3f cost=%.6f workspace=%s\n",
		attemptID, snapshotID, strategy, status, risk, isWinner != 0, blocked, score, cost, workspace)
	fmt.Fprintf(out, "    command=%q\n", command)
	if artifact != "" {
		hash, size, exists := fileDigest(artifact)
		fmt.Fprintf(out, "    artifact=%s exists=%t sha256=%s bytes=%d\n", artifact, exists, hash, size)
	}
	if toolCallID != "" {
		if err := printReplayToolCall(db, toolCallID, out); err != nil {
			return err
		}
	}
	if err := printReplayProcesses(db, attemptID, toolCallID, out); err != nil {
		return err
	}
	if err := printReplayExternalEffects(db, attemptID, toolCallID, out); err != nil {
		return err
	}
	return printReplayEvents(db, attemptID, toolCallID, out)
}

func printReplayToolCall(db *sql.DB, toolCallID string, out io.Writer) error {
	var sessionID, command, status, resultRef, policy, startedAt, endedAt string
	var exitCode, wallMS int64
	var cost float64
	err := db.QueryRow(`SELECT session_id, command, status, COALESCE(exit_code, 0), wall_ms, cost_estimate, COALESCE(result_ref, ''), policy_decision, started_at, ended_at
		FROM tool_calls WHERE id = ?`, toolCallID).Scan(&sessionID, &command, &status, &exitCode, &wallMS, &cost, &resultRef, &policy, &startedAt, &endedAt)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "    tool_call=%s session=%s status=%s exit=%d wall_ms=%d cost=%.6f policy=%s result=%s started_at=%s ended_at=%s command=%q\n",
		toolCallID, sessionID, status, exitCode, wallMS, cost, policy, resultRef, startedAt, endedAt, command)
	return nil
}

func printReplayProcesses(db *sql.DB, attemptID, toolCallID string, out io.Writer) error {
	rows, err := db.Query(`SELECT id, session_id, command, status, COALESCE(exit_code, 0), started_at, COALESCE(ended_at, '')
		FROM processes WHERE tool_call_id = ? ORDER BY started_at ASC`, toolCallID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, sessionID, command, status, startedAt, endedAt string
		var exitCode int64
		if err := rows.Scan(&id, &sessionID, &command, &status, &exitCode, &startedAt, &endedAt); err != nil {
			return err
		}
		fmt.Fprintf(out, "    process=%s session=%s status=%s exit=%d started_at=%s ended_at=%s command=%q\n",
			id, sessionID, status, exitCode, startedAt, endedAt, command)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_ = attemptID
	return nil
}

func printReplayExternalEffects(db *sql.DB, attemptID, toolCallID string, out io.Writer) error {
	rows, err := db.Query(`SELECT id, effect_type, target, mode, decision, compensation_ref, status, payload
		FROM external_effects WHERE attempt_id = ? OR tool_call_id = ? ORDER BY created_at ASC`, attemptID, toolCallID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, effectType, target, mode, decision, compensationRef, status, payload string
		if err := rows.Scan(&id, &effectType, &target, &mode, &decision, &compensationRef, &status, &payload); err != nil {
			return err
		}
		fmt.Fprintf(out, "    external_effect=%s type=%s target=%s mode=%s decision=%s compensation_ref=%s status=%s payload=%s\n",
			id, effectType, target, mode, decision, compensationRef, status, payload)
	}
	return rows.Err()
}

func printReplayEvents(db *sql.DB, attemptID, toolCallID string, out io.Writer) error {
	rows, err := db.Query(`SELECT id, event_type, source, COALESCE(process_id, ''), COALESCE(snapshot_id, ''), correlation_method, correlation_confidence, payload
		FROM events WHERE tool_call_id = ? OR payload LIKE ? ORDER BY created_at ASC`, toolCallID, "%"+attemptID+"%")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, eventType, source, processID, snapshotID, correlationMethod, payload string
		var confidence float64
		if err := rows.Scan(&id, &eventType, &source, &processID, &snapshotID, &correlationMethod, &confidence, &payload); err != nil {
			return err
		}
		fmt.Fprintf(out, "    event=%s type=%s source=%s process=%s snapshot=%s correlation=%s confidence=%.2f payload=%s\n",
			id, eventType, source, processID, snapshotID, correlationMethod, confidence, payload)
	}
	return rows.Err()
}
