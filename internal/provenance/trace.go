package provenance

import (
	"database/sql"
	"fmt"
	"io"

	"github.com/byteyellow/agentprovenance/internal/security"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TraceRun(db *sql.DB, runID string, out io.Writer) error {
	if runID == "" {
		return fmt.Errorf("run_id is required")
	}
	runSnapshotIDs, err := collectRunSnapshotIDs(db, runID)
	if err != nil {
		return err
	}
	runGraphIDs, err := collectRunGraphIDs(db, runID, runSnapshotIDs)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "run_id=%s\n", runID)

	rows, err := db.Query(`SELECT id, lease_id, status, workspace_host_path, COALESCE(container_id, '') FROM sessions WHERE run_id = ? ORDER BY created_at ASC`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	fmt.Fprintln(out, "sessions:")
	for rows.Next() {
		var id, leaseID, status, workspace, containerID string
		if err := rows.Scan(&id, &leaseID, &status, &workspace, &containerID); err != nil {
			return err
		}
		fmt.Fprintf(out, "  session=%s lease=%s status=%s container=%s workspace=%s\n", id, leaseID, status, containerID, workspace)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	rolloutRows, err := db.Query(`SELECT id, status, base_snapshot_id, fanout, winner_attempt_id, promotion_id, risk_status, cost_estimate, created_at
		FROM rollouts WHERE run_id = ? ORDER BY created_at ASC`, runID)
	if err != nil {
		return err
	}
	defer rolloutRows.Close()
	fmt.Fprintln(out, "rollouts:")
	for rolloutRows.Next() {
		var id, status, baseSnapshotID, winnerAttemptID, promotionID, riskStatus, createdAt string
		var fanout int
		var cost float64
		if err := rolloutRows.Scan(&id, &status, &baseSnapshotID, &fanout, &winnerAttemptID, &promotionID, &riskStatus, &cost, &createdAt); err != nil {
			return err
		}
		fmt.Fprintf(out, "  rollout=%s status=%s base_snapshot=%s fanout=%d winner=%s promotion=%s risk=%s cost=%.6f created_at=%s\n", id, status, baseSnapshotID, fanout, winnerAttemptID, promotionID, riskStatus, cost, createdAt)
	}
	if err := rolloutRows.Err(); err != nil {
		return err
	}

	attemptRows, err := db.Query(`SELECT a.id, a.rollout_id, a.snapshot_id, a.status, COALESCE(a.risk_status, 'unknown'), COALESCE(a.budget_exceeded, 0), a.score, a.cost_estimate, a.is_winner
		FROM fork_attempts a JOIN rollouts r ON a.rollout_id = r.id
		WHERE r.run_id = ? ORDER BY a.created_at ASC`, runID)
	if err != nil {
		return err
	}
	defer attemptRows.Close()
	fmt.Fprintln(out, "attempts:")
	for attemptRows.Next() {
		var id, rolloutID, snapshotID, status, riskStatus string
		var score, cost float64
		var budgetExceeded, isWinner int
		if err := attemptRows.Scan(&id, &rolloutID, &snapshotID, &status, &riskStatus, &budgetExceeded, &score, &cost, &isWinner); err != nil {
			return err
		}
		fmt.Fprintf(out, "  attempt=%s rollout=%s snapshot=%s status=%s risk=%s budget_exceeded=%t score=%.3f cost=%.6f winner=%t\n", id, rolloutID, snapshotID, status, riskStatus, budgetExceeded != 0, score, cost, isWinner != 0)
	}
	if err := attemptRows.Err(); err != nil {
		return err
	}

	artifactRows, err := db.Query(`SELECT a.artifact_result, a.id, a.tool_call_id, a.strategy, a.is_winner
		FROM fork_attempts a JOIN rollouts r ON a.rollout_id = r.id
		WHERE r.run_id = ? AND COALESCE(a.artifact_result, '') != ''
		ORDER BY a.created_at ASC`, runID)
	if err != nil {
		return err
	}
	defer artifactRows.Close()
	fmt.Fprintln(out, "artifacts:")
	for artifactRows.Next() {
		var artifactRef, attemptID, toolCallID, strategy string
		var isWinner int
		if err := artifactRows.Scan(&artifactRef, &attemptID, &toolCallID, &strategy, &isWinner); err != nil {
			return err
		}
		fmt.Fprintf(out, "  artifact=%s attempt=%s tool_call=%s strategy=%s winner=%t\n", artifactRef, attemptID, toolCallID, strategy, isWinner != 0)
	}
	if err := artifactRows.Err(); err != nil {
		return err
	}

	toolRows, err := db.Query(`SELECT id, rollout_id, attempt_id, status, COALESCE(exit_code, 0), wall_ms, cost_estimate, policy_decision, result_ref, command
		FROM tool_calls WHERE run_id = ? ORDER BY created_at ASC`, runID)
	if err != nil {
		return err
	}
	defer toolRows.Close()
	fmt.Fprintln(out, "tool_calls:")
	for toolRows.Next() {
		var id, rolloutID, attemptID, status, policyDecision, resultRef, command string
		var exitCode int
		var wallMS int64
		var cost float64
		if err := toolRows.Scan(&id, &rolloutID, &attemptID, &status, &exitCode, &wallMS, &cost, &policyDecision, &resultRef, &command); err != nil {
			return err
		}
		fmt.Fprintf(out, "  tool_call=%s rollout=%s attempt=%s status=%s exit=%d wall_ms=%d cost=%.6f policy=%s result=%s command=%q\n",
			id, rolloutID, attemptID, status, exitCode, wallMS, cost, policyDecision, resultRef, command)
	}
	if err := toolRows.Err(); err != nil {
		return err
	}

	procRows, err := db.Query(`SELECT id, session_id, COALESCE(tool_call_id, ''), command, status, COALESCE(exit_code, 0), started_at, COALESCE(ended_at, '') FROM processes
		WHERE session_id IN (SELECT id FROM sessions WHERE run_id = ?) ORDER BY started_at ASC`, runID)
	if err != nil {
		return err
	}
	defer procRows.Close()
	fmt.Fprintln(out, "processes:")
	for procRows.Next() {
		var id, sessionID, toolCallID, command, status, startedAt, endedAt string
		var exitCode int
		if err := procRows.Scan(&id, &sessionID, &toolCallID, &command, &status, &exitCode, &startedAt, &endedAt); err != nil {
			return err
		}
		fmt.Fprintf(out, "  process=%s session=%s tool_call=%s status=%s exit=%d command=%q started_at=%s ended_at=%s\n", id, sessionID, toolCallID, status, exitCode, command, startedAt, endedAt)
	}
	if err := procRows.Err(); err != nil {
		return err
	}

	snapRows, err := db.Query(`SELECT id, COALESCE(name, ''), COALESCE(parent_id, ''), kind, status, manifest_hash, bytes FROM snapshots ORDER BY created_at ASC`)
	if err != nil {
		return err
	}
	defer snapRows.Close()
	fmt.Fprintln(out, "snapshots:")
	for snapRows.Next() {
		var id, name, parentID, kind, status, hash string
		var bytes int64
		if err := snapRows.Scan(&id, &name, &parentID, &kind, &status, &hash, &bytes); err != nil {
			return err
		}
		if !runSnapshotIDs[id] {
			continue
		}
		fmt.Fprintf(out, "  snapshot=%s name=%s kind=%s status=%s parent=%s bytes=%d hash=%s\n", id, name, kind, status, parentID, bytes, hash)
	}
	if err := snapRows.Err(); err != nil {
		return err
	}

	edgeRows, err := db.Query(`SELECT parent_id, child_id, edge_type, plan, COALESCE(plan_reason, ''), COALESCE(planner_score, 0), created_at FROM snapshot_edges ORDER BY created_at ASC`)
	if err != nil {
		return err
	}
	defer edgeRows.Close()
	fmt.Fprintln(out, "snapshot_edges:")
	for edgeRows.Next() {
		var parentID, childID, edgeType, plan, reason, createdAt string
		var score float64
		if err := edgeRows.Scan(&parentID, &childID, &edgeType, &plan, &reason, &score, &createdAt); err != nil {
			return err
		}
		if !runGraphIDs[parentID] || !runGraphIDs[childID] {
			continue
		}
		fmt.Fprintf(out, "  parent=%s child=%s type=%s plan=%s score=%.3f reason=%q created_at=%s\n", parentID, childID, edgeType, plan, score, reason, createdAt)
	}
	if err := edgeRows.Err(); err != nil {
		return err
	}

	planRows, err := db.Query(`SELECT parent_id, child_id, edge_type, plan, COALESCE(plan_reason, ''), COALESCE(planner_score, 0), created_at
		FROM snapshot_edges
		WHERE COALESCE(plan_reason, '') != ''
		ORDER BY created_at ASC`)
	if err != nil {
		return err
	}
	defer planRows.Close()
	fmt.Fprintln(out, "snapshot_plans:")
	for planRows.Next() {
		var parentID, childID, edgeType, plan, reason, createdAt string
		var score float64
		if err := planRows.Scan(&parentID, &childID, &edgeType, &plan, &reason, &score, &createdAt); err != nil {
			return err
		}
		if !runGraphIDs[parentID] || !runGraphIDs[childID] {
			continue
		}
		fmt.Fprintf(out, "  source=%s target=%s type=%s selected_plan=%s score=%.3f created_at=%s explanation=%q\n", parentID, childID, edgeType, plan, score, createdAt, reason)
	}
	if err := planRows.Err(); err != nil {
		return err
	}

	graphRows, err := db.Query(`SELECT from_id, to_id, edge_type, source_event_id, created_at FROM graph_edges WHERE run_id = ? ORDER BY created_at ASC`, runID)
	if err != nil {
		return err
	}
	defer graphRows.Close()
	fmt.Fprintln(out, "graph_edges:")
	for graphRows.Next() {
		var fromID, toID, edgeType, sourceEventID, createdAt string
		if err := graphRows.Scan(&fromID, &toID, &edgeType, &sourceEventID, &createdAt); err != nil {
			return err
		}
		fmt.Fprintf(out, "  from=%s to=%s type=%s source_event=%s created_at=%s\n", fromID, toID, edgeType, sourceEventID, createdAt)
	}
	if err := graphRows.Err(); err != nil {
		return err
	}

	evidenceRows, err := db.Query(`SELECT id, rollout_id, attempt_id, session_id, tool_call_id, snapshot_id, event_type, priority, status, created_at, COALESCE(processed_at, ''), COALESCE(payload, '')
		FROM evidence_events WHERE run_id = ? ORDER BY created_at ASC`, runID)
	if err != nil {
		return err
	}
	defer evidenceRows.Close()
	fmt.Fprintln(out, "evidence_events:")
	for evidenceRows.Next() {
		var id, rolloutID, attemptID, sessionID, toolCallID, snapshotID, eventType, priority, status, createdAt, processedAt, payload string
		if err := evidenceRows.Scan(&id, &rolloutID, &attemptID, &sessionID, &toolCallID, &snapshotID, &eventType, &priority, &status, &createdAt, &processedAt, &payload); err != nil {
			return err
		}
		fmt.Fprintf(out, "  evidence=%s rollout=%s attempt=%s session=%s tool_call=%s snapshot=%s type=%s priority=%s status=%s created_at=%s processed_at=%s payload=%s\n", id, rolloutID, attemptID, sessionID, toolCallID, snapshotID, eventType, priority, status, createdAt, processedAt, payload)
	}
	if err := evidenceRows.Err(); err != nil {
		return err
	}

	gcRows, err := db.Query(`SELECT id, rollout_id, attempt_id, status, reclaimed_bytes, reclaimed_inodes, gc_latency_ms, failure_reason
		FROM gc_jobs WHERE run_id = ? ORDER BY created_at ASC`, runID)
	if err != nil {
		return err
	}
	defer gcRows.Close()
	fmt.Fprintln(out, "gc_jobs:")
	for gcRows.Next() {
		var id, rolloutID, attemptID, status, failureReason string
		var bytes, inodes, latency int64
		if err := gcRows.Scan(&id, &rolloutID, &attemptID, &status, &bytes, &inodes, &latency, &failureReason); err != nil {
			return err
		}
		fmt.Fprintf(out, "  gc=%s rollout=%s attempt=%s status=%s reclaimed_bytes=%d reclaimed_inodes=%d gc_latency_ms=%d failure=%q\n", id, rolloutID, attemptID, status, bytes, inodes, latency, failureReason)
	}
	if err := gcRows.Err(); err != nil {
		return err
	}

	events, err := telemetry.ListEvents(db, runID, "")
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "events:")
	for _, event := range events {
		fmt.Fprintf(out, "  event=%s type=%s source=%s session=%s process=%s tool_call=%s snapshot=%s payload=%s\n",
			event.ID, event.EventType, event.Source, event.SessionID, event.ProcessID, event.ToolCallID, event.SnapshotID, event.Payload)
	}

	decisions, err := security.ListDecisions(db, runID)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "policy_decisions:")
	for _, decision := range decisions {
		fmt.Fprintf(out, "  decision=%s event=%s session=%s action=%s reason=%s created_at=%s\n",
			decision.ID, decision.EventID, decision.SessionID, decision.Decision, decision.Reason, decision.CreatedAt)
	}

	return nil
}

func TraceArtifact(db *sql.DB, artifactRef string, out io.Writer) error {
	if artifactRef == "" {
		return fmt.Errorf("artifact ref is required")
	}
	fmt.Fprintf(out, "artifact=%s\n", artifactRef)

	rows, err := db.Query(`SELECT run_id, rollout_id, from_id, edge_type, source_event_id, created_at
		FROM graph_edges WHERE to_id = ? ORDER BY created_at ASC`, artifactRef)
	if err != nil {
		return err
	}
	defer rows.Close()
	fmt.Fprintln(out, "artifact_edges:")
	seenAttempts := map[string]bool{}
	seenTools := map[string]bool{}
	seenRollouts := map[string]bool{}
	for rows.Next() {
		var runID, rolloutID, fromID, edgeType, sourceEventID, createdAt string
		if err := rows.Scan(&runID, &rolloutID, &fromID, &edgeType, &sourceEventID, &createdAt); err != nil {
			return err
		}
		fmt.Fprintf(out, "  run=%s rollout=%s from=%s to=%s type=%s source_event=%s created_at=%s\n", runID, rolloutID, fromID, artifactRef, edgeType, sourceEventID, createdAt)
		if rolloutID != "" {
			seenRollouts[rolloutID] = true
		}
		switch edgeType {
		case "attempt_artifact":
			seenAttempts[fromID] = true
		case "tool_call_artifact":
			seenTools[fromID] = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	directRows, err := db.Query(`SELECT a.id, a.rollout_id, a.tool_call_id
		FROM fork_attempts a WHERE a.artifact_result = ? ORDER BY a.created_at ASC`, artifactRef)
	if err != nil {
		return err
	}
	defer directRows.Close()
	for directRows.Next() {
		var attemptID, rolloutID, toolCallID string
		if err := directRows.Scan(&attemptID, &rolloutID, &toolCallID); err != nil {
			return err
		}
		seenAttempts[attemptID] = true
		if rolloutID != "" {
			seenRollouts[rolloutID] = true
		}
		if toolCallID != "" {
			seenTools[toolCallID] = true
		}
	}
	if err := directRows.Err(); err != nil {
		return err
	}

	fmt.Fprintln(out, "attempts:")
	for attemptID := range seenAttempts {
		if err := printArtifactAttempt(db, out, attemptID); err != nil {
			return err
		}
	}
	fmt.Fprintln(out, "tool_calls:")
	for toolCallID := range seenTools {
		if err := printArtifactToolCall(db, out, toolCallID); err != nil {
			return err
		}
	}
	fmt.Fprintln(out, "rollouts:")
	for rolloutID := range seenRollouts {
		if err := printArtifactRollout(db, out, rolloutID); err != nil {
			return err
		}
	}
	return nil
}

func TraceAttempt(db *sql.DB, attemptID string, out io.Writer) error {
	if attemptID == "" {
		return fmt.Errorf("attempt id is required")
	}
	fmt.Fprintf(out, "attempt=%s\n", attemptID)

	var rolloutID, toolCallID, artifactRef string
	err := db.QueryRow(`SELECT COALESCE(rollout_id, ''), COALESCE(tool_call_id, ''), COALESCE(artifact_result, '')
		FROM fork_attempts WHERE id = ?`, attemptID).Scan(&rolloutID, &toolCallID, &artifactRef)
	if err != nil {
		return err
	}

	fmt.Fprintln(out, "attempts:")
	if err := printArtifactAttempt(db, out, attemptID); err != nil {
		return err
	}
	fmt.Fprintln(out, "tool_calls:")
	if toolCallID != "" {
		if err := printArtifactToolCall(db, out, toolCallID); err != nil {
			return err
		}
	}
	fmt.Fprintln(out, "artifacts:")
	if artifactRef != "" {
		fmt.Fprintf(out, "  artifact=%s attempt=%s tool_call=%s\n", artifactRef, attemptID, toolCallID)
	}
	fmt.Fprintln(out, "rollouts:")
	if rolloutID != "" {
		if err := printArtifactRollout(db, out, rolloutID); err != nil {
			return err
		}
	}

	edgeRows, err := db.Query(`SELECT run_id, rollout_id, from_id, to_id, edge_type, source_event_id, created_at
		FROM graph_edges WHERE from_id = ? OR to_id = ? ORDER BY created_at ASC`, attemptID, attemptID)
	if err != nil {
		return err
	}
	defer edgeRows.Close()
	fmt.Fprintln(out, "graph_edges:")
	for edgeRows.Next() {
		var runID, edgeRolloutID, fromID, toID, edgeType, sourceEventID, createdAt string
		if err := edgeRows.Scan(&runID, &edgeRolloutID, &fromID, &toID, &edgeType, &sourceEventID, &createdAt); err != nil {
			return err
		}
		fmt.Fprintf(out, "  run=%s rollout=%s from=%s to=%s type=%s source_event=%s created_at=%s\n", runID, edgeRolloutID, fromID, toID, edgeType, sourceEventID, createdAt)
	}
	if err := edgeRows.Err(); err != nil {
		return err
	}

	evidenceRows, err := db.Query(`SELECT id, event_type, priority, status, COALESCE(processed_at, ''), COALESCE(payload, '')
		FROM evidence_events WHERE attempt_id = ? ORDER BY created_at ASC`, attemptID)
	if err != nil {
		return err
	}
	defer evidenceRows.Close()
	fmt.Fprintln(out, "evidence_events:")
	for evidenceRows.Next() {
		var id, eventType, priority, status, processedAt, payload string
		if err := evidenceRows.Scan(&id, &eventType, &priority, &status, &processedAt, &payload); err != nil {
			return err
		}
		fmt.Fprintf(out, "  evidence=%s type=%s priority=%s status=%s processed_at=%s payload=%s\n", id, eventType, priority, status, processedAt, payload)
	}
	return evidenceRows.Err()
}

func TraceToolCall(db *sql.DB, toolCallID string, out io.Writer) error {
	if toolCallID == "" {
		return fmt.Errorf("tool_call id is required")
	}
	fmt.Fprintf(out, "tool_call=%s\n", toolCallID)

	var rolloutID, attemptID, resultRef string
	err := db.QueryRow(`SELECT COALESCE(rollout_id, ''), COALESCE(attempt_id, ''), COALESCE(result_ref, '')
		FROM tool_calls WHERE id = ?`, toolCallID).Scan(&rolloutID, &attemptID, &resultRef)
	if err != nil {
		return err
	}

	fmt.Fprintln(out, "tool_calls:")
	if err := printArtifactToolCall(db, out, toolCallID); err != nil {
		return err
	}
	fmt.Fprintln(out, "attempts:")
	if attemptID != "" {
		if err := printArtifactAttempt(db, out, attemptID); err != nil {
			return err
		}
	}
	fmt.Fprintln(out, "artifacts:")
	if resultRef != "" {
		fmt.Fprintf(out, "  artifact=%s attempt=%s tool_call=%s\n", resultRef, attemptID, toolCallID)
	}
	fmt.Fprintln(out, "rollouts:")
	if rolloutID != "" {
		if err := printArtifactRollout(db, out, rolloutID); err != nil {
			return err
		}
	}

	processRows, err := db.Query(`SELECT id, session_id, command, status, COALESCE(exit_code, 0), started_at, COALESCE(ended_at, '')
		FROM processes WHERE tool_call_id = ? ORDER BY started_at ASC`, toolCallID)
	if err != nil {
		return err
	}
	defer processRows.Close()
	fmt.Fprintln(out, "processes:")
	for processRows.Next() {
		var processID, sessionID, command, status, startedAt, endedAt string
		var exitCode int
		if err := processRows.Scan(&processID, &sessionID, &command, &status, &exitCode, &startedAt, &endedAt); err != nil {
			return err
		}
		fmt.Fprintf(out, "  process=%s session=%s status=%s exit=%d command=%q started_at=%s ended_at=%s\n", processID, sessionID, status, exitCode, command, startedAt, endedAt)
	}
	if err := processRows.Err(); err != nil {
		return err
	}

	edgeRows, err := db.Query(`SELECT run_id, rollout_id, from_id, to_id, edge_type, source_event_id, created_at
		FROM graph_edges WHERE from_id = ? OR to_id = ? ORDER BY created_at ASC`, toolCallID, toolCallID)
	if err != nil {
		return err
	}
	defer edgeRows.Close()
	fmt.Fprintln(out, "graph_edges:")
	for edgeRows.Next() {
		var runID, edgeRolloutID, fromID, toID, edgeType, sourceEventID, createdAt string
		if err := edgeRows.Scan(&runID, &edgeRolloutID, &fromID, &toID, &edgeType, &sourceEventID, &createdAt); err != nil {
			return err
		}
		fmt.Fprintf(out, "  run=%s rollout=%s from=%s to=%s type=%s source_event=%s created_at=%s\n", runID, edgeRolloutID, fromID, toID, edgeType, sourceEventID, createdAt)
	}
	if err := edgeRows.Err(); err != nil {
		return err
	}

	evidenceRows, err := db.Query(`SELECT id, event_type, priority, status, COALESCE(processed_at, ''), COALESCE(payload, '')
		FROM evidence_events WHERE tool_call_id = ? ORDER BY created_at ASC`, toolCallID)
	if err != nil {
		return err
	}
	defer evidenceRows.Close()
	fmt.Fprintln(out, "evidence_events:")
	for evidenceRows.Next() {
		var id, eventType, priority, status, processedAt, payload string
		if err := evidenceRows.Scan(&id, &eventType, &priority, &status, &processedAt, &payload); err != nil {
			return err
		}
		fmt.Fprintf(out, "  evidence=%s type=%s priority=%s status=%s processed_at=%s payload=%s\n", id, eventType, priority, status, processedAt, payload)
	}
	return evidenceRows.Err()
}

func printArtifactAttempt(db *sql.DB, out io.Writer, attemptID string) error {
	var rolloutID, toolCallID, strategy, status, riskStatus string
	var score, cost float64
	var isWinner int
	err := db.QueryRow(`SELECT rollout_id, tool_call_id, strategy, status, COALESCE(risk_status, 'unknown'), score, cost_estimate, is_winner
		FROM fork_attempts WHERE id = ?`, attemptID).Scan(&rolloutID, &toolCallID, &strategy, &status, &riskStatus, &score, &cost, &isWinner)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "  attempt=%s rollout=%s tool_call=%s strategy=%s status=%s risk=%s score=%.3f cost=%.6f winner=%t\n",
		attemptID, rolloutID, toolCallID, strategy, status, riskStatus, score, cost, isWinner != 0)
	return err
}

func printArtifactToolCall(db *sql.DB, out io.Writer, toolCallID string) error {
	var rolloutID, attemptID, status, resultRef, command string
	var exitCode int
	var wallMS int64
	err := db.QueryRow(`SELECT rollout_id, attempt_id, status, COALESCE(exit_code, 0), wall_ms, result_ref, command
		FROM tool_calls WHERE id = ?`, toolCallID).Scan(&rolloutID, &attemptID, &status, &exitCode, &wallMS, &resultRef, &command)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "  tool_call=%s rollout=%s attempt=%s status=%s exit=%d wall_ms=%d result=%s command=%q\n",
		toolCallID, rolloutID, attemptID, status, exitCode, wallMS, resultRef, command)
	return err
}

func printArtifactRollout(db *sql.DB, out io.Writer, rolloutID string) error {
	var runID, status, baseSnapshotID, winnerAttemptID, riskStatus string
	var cost float64
	err := db.QueryRow(`SELECT run_id, status, base_snapshot_id, winner_attempt_id, risk_status, cost_estimate
		FROM rollouts WHERE id = ?`, rolloutID).Scan(&runID, &status, &baseSnapshotID, &winnerAttemptID, &riskStatus, &cost)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "  rollout=%s run=%s status=%s base_snapshot=%s winner=%s risk=%s cost=%.6f\n",
		rolloutID, runID, status, baseSnapshotID, winnerAttemptID, riskStatus, cost)
	return err
}

func collectRunGraphIDs(db *sql.DB, runID string, snapshotIDs map[string]bool) (map[string]bool, error) {
	ids := map[string]bool{}
	for id := range snapshotIDs {
		ids[id] = true
	}
	rows, err := db.Query(`SELECT a.id FROM fork_attempts a JOIN rollouts r ON a.rollout_id = r.id WHERE r.run_id = ?`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids[id] = true
	}
	return ids, rows.Err()
}

func collectRunSnapshotIDs(db *sql.DB, runID string) (map[string]bool, error) {
	ids := map[string]bool{}
	rows, err := db.Query(`SELECT id, COALESCE(parent_id, '') FROM snapshots WHERE session_id IN (SELECT id FROM sessions WHERE run_id = ?)`, runID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, parentID string
		if err := rows.Scan(&id, &parentID); err != nil {
			rows.Close()
			return nil, err
		}
		addSnapshotWithParents(db, ids, id)
		addSnapshotWithParents(db, ids, parentID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	rows, err = db.Query(`SELECT base_snapshot_id FROM rollouts WHERE run_id = ?`, runID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		addSnapshotWithParents(db, ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	rows, err = db.Query(`SELECT a.snapshot_id FROM fork_attempts a JOIN rollouts r ON a.rollout_id = r.id WHERE r.run_id = ?`, runID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		addSnapshotWithParents(db, ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	return ids, nil
}

func addSnapshotWithParents(db *sql.DB, ids map[string]bool, snapshotID string) {
	for snapshotID != "" && !ids[snapshotID] {
		ids[snapshotID] = true
		var parentID string
		if err := db.QueryRow(`SELECT COALESCE(parent_id, '') FROM snapshots WHERE id = ?`, snapshotID).Scan(&parentID); err != nil {
			return
		}
		snapshotID = parentID
	}
}
