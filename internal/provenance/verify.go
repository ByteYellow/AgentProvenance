package provenance

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

type VerifyIssue struct {
	Severity string `json:"severity"`
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Message  string `json:"message"`
}

type VerifyResult struct {
	SchemaVersion string        `json:"schema_version"`
	RunID         string        `json:"run_id"`
	Status        string        `json:"status"`
	IssueCount    int           `json:"issue_count"`
	ErrorCount    int           `json:"error_count"`
	WarningCount  int           `json:"warning_count"`
	Issues        []VerifyIssue `json:"issues"`
}

func VerifyRun(db *sql.DB, runID string, out io.Writer) error {
	result, err := Verify(db, runID)
	if err != nil {
		return err
	}
	PrintVerifyResult(out, result)
	if result.ErrorCount > 0 {
		return fmt.Errorf("graph verify failed: errors=%d warnings=%d", result.ErrorCount, result.WarningCount)
	}
	return nil
}

func VerifyRunJSON(db *sql.DB, runID string, out io.Writer) error {
	result, err := Verify(db, runID)
	if err != nil {
		return err
	}
	if err := PrintVerifyResultJSON(out, result); err != nil {
		return err
	}
	if result.ErrorCount > 0 {
		return fmt.Errorf("graph verify failed: errors=%d warnings=%d", result.ErrorCount, result.WarningCount)
	}
	return nil
}

func Verify(db *sql.DB, runID string) (VerifyResult, error) {
	if runID == "" {
		return VerifyResult{}, fmt.Errorf("run_id is required")
	}
	result := VerifyResult{SchemaVersion: "agentprovenance.verify/v1", RunID: runID, Status: "ok"}
	add := func(severity, kind, id, format string, args ...any) {
		result.Issues = append(result.Issues, VerifyIssue{
			Severity: severity,
			Kind:     kind,
			ID:       id,
			Message:  fmt.Sprintf(format, args...),
		})
		result.IssueCount++
		if severity == "error" {
			result.ErrorCount++
		} else {
			result.WarningCount++
		}
	}
	if err := verifyRollouts(db, runID, add); err != nil {
		return result, err
	}
	if err := verifyAttempts(db, runID, add); err != nil {
		return result, err
	}
	if err := verifyToolCalls(db, runID, add); err != nil {
		return result, err
	}
	if err := verifyProcesses(db, runID, add); err != nil {
		return result, err
	}
	if err := verifyEvents(db, runID, add); err != nil {
		return result, err
	}
	if err := verifyExternalEffects(db, runID, add); err != nil {
		return result, err
	}
	if err := verifyExecutionContextBindings(db, runID, add); err != nil {
		return result, err
	}
	if err := verifyReplayManifest(db, runID, add); err != nil {
		return result, err
	}
	if err := verifyObjects(db, runID, add); err != nil {
		return result, err
	}
	if result.ErrorCount > 0 {
		result.Status = "failed"
	}
	return result, nil
}

func PrintVerifyResult(out io.Writer, result VerifyResult) {
	status := "ok"
	if result.ErrorCount > 0 {
		status = "failed"
	}
	fmt.Fprintf(out, "run=%s status=%s errors=%d warnings=%d issues=%d\n", result.RunID, status, result.ErrorCount, result.WarningCount, result.IssueCount)
	for _, issue := range result.Issues {
		fmt.Fprintf(out, "issue severity=%s kind=%s id=%s message=%q\n", issue.Severity, issue.Kind, issue.ID, issue.Message)
	}
}

func PrintVerifyResultJSON(out io.Writer, result VerifyResult) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

type issueAdder func(severity, kind, id, format string, args ...any)

func verifyRollouts(db *sql.DB, runID string, add issueAdder) error {
	rows, err := db.Query(`SELECT id, base_snapshot_id, status, winner_attempt_id, promotion_id, risk_status FROM rollouts WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, baseSnapshotID, status, winnerAttemptID, promotionID, riskStatus string
		if err := rows.Scan(&id, &baseSnapshotID, &status, &winnerAttemptID, &promotionID, &riskStatus); err != nil {
			return err
		}
		if !exists(db, `SELECT 1 FROM snapshots WHERE id = ?`, baseSnapshotID) {
			add("error", "missing_snapshot", id, "rollout base_snapshot_id %s does not exist", baseSnapshotID)
		}
		if winnerAttemptID != "" && !exists(db, `SELECT 1 FROM fork_attempts WHERE id = ? AND rollout_id = ?`, winnerAttemptID, id) {
			add("error", "missing_winner_attempt", id, "winner_attempt_id %s does not belong to rollout", winnerAttemptID)
		}
		if promotionID != "" && !exists(db, `SELECT 1 FROM promotions WHERE id = ? AND rollout_id = ?`, promotionID, id) {
			add("error", "missing_promotion", id, "promotion_id %s does not belong to rollout", promotionID)
		}
		if promotionID != "" && winnerAttemptID != "" && !exists(db, `SELECT 1 FROM promotions WHERE id = ? AND rollout_id = ? AND attempt_id = ?`, promotionID, id, winnerAttemptID) {
			add("error", "promotion_winner_mismatch", id, "promotion_id %s does not promote winner_attempt_id %s", promotionID, winnerAttemptID)
		}
		if status == "completed" && winnerAttemptID == "" {
			add("error", "missing_winner_attempt", id, "completed rollout has no winner_attempt_id")
		}
		if riskStatus == "clean" && winnerAttemptID != "" && attemptIsTainted(db, winnerAttemptID) {
			add("error", "tainted_winner", id, "clean rollout points to tainted/quarantined winner %s", winnerAttemptID)
		}
	}
	return rows.Err()
}

func verifyAttempts(db *sql.DB, runID string, add issueAdder) error {
	rows, err := db.Query(`SELECT a.id, a.rollout_id, a.tool_call_id, a.snapshot_id, a.status, a.risk_status, a.is_winner, COALESCE(a.artifact_result, '')
		FROM fork_attempts a JOIN rollouts r ON a.rollout_id = r.id WHERE r.run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, rolloutID, toolCallID, snapshotID, status, riskStatus, artifact string
		var isWinner int
		if err := rows.Scan(&id, &rolloutID, &toolCallID, &snapshotID, &status, &riskStatus, &isWinner, &artifact); err != nil {
			return err
		}
		if !exists(db, `SELECT 1 FROM rollouts WHERE id = ? AND run_id = ?`, rolloutID, runID) {
			add("error", "missing_rollout", id, "attempt rollout_id %s does not exist in run", rolloutID)
		}
		if !exists(db, `SELECT 1 FROM snapshots WHERE id = ?`, snapshotID) {
			add("error", "missing_snapshot", id, "attempt snapshot_id %s does not exist", snapshotID)
		}
		if toolCallID != "" && !exists(db, `SELECT 1 FROM tool_calls WHERE id = ? AND attempt_id = ?`, toolCallID, id) {
			add("error", "missing_tool_call", id, "attempt tool_call_id %s does not point back to attempt", toolCallID)
		}
		if isWinner != 0 && (status == "quarantined" || riskStatus == "tainted") {
			add("error", "tainted_winner", id, "winner attempt status=%s risk=%s", status, riskStatus)
		}
		if artifact != "" {
			if _, err := os.Stat(artifact); err != nil {
				add("warning", "missing_artifact_file", id, "artifact_result %s is not readable: %v", artifact, err)
			}
		}
	}
	return rows.Err()
}

func verifyToolCalls(db *sql.DB, runID string, add issueAdder) error {
	rows, err := db.Query(`SELECT id, rollout_id, attempt_id, session_id, COALESCE(result_ref, '') FROM tool_calls WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, rolloutID, attemptID, sessionID, resultRef string
		if err := rows.Scan(&id, &rolloutID, &attemptID, &sessionID, &resultRef); err != nil {
			return err
		}
		if rolloutID != "" && !exists(db, `SELECT 1 FROM rollouts WHERE id = ? AND run_id = ?`, rolloutID, runID) {
			add("error", "missing_rollout", id, "tool_call rollout_id %s does not exist in run", rolloutID)
		}
		if attemptID != "" && !exists(db, `SELECT 1 FROM fork_attempts WHERE id = ?`, attemptID) {
			add("error", "missing_attempt", id, "tool_call attempt_id %s does not exist", attemptID)
		}
		if sessionID != "" && !exists(db, `SELECT 1 FROM sessions WHERE id = ?`, sessionID) {
			add("error", "missing_session", id, "tool_call session_id %s does not exist", sessionID)
		}
		if resultRef != "" {
			if _, err := os.Stat(resultRef); err != nil {
				add("warning", "missing_result_ref", id, "result_ref %s is not readable: %v", resultRef, err)
			}
		}
	}
	return rows.Err()
}

func verifyProcesses(db *sql.DB, runID string, add issueAdder) error {
	rows, err := db.Query(`SELECT p.id, p.session_id, COALESCE(p.tool_call_id, ''), p.status, COALESCE(tc.status, '')
		FROM processes p
		JOIN sessions s ON p.session_id = s.id
		LEFT JOIN tool_calls tc ON tc.id = p.tool_call_id
		WHERE s.run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, sessionID, toolCallID, processStatus, toolCallStatus string
		if err := rows.Scan(&id, &sessionID, &toolCallID, &processStatus, &toolCallStatus); err != nil {
			return err
		}
		if !exists(db, `SELECT 1 FROM sessions WHERE id = ? AND run_id = ?`, sessionID, runID) {
			add("error", "missing_session", id, "process session_id %s does not exist in run", sessionID)
		}
		if toolCallID != "" && !exists(db, `SELECT 1 FROM tool_calls WHERE id = ?`, toolCallID) {
			add("error", "missing_tool_call", id, "process tool_call_id %s does not exist", toolCallID)
		}
		if isTerminalToolCallStatus(toolCallStatus) && isNonTerminalProcessStatus(processStatus) {
			add("error", "stale_process_status", id, "tool_call %s is %s but process is still %s", toolCallID, toolCallStatus, processStatus)
		}
	}
	return rows.Err()
}

func isTerminalToolCallStatus(status string) bool {
	switch status {
	case "passed", "failed", "rejected", "budget_exceeded", "killed":
		return true
	default:
		return false
	}
}

func isNonTerminalProcessStatus(status string) bool {
	switch status {
	case "running", "burst_pending":
		return true
	default:
		return false
	}
}

func verifyEvents(db *sql.DB, runID string, add issueAdder) error {
	rows, err := db.Query(`SELECT id, COALESCE(session_id, ''), COALESCE(tool_call_id, ''), COALESCE(process_id, ''), COALESCE(snapshot_id, ''), COALESCE(correlation_method, ''), COALESCE(correlation_confidence, 0) FROM events WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, sessionID, toolCallID, processID, snapshotID, correlationMethod string
		var correlationConfidence float64
		if err := rows.Scan(&id, &sessionID, &toolCallID, &processID, &snapshotID, &correlationMethod, &correlationConfidence); err != nil {
			return err
		}
		if sessionID != "" && !exists(db, `SELECT 1 FROM sessions WHERE id = ?`, sessionID) {
			add("error", "missing_session", id, "event session_id %s does not exist", sessionID)
		}
		if toolCallID != "" && !exists(db, `SELECT 1 FROM tool_calls WHERE id = ?`, toolCallID) {
			add("error", "missing_tool_call", id, "event tool_call_id %s does not exist", toolCallID)
		}
		if processID != "" && !exists(db, `SELECT 1 FROM processes WHERE id = ?`, processID) {
			add("error", "missing_process", id, "event process_id %s does not exist", processID)
		}
		if snapshotID != "" && !exists(db, `SELECT 1 FROM snapshots WHERE id = ?`, snapshotID) {
			add("error", "missing_snapshot", id, "event snapshot_id %s does not exist", snapshotID)
		}
		if correlationMethod != "" && correlationConfidence <= 0 {
			add("error", "invalid_correlation_confidence", id, "event correlation_method %s has confidence %.2f", correlationMethod, correlationConfidence)
		}
		if toolCallID != "" && processID != "" && !exists(db, `SELECT 1 FROM processes WHERE id = ? AND tool_call_id = ?`, processID, toolCallID) {
			add("error", "event_process_tool_call_mismatch", id, "event process_id %s is not bound to tool_call_id %s", processID, toolCallID)
		}
	}
	return rows.Err()
}

func verifyExternalEffects(db *sql.DB, runID string, add issueAdder) error {
	rows, err := db.Query(`SELECT id, attempt_id, session_id, tool_call_id, process_id, mode, decision FROM external_effects WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, attemptID, sessionID, toolCallID, processID, mode, decision string
		if err := rows.Scan(&id, &attemptID, &sessionID, &toolCallID, &processID, &mode, &decision); err != nil {
			return err
		}
		if attemptID != "" && !exists(db, `SELECT 1 FROM fork_attempts WHERE id = ?`, attemptID) {
			add("error", "missing_attempt", id, "external effect attempt_id %s does not exist", attemptID)
		}
		if sessionID != "" && !exists(db, `SELECT 1 FROM sessions WHERE id = ?`, sessionID) {
			add("error", "missing_session", id, "external effect session_id %s does not exist", sessionID)
		}
		if toolCallID != "" && !exists(db, `SELECT 1 FROM tool_calls WHERE id = ?`, toolCallID) {
			add("error", "missing_tool_call", id, "external effect tool_call_id %s does not exist", toolCallID)
		}
		if processID != "" && !exists(db, `SELECT 1 FROM processes WHERE id = ?`, processID) {
			add("error", "missing_process", id, "external effect process_id %s does not exist", processID)
		}
		if !oneOf(mode, "dry-run", "mock", "allowlist", "compensation") {
			add("error", "invalid_external_effect_mode", id, "invalid mode %s", mode)
		}
		if !oneOf(decision, "allow", "deny", "audit") {
			add("error", "invalid_external_effect_decision", id, "invalid decision %s", decision)
		}
	}
	return rows.Err()
}

func verifyObjects(db *sql.DB, runID string, add issueAdder) error {
	rows, err := db.Query(`SELECT hash, source_id, parent_hashes, path FROM provenance_objects WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var hash, sourceID, parentHashes, path string
		if err := rows.Scan(&hash, &sourceID, &parentHashes, &path); err != nil {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			add("error", "missing_provenance_object", sourceID, "object %s path %s is not readable: %v", hash, path, err)
			continue
		}
		sum := sha256.Sum256(raw)
		actual := "sha256:" + hex.EncodeToString(sum[:])
		if actual != hash {
			add("error", "object_hash_mismatch", sourceID, "object hash=%s actual=%s path=%s", hash, actual, path)
		}
		for _, parent := range strings.Split(parentHashes, ",") {
			parent = strings.TrimSpace(parent)
			if parent == "" {
				continue
			}
			if !exists(db, `SELECT 1 FROM provenance_objects WHERE hash = ?`, parent) {
				add("error", "missing_parent_object", sourceID, "parent object %s does not exist", parent)
			}
		}
	}
	return rows.Err()
}

func verifyExecutionContextBindings(db *sql.DB, runID string, add issueAdder) error {
	rows, err := db.Query(`SELECT id, session_id, attempt_id, tool_call_id, process_id, confidence FROM execution_context_bindings WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	bindings := 0
	for rows.Next() {
		bindings++
		var id, sessionID, attemptID, toolCallID, processID string
		var confidence float64
		if err := rows.Scan(&id, &sessionID, &attemptID, &toolCallID, &processID, &confidence); err != nil {
			return err
		}
		if confidence <= 0 {
			add("error", "invalid_binding_confidence", id, "execution context binding confidence %.2f must be positive", confidence)
		}
		if sessionID != "" && !exists(db, `SELECT 1 FROM sessions WHERE id = ?`, sessionID) {
			add("error", "missing_session", id, "binding session_id %s does not exist", sessionID)
		}
		if attemptID != "" && !exists(db, `SELECT 1 FROM fork_attempts WHERE id = ?`, attemptID) {
			add("error", "missing_attempt", id, "binding attempt_id %s does not exist", attemptID)
		}
		if toolCallID != "" && !exists(db, `SELECT 1 FROM tool_calls WHERE id = ?`, toolCallID) {
			add("error", "missing_tool_call", id, "binding tool_call_id %s does not exist", toolCallID)
		}
		if processID != "" && !exists(db, `SELECT 1 FROM processes WHERE id = ?`, processID) {
			add("error", "missing_process", id, "binding process_id %s does not exist", processID)
		}
		if processID != "" && toolCallID != "" && !exists(db, `SELECT 1 FROM processes WHERE id = ? AND tool_call_id = ?`, processID, toolCallID) {
			add("error", "binding_process_tool_call_mismatch", id, "binding process_id %s is not bound to tool_call_id %s", processID, toolCallID)
		}
		if attemptID != "" && toolCallID != "" && !exists(db, `SELECT 1 FROM tool_calls WHERE id = ? AND attempt_id = ?`, toolCallID, attemptID) {
			add("error", "binding_attempt_tool_call_mismatch", id, "binding tool_call_id %s is not bound to attempt_id %s", toolCallID, attemptID)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	var correlatedEvents int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id = ? AND COALESCE(correlation_method, '') != ''`, runID).Scan(&correlatedEvents); err != nil {
		return err
	}
	if correlatedEvents > 0 && bindings == 0 {
		add("error", "missing_execution_context_binding", runID, "run has %d correlated events but no execution_context_bindings", correlatedEvents)
	}
	return nil
}

func verifyReplayManifest(db *sql.DB, runID string, add issueAdder) error {
	manifest, err := BuildReplayRun(db, runID)
	if err != nil {
		add("error", "replay_manifest_failed", runID, "replay manifest cannot be built: %v", err)
		return nil
	}
	if manifest.SchemaVersion != "agentprovenance.replay/v1" {
		add("error", "invalid_replay_schema", runID, "unexpected replay schema %s", manifest.SchemaVersion)
	}
	if len(manifest.Rollouts) == 0 {
		add("error", "empty_replay_manifest", runID, "replay manifest has no rollouts")
	}
	for _, rollout := range manifest.Rollouts {
		if rollout.Status == "completed" && rollout.WinnerAttemptID == "" {
			add("error", "replay_missing_winner", rollout.ID, "completed rollout has no winner in replay manifest")
		}
		if rollout.BaseSnapshotID != "" && rollout.BaseSnapshot == nil {
			add("error", "replay_missing_base_snapshot", rollout.ID, "base snapshot %s missing from replay manifest", rollout.BaseSnapshotID)
		}
		for _, attempt := range rollout.Attempts {
			if attempt.IsWinner && attempt.ReplayBlocked {
				add("error", "replay_blocked_winner", attempt.ID, "winner attempt is replay_blocked reasons=%v", attempt.BlockReasons)
			}
			if attempt.ArtifactResult != "" && (attempt.ArtifactDigest == nil || !attempt.ArtifactDigest.Exists) {
				add("warning", "replay_missing_artifact_digest", attempt.ID, "artifact_result %s has no readable digest", attempt.ArtifactResult)
			}
			if attempt.ToolCallID != "" && attempt.ToolCall == nil {
				add("error", "replay_missing_tool_call", attempt.ID, "tool_call_id %s missing from replay manifest", attempt.ToolCallID)
			}
		}
	}
	return nil
}

func attemptIsTainted(db *sql.DB, attemptID string) bool {
	var status, risk string
	_ = db.QueryRow(`SELECT status, risk_status FROM fork_attempts WHERE id = ?`, attemptID).Scan(&status, &risk)
	return status == "quarantined" || risk == "tainted"
}

func exists(db *sql.DB, query string, args ...any) bool {
	var one int
	err := db.QueryRow(query, args...).Scan(&one)
	return err == nil
}

func oneOf(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}
