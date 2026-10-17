package provenance

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/i18n"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
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
	Error         string        `json:"error,omitempty"`
}

func VerifyRun(db *sql.DB, runID string, out io.Writer, languages ...i18n.Locale) error {
	result, err := Verify(db, runID)
	if result.SchemaVersion != "" {
		PrintVerifyResult(out, result, languages...)
	}
	if err != nil {
		return err
	}
	if result.ErrorCount > 0 {
		return i18n.Errorf("graph verify failed: errors=%d warnings=%d", result.ErrorCount, result.WarningCount)
	}
	return nil
}

func VerifyRunJSON(db *sql.DB, runID string, out io.Writer) error {
	result, err := Verify(db, runID)
	if result.SchemaVersion != "" {
		if printErr := PrintVerifyResultJSON(out, result); printErr != nil {
			return errors.Join(err, printErr)
		}
	}
	if err != nil {
		return err
	}
	if result.ErrorCount > 0 {
		return i18n.Errorf("graph verify failed: errors=%d warnings=%d", result.ErrorCount, result.WarningCount)
	}
	return nil
}

func Verify(db *sql.DB, runID string) (result VerifyResult, err error) {
	if runID == "" {
		return VerifyResult{}, i18n.Errorf("run_id is required")
	}
	result = VerifyResult{SchemaVersion: "agentprovenance.verify/v1", RunID: runID, Status: "ok"}
	defer func() {
		if err != nil {
			result.Status = "unavailable"
			result.Error = err.Error()
		}
	}()
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
	// A run that left no trace anywhere is not "ok" -- there is nothing to
	// verify. Without this guard every check below runs over empty result sets
	// and the run passes clean, so `graph verify <typo>` reports a false green.
	if found, err := runExists(db, runID); err != nil {
		return result, fmt.Errorf("check run existence: %w", err)
	} else if !found {
		add("error", "unknown_run", runID, "run %s has no evidence in any table; nothing to verify", runID)
		result.Status = "failed"
		return result, nil
	}
	if err := verifyRollouts(db, runID, add); err != nil {
		return result, err
	}
	if err := verifyPromotions(db, runID, add); err != nil {
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
	if err := verifyPolicyDecisions(db, runID, add); err != nil {
		return result, err
	}
	if err := verifyRiskAndResponses(db, runID, add); err != nil {
		return result, err
	}
	if err := verifyExecutionContextBindings(db, runID, add); err != nil {
		return result, err
	}
	if err := verifyRuntimeCausality(db, runID, add); err != nil {
		return result, err
	}
	if err := verifyTelemetryBatches(db, runID, add); err != nil {
		return result, err
	}
	if err := verifyProcessObservations(db, runID, add); err != nil {
		return result, err
	}
	if err := verifyReplayManifest(db, runID, add); err != nil {
		return result, err
	}
	if err := verifyObjects(db, runID, add); err != nil {
		return result, err
	}
	if err := verifyAgentContext(db, runID, add); err != nil {
		return result, err
	}
	if result.ErrorCount > 0 {
		result.Status = "failed"
	}
	return result, nil
}

func PrintVerifyResult(out io.Writer, result VerifyResult, languages ...i18n.Locale) {
	lang := presentationLocale(languages)
	status := result.Status
	if status == "" {
		status = "ok"
		if result.ErrorCount > 0 {
			status = "failed"
		}
	}
	fmt.Fprintf(out, i18n.T(lang, "run=%s status=%s errors=%d warnings=%d issues=%d\n"), result.RunID, status, result.ErrorCount, result.WarningCount, result.IssueCount)
	if result.Error != "" {
		fmt.Fprintf(out, "verification_error=%q\n", result.Error)
	}
	for _, issue := range result.Issues {
		fmt.Fprintf(out, i18n.T(lang, "issue severity=%s kind=%s id=%s message=%q\n"), issue.Severity, issue.Kind, issue.ID, issue.Message)
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
		if found, err := exists(db, `SELECT 1 FROM snapshots WHERE id = ?`, baseSnapshotID); err != nil {
			return err
		} else if !found {
			add("error", "missing_snapshot", id, "rollout base_snapshot_id %s does not exist", baseSnapshotID)
		}
		if winnerAttemptID != "" {
			if found, err := exists(db, `SELECT 1 FROM fork_attempts WHERE id = ? AND rollout_id = ?`, winnerAttemptID, id); err != nil {
				return err
			} else if !found {
				add("error", "missing_winner_attempt", id, "winner_attempt_id %s does not belong to rollout", winnerAttemptID)
			}
		}
		if promotionID != "" {
			if found, err := exists(db, `SELECT 1 FROM promotions WHERE id = ? AND rollout_id = ?`, promotionID, id); err != nil {
				return err
			} else if !found {
				add("error", "missing_promotion", id, "promotion_id %s does not belong to rollout", promotionID)
			}
		}
		if promotionID != "" && winnerAttemptID != "" {
			if found, err := exists(db, `SELECT 1 FROM promotions WHERE id = ? AND rollout_id = ? AND attempt_id = ?`, promotionID, id, winnerAttemptID); err != nil {
				return err
			} else if !found {
				add("error", "promotion_winner_mismatch", id, "promotion_id %s does not promote winner_attempt_id %s", promotionID, winnerAttemptID)
			}
		}
		if status == "completed" && winnerAttemptID == "" {
			add("error", "missing_winner_attempt", id, "completed rollout has no winner_attempt_id")
		}
		if riskStatus == "clean" && winnerAttemptID != "" {
			if found, err := attemptIsTainted(db, winnerAttemptID); err != nil {
				return err
			} else if found {
				add("error", "tainted_winner", id, "clean rollout points to tainted/quarantined winner %s", winnerAttemptID)
			}
		}
	}
	return rows.Err()
}

func verifyPromotions(db *sql.DB, runID string, add issueAdder) error {
	rows, err := db.Query(`SELECT p.id, p.rollout_id, p.attempt_id, p.status, COALESCE(p.telemetry_watermark, ''),
		COALESCE(p.drain_started_at, ''), COALESCE(p.drain_completed_at, ''), COALESCE(p.drain_queued_before, 0),
		COALESCE(p.drain_processed, 0), COALESCE(p.drain_pending_after, 0)
		FROM promotions p JOIN rollouts r ON p.rollout_id = r.id WHERE r.run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, rolloutID, attemptID, status, watermark, drainStartedAt, drainCompletedAt string
		var drainQueuedBefore, drainProcessed, drainPendingAfter int
		if err := rows.Scan(&id, &rolloutID, &attemptID, &status, &watermark, &drainStartedAt, &drainCompletedAt, &drainQueuedBefore, &drainProcessed, &drainPendingAfter); err != nil {
			return err
		}
		if status != "promoted" && status != "risk_finalized" {
			continue
		}
		if watermark == "" {
			add("error", "promotion_missing_watermark", id, "promotion %s for rollout %s has no telemetry watermark", id, rolloutID)
		}
		if drainStartedAt == "" || drainCompletedAt == "" {
			add("error", "promotion_missing_drain_window", id, "promotion %s has incomplete drain window start=%q completed=%q", id, drainStartedAt, drainCompletedAt)
		}
		if drainPendingAfter != 0 {
			add("error", "promotion_pending_evidence", id, "promotion %s completed with drain_pending_after=%d", id, drainPendingAfter)
		}
		if drainProcessed < 0 || drainQueuedBefore < 0 {
			add("error", "promotion_invalid_drain_counts", id, "promotion %s has invalid drain counts queued_before=%d processed=%d", id, drainQueuedBefore, drainProcessed)
		}
		if watermark != "" {
			var queuedBeforeWatermark int
			if err := db.QueryRow(`SELECT COALESCE(COUNT(*), 0) FROM evidence_events
				WHERE attempt_id = ? AND status = 'queued' AND created_at <= ?`, attemptID, watermark).Scan(&queuedBeforeWatermark); err != nil {
				return err
			}
			if queuedBeforeWatermark != 0 {
				add("error", "promotion_undrained_evidence", id, "promotion %s has %d queued evidence events at or before watermark %s", id, queuedBeforeWatermark, watermark)
			}
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
		if found, err := exists(db, `SELECT 1 FROM rollouts WHERE id = ? AND run_id = ?`, rolloutID, runID); err != nil {
			return err
		} else if !found {
			add("error", "missing_rollout", id, "attempt rollout_id %s does not exist in run", rolloutID)
		}
		if found, err := exists(db, `SELECT 1 FROM snapshots WHERE id = ?`, snapshotID); err != nil {
			return err
		} else if !found {
			add("error", "missing_snapshot", id, "attempt snapshot_id %s does not exist", snapshotID)
		}
		if toolCallID != "" {
			if found, err := exists(db, `SELECT 1 FROM tool_calls WHERE id = ? AND attempt_id = ?`, toolCallID, id); err != nil {
				return err
			} else if !found {
				add("error", "missing_tool_call", id, "attempt tool_call_id %s does not point back to attempt", toolCallID)
			}
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
		if rolloutID != "" {
			if found, err := exists(db, `SELECT 1 FROM rollouts WHERE id = ? AND run_id = ?`, rolloutID, runID); err != nil {
				return err
			} else if !found {
				add("error", "missing_rollout", id, "tool_call rollout_id %s does not exist in run", rolloutID)
			}
		}
		if attemptID != "" {
			if found, err := exists(db, `SELECT 1 FROM fork_attempts WHERE id = ?`, attemptID); err != nil {
				return err
			} else if !found {
				add("error", "missing_attempt", id, "tool_call attempt_id %s does not exist", attemptID)
			}
		}
		if sessionID != "" {
			if found, err := exists(db, `SELECT 1 FROM sessions WHERE id = ?`, sessionID); err != nil {
				return err
			} else if !found {
				add("error", "missing_session", id, "tool_call session_id %s does not exist", sessionID)
			}
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
		if found, err := exists(db, `SELECT 1 FROM sessions WHERE id = ? AND run_id = ?`, sessionID, runID); err != nil {
			return err
		} else if !found {
			add("error", "missing_session", id, "process session_id %s does not exist in run", sessionID)
		}
		if toolCallID != "" {
			if found, err := exists(db, `SELECT 1 FROM tool_calls WHERE id = ?`, toolCallID); err != nil {
				return err
			} else if !found {
				add("error", "missing_tool_call", id, "process tool_call_id %s does not exist", toolCallID)
			}
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
		externalContext, err := externalContextBindingExists(db, runID, sessionID, "", toolCallID, processID)
		if err != nil {
			return err
		}
		if sessionID != "" {
			if found, err := exists(db, `SELECT 1 FROM sessions WHERE id = ?`, sessionID); err != nil {
				return err
			} else if !found && !externalContext {
				add("error", "missing_session", id, "event session_id %s does not exist", sessionID)
			}
		}
		if toolCallID != "" {
			if found, err := exists(db, `SELECT 1 FROM tool_calls WHERE id = ?`, toolCallID); err != nil {
				return err
			} else if !found && !externalContext {
				add("error", "missing_tool_call", id, "event tool_call_id %s does not exist", toolCallID)
			}
		}
		if processID != "" {
			if found, err := exists(db, `SELECT 1 FROM processes WHERE id = ?`, processID); err != nil {
				return err
			} else if !found && !externalContext {
				add("error", "missing_process", id, "event process_id %s does not exist", processID)
			}
		}
		if snapshotID != "" {
			if found, err := exists(db, `SELECT 1 FROM snapshots WHERE id = ?`, snapshotID); err != nil {
				return err
			} else if !found {
				add("error", "missing_snapshot", id, "event snapshot_id %s does not exist", snapshotID)
			}
		}
		if math.IsNaN(correlationConfidence) || math.IsInf(correlationConfidence, 0) || correlationConfidence < 0 || correlationConfidence > 1 {
			add("error", "invalid_correlation_confidence", id, "event correlation_method %s has confidence %.2f", correlationMethod, correlationConfidence)
		}
		if toolCallID != "" && processID != "" {
			if found, err := exists(db, `SELECT 1 FROM processes WHERE id = ? AND tool_call_id = ?`, processID, toolCallID); err != nil {
				return err
			} else if !found && !externalContext {
				add("error", "event_process_tool_call_mismatch", id, "event process_id %s is not bound to tool_call_id %s", processID, toolCallID)
			}
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
		if attemptID != "" {
			if found, err := exists(db, `SELECT 1 FROM fork_attempts WHERE id = ?`, attemptID); err != nil {
				return err
			} else if !found {
				add("error", "missing_attempt", id, "external effect attempt_id %s does not exist", attemptID)
			}
		}
		if sessionID != "" {
			if found, err := exists(db, `SELECT 1 FROM sessions WHERE id = ?`, sessionID); err != nil {
				return err
			} else if !found {
				add("error", "missing_session", id, "external effect session_id %s does not exist", sessionID)
			}
		}
		if toolCallID != "" {
			if found, err := exists(db, `SELECT 1 FROM tool_calls WHERE id = ?`, toolCallID); err != nil {
				return err
			} else if !found {
				add("error", "missing_tool_call", id, "external effect tool_call_id %s does not exist", toolCallID)
			}
		}
		if processID != "" {
			if found, err := exists(db, `SELECT 1 FROM processes WHERE id = ?`, processID); err != nil {
				return err
			} else if !found {
				add("error", "missing_process", id, "external effect process_id %s does not exist", processID)
			}
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

func verifyPolicyDecisions(db *sql.DB, runID string, add issueAdder) error {
	rows, err := db.Query(`SELECT id, COALESCE(event_id, ''), COALESCE(session_id, '') FROM policy_decisions WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, eventID, sessionID string
		if err := rows.Scan(&id, &eventID, &sessionID); err != nil {
			return err
		}
		policyNodeID := "policy_decision/" + id
		if eventID != "" {
			if found, err := exists(db, `SELECT 1 FROM events WHERE id = ?`, eventID); err != nil {
				return err
			} else if !found {
				add("error", "missing_policy_event", id, "policy decision event_id %s does not exist", eventID)
			}
			if found, err := edgeExists(db, runID, "runtime_event/"+eventID, policyNodeID, "runtime_event_policy_decision"); err != nil {
				return err
			} else if !found {
				add("error", "missing_policy_decision_edge", id, "runtime event %s is not linked to policy decision %s", eventID, id)
			}
		}
		if sessionID != "" {
			externalContext, err := externalContextBindingExists(db, runID, sessionID, "", "", "")
			if err != nil {
				return err
			}
			if found, err := exists(db, `SELECT 1 FROM sessions WHERE id = ?`, sessionID); err != nil {
				return err
			} else if !found && !externalContext {
				add("error", "missing_policy_session", id, "policy decision session_id %s does not exist", sessionID)
			}
			if found, err := edgeExists(db, runID, policyNodeID, sessionID, "policy_decision_session"); err != nil {
				return err
			} else if !found {
				add("error", "missing_policy_session_edge", id, "policy decision %s is not linked to session %s", id, sessionID)
			}
		}
	}
	return rows.Err()
}

func verifyRiskAndResponses(db *sql.DB, runID string, add issueAdder) error {
	policies, err := db.Query(`SELECT id, COALESCE(event_id, ''), decision FROM policy_decisions WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer policies.Close()
	for policies.Next() {
		var id, eventID, decision string
		if err := policies.Scan(&id, &eventID, &decision); err != nil {
			return err
		}
		if decision == "allow" {
			continue
		}
		if found, err := exists(db, `SELECT 1 FROM risk_signals WHERE run_id = ? AND policy_decision_id = ?`, runID, id); err != nil {
			return err
		} else if !found {
			add("error", "missing_policy_risk_signal", id, "non-allow policy decision %s has no risk signal", id)
		}
		if found, err := exists(db, `SELECT 1 FROM response_actions WHERE run_id = ? AND policy_decision_id = ?`, runID, id); err != nil {
			return err
		} else if !found {
			add("error", "missing_policy_response_action", id, "non-allow policy decision %s has no response action", id)
		}
		// Unified signal model: a non-allow policy decision must also surface as a
		// security-dimension signal (via its risk_signal). The policy path writes
		// this live and a writeback failure emits an observable error event, so a
		// missing unified signal here is a real integrity gap.
		if found, err := exists(db, `SELECT 1 FROM signals s JOIN risk_signals r ON s.source_id = r.id
			WHERE s.dimension = 'security' AND s.source_table = 'risk_signals'
			AND r.policy_decision_id = ? AND s.run_id = ?`, id, runID); err != nil {
			return err
		} else if !found {
			add("error", "missing_policy_unified_signal", id, "non-allow policy decision %s has no unified security signal", id)
		}
		if eventID != "" {
			if found, err := edgeExists(db, runID, "runtime_event/"+eventID, "policy_decision/"+id, "runtime_event_policy_decision"); err != nil {
				return err
			} else if !found {
				add("error", "missing_policy_decision_edge", id, "runtime event %s is not linked to policy decision %s", eventID, id)
			}
		}
	}
	if err := policies.Err(); err != nil {
		return err
	}

	risks, err := db.Query(`SELECT id, COALESCE(event_id, ''), COALESCE(policy_decision_id, ''), recommended_action FROM risk_signals WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer risks.Close()
	for risks.Next() {
		var id, eventID, policyDecisionID, recommendedAction string
		if err := risks.Scan(&id, &eventID, &policyDecisionID, &recommendedAction); err != nil {
			return err
		}
		if found, err := exists(db, `SELECT 1 FROM policy_decisions WHERE id = ? AND run_id = ?`, policyDecisionID, runID); err != nil {
			return err
		} else if policyDecisionID == "" || !found {
			add("error", "missing_risk_policy_decision", id, "risk signal %s references missing policy decision %s", id, policyDecisionID)
		}
		if found, err := exists(db, `SELECT 1 FROM events WHERE id = ? AND run_id = ?`, eventID, runID); err != nil {
			return err
		} else if eventID == "" || !found {
			add("error", "missing_risk_event", id, "risk signal %s references missing runtime event %s", id, eventID)
		}
		if policyDecisionID != "" {
			if found, err := edgeExists(db, runID, "policy_decision/"+policyDecisionID, "risk_signal/"+id, "policy_decision_risk_signal"); err != nil {
				return err
			} else if !found {
				add("error", "missing_risk_signal_edge", id, "policy decision %s is not linked to risk signal %s", policyDecisionID, id)
			}
		}
		if found, err := exists(db, `SELECT 1 FROM response_actions WHERE run_id = ? AND risk_signal_id = ?`, runID, id); err != nil {
			return err
		} else if !found {
			add("error", "missing_risk_response_action", id, "risk signal %s has no response action", id)
		}
		if !oneOf(recommendedAction, "audit", "deny", "kill", "quarantine", "taint", "export", "notify") {
			add("error", "invalid_risk_recommended_action", id, "risk signal %s has invalid recommended action %s", id, recommendedAction)
		}
	}
	if err := risks.Err(); err != nil {
		return err
	}

	responses, err := db.Query(`SELECT id, COALESCE(risk_signal_id, ''), COALESCE(policy_decision_id, ''), action_type, target_type, COALESCE(target_id, ''), status FROM response_actions WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer responses.Close()
	for responses.Next() {
		var id, riskSignalID, policyDecisionID, actionType, targetType, targetID, status string
		if err := responses.Scan(&id, &riskSignalID, &policyDecisionID, &actionType, &targetType, &targetID, &status); err != nil {
			return err
		}
		if found, err := exists(db, `SELECT 1 FROM risk_signals WHERE id = ? AND run_id = ?`, riskSignalID, runID); err != nil {
			return err
		} else if riskSignalID == "" || !found {
			add("error", "missing_response_risk_signal", id, "response action %s references missing risk signal %s", id, riskSignalID)
		}
		if found, err := exists(db, `SELECT 1 FROM policy_decisions WHERE id = ? AND run_id = ?`, policyDecisionID, runID); err != nil {
			return err
		} else if policyDecisionID == "" || !found {
			add("error", "missing_response_policy_decision", id, "response action %s references missing policy decision %s", id, policyDecisionID)
		}
		if riskSignalID != "" && policyDecisionID != "" {
			if found, err := exists(db, `SELECT 1 FROM risk_signals WHERE id = ? AND policy_decision_id = ? AND run_id = ?`, riskSignalID, policyDecisionID, runID); err != nil {
				return err
			} else if !found {
				add("error", "response_risk_policy_mismatch", id, "response action %s risk %s is not linked to policy decision %s", id, riskSignalID, policyDecisionID)
			}
		}
		if riskSignalID != "" {
			if found, err := edgeExists(db, runID, "risk_signal/"+riskSignalID, "response_action/"+id, "risk_signal_response_action"); err != nil {
				return err
			} else if !found {
				add("error", "missing_response_action_edge", id, "risk signal %s is not linked to response action %s", riskSignalID, id)
			}
		}
		if !oneOf(actionType, "audit", "deny", "kill", "quarantine", "taint", "export", "notify") {
			add("error", "invalid_response_action_type", id, "response action %s has invalid action_type %s", id, actionType)
		}
		if targetType == "" || targetID == "" {
			add("error", "missing_response_target", id, "response action %s has target_type=%q target_id=%q", id, targetType, targetID)
		}
		if !oneOf(status, "recorded", "pending", "running", "succeeded", "failed", "skipped") {
			add("error", "invalid_response_status", id, "response action %s has invalid status %s", id, status)
		}
	}
	return responses.Err()
}

func verifyObjects(db *sql.DB, runID string, add issueAdder) error {
	checkedText := map[string]bool{}
	rows, err := db.Query(`SELECT hash, object_type, source_id, parent_hashes, path FROM provenance_objects WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var hash, objectType, sourceID, parentHashes, path string
		if err := rows.Scan(&hash, &objectType, &sourceID, &parentHashes, &path); err != nil {
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
		var obj provenanceObject
		if err := json.Unmarshal(raw, &obj); err != nil {
			add("error", "invalid_provenance_object_json", sourceID, "object %s is invalid JSON: %v", hash, err)
			continue
		}
		if objectType == "record_manifest" {
			expected, err := BuildRecordManifest(db, runID)
			if err != nil {
				add("error", "record_manifest_rebuild_failed", sourceID, "record manifest cannot be rebuilt: %v", err)
			} else if !jsonEqual(obj.Payload["manifest"], expected) {
				add("error", "record_manifest_mismatch", sourceID, "record manifest object does not match rebuilt manifest")
			}
		}
		contentRef, _ := obj.Payload["content_ref"].(string)
		if objectType == "text_content" || obj.Payload["kind"] == "stored_text" {
			contentRef = hash
		}
		if contentRef != "" && (objectType == "artifact" || objectType == "text_content") {
			if !checkedText[contentRef] {
				if err := VerifyTextContent(db, runID, contentRef); err != nil {
					if contentQueryFailed(err) {
						return err
					}
					add("error", "text_content_invalid", sourceID, "saved text cannot be verified: %v", err)
				}
				checkedText[contentRef] = true
			}
			if contentRef != hash {
				page, err := ReadTextContentPage(db, runID, contentRef, 0, 4)
				if err == nil {
					for field, want := range map[string]any{"content_bytes": page.TotalBytes, "sha256": page.SHA256, "redacted": page.Redacted} {
						if got, exists := obj.Payload[field]; exists && !jsonEqual(got, want) {
							add("error", "artifact_content_metadata_mismatch", sourceID, "saved artifact %s differs from its text manifest", field)
						}
					}
				}
			}
		}
		for _, parent := range strings.Split(parentHashes, ",") {
			parent = strings.TrimSpace(parent)
			if parent == "" {
				continue
			}
			if found, err := exists(db, `SELECT 1 FROM provenance_objects WHERE hash = ?`, parent); err != nil {
				return err
			} else if !found {
				add("error", "missing_parent_object", sourceID, "parent object %s does not exist", parent)
			}
		}
	}
	return rows.Err()
}

func jsonEqual(a, b any) bool {
	aa, errA := normalizedJSON(a)
	bb, errB := normalizedJSON(b)
	return errA == nil && errB == nil && bytes.Equal(aa, bb)
}

func normalizedJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, err
	}
	return json.Marshal(decoded)
}

func verifyExecutionContextBindings(db *sql.DB, runID string, add issueAdder) error {
	rows, err := db.Query(`SELECT id, session_id, attempt_id, tool_call_id, process_id, container_id, cgroup_id, root_pid, pid, binding_source, confidence FROM execution_context_bindings WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	bindings := 0
	for rows.Next() {
		bindings++
		var id, sessionID, attemptID, toolCallID, processID, containerID, cgroupID, source string
		var rootPID, pid int64
		var confidence float64
		if err := rows.Scan(&id, &sessionID, &attemptID, &toolCallID, &processID, &containerID, &cgroupID, &rootPID, &pid, &source, &confidence); err != nil {
			return err
		}
		externalContext := isExternalRuntimeBinding(containerID, cgroupID, rootPID, pid, source)
		if math.IsNaN(confidence) || math.IsInf(confidence, 0) || confidence < 0 || confidence > 1 {
			add("error", "invalid_binding_confidence", id, "execution context binding confidence %.2f must be in [0,1]", confidence)
		}
		if sessionID != "" {
			if found, err := exists(db, `SELECT 1 FROM sessions WHERE id = ?`, sessionID); err != nil {
				return err
			} else if !found && !externalContext {
				add("error", "missing_session", id, "binding session_id %s does not exist", sessionID)
			}
		}
		if attemptID != "" {
			if found, err := exists(db, `SELECT 1 FROM fork_attempts WHERE id = ?`, attemptID); err != nil {
				return err
			} else if !found && !externalContext {
				add("error", "missing_attempt", id, "binding attempt_id %s does not exist", attemptID)
			}
		}
		if toolCallID != "" {
			if found, err := exists(db, `SELECT 1 FROM tool_calls WHERE id = ?`, toolCallID); err != nil {
				return err
			} else if !found && !externalContext {
				add("error", "missing_tool_call", id, "binding tool_call_id %s does not exist", toolCallID)
			}
		}
		if processID != "" {
			if found, err := exists(db, `SELECT 1 FROM processes WHERE id = ?`, processID); err != nil {
				return err
			} else if !found && !externalContext {
				add("error", "missing_process", id, "binding process_id %s does not exist", processID)
			}
		}
		if processID != "" && toolCallID != "" {
			if found, err := exists(db, `SELECT 1 FROM processes WHERE id = ? AND tool_call_id = ?`, processID, toolCallID); err != nil {
				return err
			} else if !found && !externalContext {
				add("error", "binding_process_tool_call_mismatch", id, "binding process_id %s is not bound to tool_call_id %s", processID, toolCallID)
			}
		}
		if attemptID != "" && toolCallID != "" {
			if found, err := exists(db, `SELECT 1 FROM tool_calls WHERE id = ? AND attempt_id = ?`, toolCallID, attemptID); err != nil {
				return err
			} else if !found && !externalContext {
				add("error", "binding_attempt_tool_call_mismatch", id, "binding tool_call_id %s is not bound to attempt_id %s", toolCallID, attemptID)
			}
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

func verifyRuntimeCausality(db *sql.DB, runID string, add issueAdder) error {
	// Buffer the run's events, then resolve edge and attempt membership from
	// in-memory maps. Previously each event issued up to ~12 single-row edge and
	// attempt-id queries inside the open events cursor - an O(events x lookups)
	// N+1 that also required store.Open to keep a multi-connection pool.
	// Preloading first removes both.
	type runtimeEvent struct {
		id, toolCallID, processID, eventType, payload, correlationMethod, source string
		pid, tgid, ppid                                                          int64
	}
	rows, err := db.Query(`SELECT id, COALESCE(tool_call_id, ''), COALESCE(process_id, ''), event_type, payload,
		COALESCE(correlation_method, ''),
		COALESCE(source, ''),
		COALESCE(pid, 0), COALESCE(tgid, 0), COALESCE(ppid, 0)
		FROM events WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	var events []runtimeEvent
	toolCallIDs := map[string]struct{}{}
	for rows.Next() {
		var e runtimeEvent
		if err := rows.Scan(&e.id, &e.toolCallID, &e.processID, &e.eventType, &e.payload, &e.correlationMethod, &e.source, &e.pid, &e.tgid, &e.ppid); err != nil {
			rows.Close()
			return err
		}
		if e.toolCallID != "" {
			toolCallIDs[e.toolCallID] = struct{}{}
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	edges, err := loadRunEdgeSet(db, runID)
	if err != nil {
		return err
	}
	attemptByToolCall, err := loadAttemptIDsForToolCalls(db, toolCallIDs)
	if err != nil {
		return err
	}
	hasEdge := func(fromID, toID, edgeType string) bool {
		_, ok := edges[edgeKey{fromID, toID, edgeType}]
		return ok
	}

	for _, e := range events {
		id, toolCallID, processID, eventType, payload, correlationMethod, source := e.id, e.toolCallID, e.processID, e.eventType, e.payload, e.correlationMethod, e.source
		identity := telemetry.ProcessGraphIdentity(telemetry.EventRecord{ID: id, Source: source, Payload: payload, PID: e.pid, TGID: e.tgid, PPID: e.ppid})
		hasProcessEdge := func(fromID, toID, edgeType string) bool {
			if identity.Version == "" {
				return hasEdge(fromID, toID, edgeType)
			}
			_, ok := edges[edgeKey{fromID, toID, edgeType}][id]
			return ok
		}
		if identity.Version != "" && identity.Version != telemetry.RuntimeProcessGraphVersion {
			add("error", "unsupported_runtime_process_identity", id, "unsupported process identity version %s", identity.Version)
		}
		if telemetry.TelemetrySource(source, correlationMethod) {
			if err := telemetry.ValidateStoredPayload(eventType, payload); err != nil {
				add("error", "invalid_telemetry_payload_schema", id, "event %s type=%s has invalid telemetry payload: %v", id, eventType, err)
			}
		}
		isRuntimeTelemetry := correlationMethod != ""
		isFileTelemetry := eventType == "file_write" || eventType == "file_open"
		if !isRuntimeTelemetry && !isFileTelemetry {
			continue
		}
		attemptID := attemptByToolCall[toolCallID]
		eventNode := "runtime_event/" + id
		if isRuntimeTelemetry && attemptID != "" && !hasEdge(attemptID, eventNode, "runtime_attempt_event") {
			add("error", "missing_runtime_attempt_event_edge", id, "attempt %s is not linked to runtime event %s", attemptID, id)
		}
		if isRuntimeTelemetry && toolCallID != "" {
			if !hasEdge(toolCallID, eventNode, "runtime_tool_call_event") {
				add("error", "missing_runtime_tool_call_event_edge", id, "tool_call %s is not linked to runtime event %s", toolCallID, id)
			}
			if processID != "" && !hasEdge(toolCallID, processID, "runtime_tool_call_process") {
				add("error", "missing_runtime_tool_call_process_edge", id, "tool_call %s is not linked to process %s", toolCallID, processID)
			}
		}
		if isRuntimeTelemetry && processID != "" && !hasEdge(processID, eventNode, "runtime_process_event") {
			add("error", "missing_runtime_process_event_edge", id, "process %s is not linked to runtime event %s", processID, id)
		}
		if isRuntimeTelemetry && identity.Process.ID != "" {
			processNode := identity.Process.ID
			if identity.Version != "" && !hasProcessEdge(processNode, eventNode, "runtime_process_event") {
				add("error", "missing_runtime_process_event_edge", id, "observed process %s is not linked to event %s", processNode, id)
			}
			if processID != "" {
				if !hasProcessEdge(processID, processNode, "runtime_process_observed") {
					add("error", "missing_runtime_process_observed_edge", id, "process %s is not linked to observed process %s", processID, processNode)
				}
			}
		}
		if isRuntimeTelemetry && identity.Process.ID != "" && identity.Parent.ID != "" {
			parentNode, childNode := identity.Parent.ID, identity.Process.ID
			if !hasProcessEdge(parentNode, childNode, "runtime_process_parent") {
				add("error", "missing_runtime_process_parent_edge", id, "process %s is not linked as parent of %s", parentNode, childNode)
			}
			if !hasProcessEdge(childNode, parentNode, "runtime_process_child_of") {
				add("error", "missing_runtime_process_child_edge", id, "process %s is not linked back to parent %s", childNode, parentNode)
			}
		}
		if isRuntimeTelemetry && identity.Process.ID != "" && identity.ThreadGroup.ID != "" && e.pid != e.tgid {
			threadGroupNode, processNode := identity.ThreadGroup.ID, identity.Process.ID
			if !hasProcessEdge(threadGroupNode, processNode, "runtime_process_thread") {
				add("error", "missing_runtime_process_thread_edge", id, "thread group %s is not linked to %s", threadGroupNode, processNode)
			}
		}
		if eventType == "file_write" || eventType == "file_open" {
			if path := verifyPayloadPath(payload); path != "" {
				fileNode := "workspace_file/" + path
				if !hasEdge(eventNode, fileNode, "runtime_event_file") {
					add("error", "missing_runtime_event_file_edge", id, "runtime event %s is not linked to file %s", id, path)
				}
				if processID != "" && !hasEdge(processID, fileNode, "runtime_process_file") {
					add("error", "missing_runtime_process_file_edge", id, "process %s is not linked to file %s", processID, path)
				}
				if toolCallID != "" && !hasEdge(toolCallID, fileNode, "runtime_tool_call_file") {
					add("error", "missing_runtime_tool_call_file_edge", id, "tool_call %s is not linked to file %s", toolCallID, path)
				}
				if attemptID != "" && !hasEdge(attemptID, fileNode, "runtime_attempt_file") {
					add("error", "missing_runtime_attempt_file_edge", id, "attempt %s is not linked to file %s", attemptID, path)
				}
			}
		}
	}
	return nil
}

func verifyTelemetryBatches(db *sql.DB, runID string, add issueAdder) error {
	rows, err := db.Query(`SELECT id, format, file_sha256, event_ids_json, event_ids_sha256, ingested_count
		FROM telemetry_batches WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, format, fileHash, eventIDsJSON, eventIDsHash string
		var ingestedCount int
		if err := rows.Scan(&id, &format, &fileHash, &eventIDsJSON, &eventIDsHash, &ingestedCount); err != nil {
			return err
		}
		if strings.TrimSpace(format) == "" {
			add("error", "telemetry_batch_missing_format", id, "telemetry batch has no source format")
		}
		if strings.TrimSpace(fileHash) == "" {
			add("error", "telemetry_batch_missing_file_hash", id, "telemetry batch has no input file sha256")
		}
		var eventIDs []string
		if err := json.Unmarshal([]byte(eventIDsJSON), &eventIDs); err != nil {
			add("error", "telemetry_batch_invalid_event_ids", id, "telemetry batch event_ids_json is not valid JSON: %v", err)
			continue
		}
		if len(eventIDs) != ingestedCount {
			add("error", "telemetry_batch_ingested_count_mismatch", id, "telemetry batch ingested_count=%d but event_ids=%d", ingestedCount, len(eventIDs))
		}
		if got := hashVerifyStrings(eventIDs); got != eventIDsHash {
			add("error", "telemetry_batch_event_hash_mismatch", id, "telemetry batch event_ids_sha256 mismatch got=%s want=%s", got, eventIDsHash)
		}
		for _, eventID := range eventIDs {
			if found, err := exists(db, `SELECT 1 FROM events WHERE id = ? AND run_id = ?`, eventID, runID); err != nil {
				return err
			} else if !found {
				add("error", "telemetry_batch_missing_event", id, "telemetry batch references missing event %s", eventID)
			}
		}
	}
	return rows.Err()
}

func hashVerifyStrings(values []string) string {
	h := sha256.New()
	for _, value := range values {
		_, _ = h.Write([]byte(value))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func verifyProcessObservations(db *sql.DB, runID string, add issueAdder) error {
	rows, err := db.Query(`SELECT id, COALESCE(tool_call_id, ''), COALESCE(process_id, ''), payload
		FROM events
		WHERE run_id = ? AND source = 'record_process_sample' AND event_type = 'process_observed'
		ORDER BY created_at ASC`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, toolCallID, processID, payload string
		if err := rows.Scan(&id, &toolCallID, &processID, &payload); err != nil {
			return err
		}
		var proc struct {
			PID          int64  `json:"pid"`
			PPID         int64  `json:"ppid"`
			Command      string `json:"command"`
			OutlivedRoot bool   `json:"outlived_root"`
		}
		if err := json.Unmarshal(unwrapRecordProcessPayload(payload), &proc); err != nil {
			add("error", "invalid_process_observation_payload", id, "process observation payload is not valid JSON: %v", err)
			continue
		}
		if proc.PID == 0 {
			add("error", "invalid_process_observation_pid", id, "process observation has empty pid")
		}
		if toolCallID == "" {
			add("error", "missing_process_observation_tool_call", id, "process observation pid %d has no tool_call_id", proc.PID)
		}
		if processID == "" {
			add("error", "missing_process_observation_process", id, "process observation pid %d has no process_id", proc.PID)
		}
		if !proc.OutlivedRoot {
			continue
		}
		refs, err := orphanLifecycleVerifyRefs(db, runID, proc.PID)
		if err != nil {
			return err
		}
		if len(refs.evidenceIDs) == 0 {
			add("error", "missing_orphan_lifecycle_evidence", id, "outlived process pid %d has no orphan_lifecycle_decision evidence", proc.PID)
		}
		if len(refs.policyDecisionIDs) == 0 {
			add("error", "missing_orphan_lifecycle_policy_decision", id, "outlived process pid %d has no linked orphan lifecycle policy decision", proc.PID)
		}
		for _, decisionID := range refs.policyDecisionIDs {
			if found, err := exists(db, `SELECT 1 FROM policy_decisions WHERE id = ? AND run_id = ? AND rule_id = 'zero_sdk_orphan_observe_only' AND decision = 'audit'`, decisionID, runID); err != nil {
				return err
			} else if !found {
				add("error", "missing_orphan_lifecycle_policy_decision", id, "outlived process pid %d references missing policy decision %s", proc.PID, decisionID)
			}
		}
	}
	return rows.Err()
}

type orphanLifecycleRefsForVerify struct {
	evidenceIDs       []string
	policyDecisionIDs []string
}

func orphanLifecycleVerifyRefs(db *sql.DB, runID string, pid int64) (orphanLifecycleRefsForVerify, error) {
	rows, err := db.Query(`SELECT id, payload FROM evidence_events
		WHERE run_id = ? AND event_type = 'orphan_lifecycle_decision' ORDER BY created_at ASC`, runID)
	if err != nil {
		return orphanLifecycleRefsForVerify{}, err
	}
	defer rows.Close()
	refs := orphanLifecycleRefsForVerify{}
	decisionSeen := map[string]bool{}
	for rows.Next() {
		var id, payload string
		if err := rows.Scan(&id, &payload); err != nil {
			return orphanLifecycleRefsForVerify{}, err
		}
		var decoded struct {
			PID              int64  `json:"pid"`
			PolicyDecisionID string `json:"policy_decision_id"`
		}
		if err := json.Unmarshal([]byte(payload), &decoded); err != nil || decoded.PID != pid {
			continue
		}
		refs.evidenceIDs = append(refs.evidenceIDs, id)
		if decoded.PolicyDecisionID != "" && !decisionSeen[decoded.PolicyDecisionID] {
			refs.policyDecisionIDs = append(refs.policyDecisionIDs, decoded.PolicyDecisionID)
			decisionSeen[decoded.PolicyDecisionID] = true
		}
	}
	return refs, rows.Err()
}

func verifyReplayManifest(db *sql.DB, runID string, add issueAdder) error {
	manifest, err := BuildReplayRun(db, runID)
	if err != nil {
		if isNoRolloutRun(err) {
			return nil
		}
		if errors.Is(err, sql.ErrNoRows) {
			add("error", "replay_manifest_failed", runID, "replay manifest references missing evidence: %v", err)
			return nil
		}
		return fmt.Errorf("build replay manifest: %w", err)
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

func attemptIsTainted(db *sql.DB, attemptID string) (bool, error) {
	var status, risk string
	err := db.QueryRow(`SELECT status, risk_status FROM fork_attempts WHERE id = ?`, attemptID).Scan(&status, &risk)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check attempt risk: %w", err)
	}
	return status == "quarantined" || risk == "tainted", nil
}

func exists(db *sql.DB, query string, args ...any) (bool, error) {
	var one int
	err := db.QueryRow(query, args...).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("verify reference lookup: %w", err)
	}
	return true, nil
}

// runExists reports whether a run_id has any evidence at all. A run is not a row
// in one table -- it is a logical grouping keyed by run_id across the anchor
// tables -- so existence is presence in any of them. A single legitimate
// record-only run lands at least a session, so a sparse run still verifies; only
// a run with no rows anywhere (a typo, a wrong id) is treated as unknown.
func runExists(db *sql.DB, runID string) (bool, error) {
	for _, table := range []string{"sessions", "rollouts", "tool_calls", "events", "provenance_objects"} {
		if found, err := exists(db, `SELECT 1 FROM `+table+` WHERE run_id = ? LIMIT 1`, runID); err != nil {
			return false, fmt.Errorf("check %s: %w", table, err)
		} else if found {
			return true, nil
		}
	}
	return false, nil
}

func externalContextBindingExists(db *sql.DB, runID, sessionID, attemptID, toolCallID, processID string) (bool, error) {
	clauses := []string{"run_id = ?"}
	args := []any{runID}
	for _, item := range []struct {
		column string
		value  string
	}{
		{"session_id", sessionID},
		{"attempt_id", attemptID},
		{"tool_call_id", toolCallID},
		{"process_id", processID},
	} {
		if strings.TrimSpace(item.value) == "" {
			continue
		}
		clauses = append(clauses, item.column+" = ?")
		args = append(args, item.value)
	}
	if len(clauses) == 1 {
		return false, nil
	}
	query := `SELECT COALESCE(container_id, ''), COALESCE(cgroup_id, ''), COALESCE(root_pid, 0), COALESCE(pid, 0), COALESCE(binding_source, '')
		FROM execution_context_bindings WHERE ` + strings.Join(clauses, " AND ") + ` ORDER BY created_at DESC LIMIT 1`
	var containerID, cgroupID, source string
	var rootPID, pid int64
	if err := db.QueryRow(query, args...).Scan(&containerID, &cgroupID, &rootPID, &pid, &source); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("check external context binding: %w", err)
	}
	return isExternalRuntimeBinding(containerID, cgroupID, rootPID, pid, source), nil
}

func isExternalRuntimeBinding(containerID, cgroupID string, rootPID, pid int64, source string) bool {
	if containerID != "" || cgroupID != "" || rootPID != 0 || pid != 0 {
		return true
	}
	switch strings.TrimSpace(source) {
	case "external_telemetry", "telemetry_bind", "phase1_accept", "harness_tool_call_scope":
		return true
	default:
		return false
	}
}

func edgeExists(db *sql.DB, runID, fromID, toID, edgeType string) (bool, error) {
	return exists(db, `SELECT 1 FROM graph_edges WHERE run_id = ? AND from_id = ? AND to_id = ? AND edge_type = ?`, runID, fromID, toID, edgeType)
}

type edgeKey struct {
	fromID   string
	toID     string
	edgeType string
}

// loadRunEdgeSet loads every graph edge for a run into a membership set so edge
// existence can be checked in memory instead of one query per lookup. All
// edgeExists calls in verifyRuntimeCausality share the same run_id, so this set
// is an exact substitute for that query.
func loadRunEdgeSet(db *sql.DB, runID string) (map[edgeKey]map[string]struct{}, error) {
	rows, err := db.Query(`SELECT from_id, to_id, edge_type, COALESCE(source_event_id,'') FROM graph_edges WHERE run_id = ?`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	set := map[edgeKey]map[string]struct{}{}
	for rows.Next() {
		var k edgeKey
		var eventID string
		if err := rows.Scan(&k.fromID, &k.toID, &k.edgeType, &eventID); err != nil {
			return nil, err
		}
		if set[k] == nil {
			set[k] = map[string]struct{}{}
		}
		set[k][eventID] = struct{}{}
	}
	return set, rows.Err()
}

// loadAttemptIDsForToolCalls resolves tool_call_id -> attempt_id for the given
// ids. It looks tool calls up by id (no run_id filter) so verification cannot
// become more lenient for tool calls with an unset run_id; a missing id maps to
// "" just as a per-row lookup would return "".
func loadAttemptIDsForToolCalls(db *sql.DB, ids map[string]struct{}) (map[string]string, error) {
	out := make(map[string]string, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	list := make([]string, 0, len(ids))
	for id := range ids {
		list = append(list, id)
	}
	const chunk = 900
	for start := 0; start < len(list); start += chunk {
		end := start + chunk
		if end > len(list) {
			end = len(list)
		}
		batch := list[start:end]
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(batch)), ",")
		args := make([]any, len(batch))
		for i, id := range batch {
			args[i] = id
		}
		rows, err := db.Query(`SELECT id, COALESCE(attempt_id, '') FROM tool_calls WHERE id IN (`+placeholders+`)`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id, attemptID string
			if err := rows.Scan(&id, &attemptID); err != nil {
				rows.Close()
				return nil, err
			}
			out[id] = attemptID
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	return out, nil
}

func verifyPayloadPath(payload string) string {
	var decoded any
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		return ""
	}
	path := strings.TrimSpace(findVerifyPayloadPath(decoded))
	path = strings.TrimPrefix(path, "/workspace/")
	path = strings.TrimPrefix(path, "./")
	if strings.HasPrefix(path, "/") {
		return ""
	}
	// Match ingestion: unresolved dot segments are raw path observations,
	// not workspace artifact identities requiring file edges.
	for _, part := range strings.Split(path, "/") {
		if part == "." || part == ".." {
			return ""
		}
	}
	return path
}

func findVerifyPayloadPath(value any) string {
	switch typed := value.(type) {
	case map[string]any:
		for _, key := range []string{"path", "file"} {
			if raw, ok := typed[key].(string); ok && raw != "" {
				return raw
			}
		}
		for _, key := range []string{"raw", "payload", "event"} {
			if nested, ok := typed[key]; ok {
				if path := findVerifyPayloadPath(nested); path != "" {
					return path
				}
			}
		}
	case []any:
		for _, item := range typed {
			if path := findVerifyPayloadPath(item); path != "" {
				return path
			}
		}
	}
	return ""
}

func oneOf(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}
