package compliance

import (
	"database/sql"
	"fmt"
	"strings"
)

type EvidenceIndex struct {
	byKind map[string][]EvidenceRef
}

func ResolveEvidence(db *sql.DB, runID string) (EvidenceIndex, error) {
	index := EvidenceIndex{byKind: map[string][]EvidenceRef{}}
	if err := index.loadToolCalls(db, runID); err != nil {
		return index, err
	}
	if err := index.loadSessions(db, runID); err != nil {
		return index, err
	}
	if err := index.loadProcesses(db, runID); err != nil {
		return index, err
	}
	if err := index.loadBindings(db, runID); err != nil {
		return index, err
	}
	if err := index.loadRuntimeEvents(db, runID); err != nil {
		return index, err
	}
	if err := index.loadPolicyDecisions(db, runID); err != nil {
		return index, err
	}
	if err := index.loadRiskSignals(db, runID); err != nil {
		return index, err
	}
	if err := index.loadBaselineDeviations(db, runID); err != nil {
		return index, err
	}
	if err := index.loadResponseActions(db, runID); err != nil {
		return index, err
	}
	if err := index.loadForensicsBundles(db, runID); err != nil {
		return index, err
	}
	if err := index.loadProvenanceObjects(db, runID); err != nil {
		return index, err
	}
	if err := index.loadGraphEdges(db, runID); err != nil {
		return index, err
	}
	if err := index.loadSnapshots(db, runID); err != nil {
		return index, err
	}
	if err := index.loadTelemetryBatches(db, runID); err != nil {
		return index, err
	}
	index.deriveSyntheticKinds()
	return index, nil
}

func (i EvidenceIndex) Refs(kinds ...string) []EvidenceRef {
	seen := map[string]bool{}
	var out []EvidenceRef
	for _, kind := range kinds {
		for _, ref := range i.byKind[kind] {
			if seen[ref.Ref] {
				continue
			}
			seen[ref.Ref] = true
			out = append(out, ref)
		}
	}
	return out
}

func (i EvidenceIndex) RequiredRefs(kinds ...string) ([]EvidenceRef, bool) {
	seen := map[string]bool{}
	var out []EvidenceRef
	for _, kind := range kinds {
		refs := i.byKind[kind]
		if len(refs) == 0 {
			return out, false
		}
		for _, ref := range refs {
			if seen[ref.Ref] {
				continue
			}
			seen[ref.Ref] = true
			out = append(out, ref)
		}
	}
	return out, true
}

func (i EvidenceIndex) add(kind, id, summary string) {
	if id == "" {
		return
	}
	i.byKind[kind] = append(i.byKind[kind], EvidenceRef{
		Ref:     kind + "/" + id,
		Kind:    kind,
		ID:      id,
		Summary: summary,
	})
}

func (i EvidenceIndex) addAlias(kind string, ref EvidenceRef) {
	ref.Kind = kind
	ref.Ref = kind + "/" + ref.ID
	i.byKind[kind] = append(i.byKind[kind], ref)
}

func (i EvidenceIndex) loadToolCalls(db *sql.DB, runID string) error {
	rows, err := db.Query(`SELECT id, command, status FROM tool_calls WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, command, status string
		if err := rows.Scan(&id, &command, &status); err != nil {
			return err
		}
		i.add("tool_call", id, fmt.Sprintf("status=%s command=%q", status, command))
	}
	return rows.Err()
}

func (i EvidenceIndex) loadSessions(db *sql.DB, runID string) error {
	rows, err := db.Query(`SELECT id, runtime, status FROM sessions WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, runtime, status string
		if err := rows.Scan(&id, &runtime, &status); err != nil {
			return err
		}
		i.add("session", id, fmt.Sprintf("runtime=%s status=%s", runtime, status))
	}
	return rows.Err()
}

func (i EvidenceIndex) loadProcesses(db *sql.DB, runID string) error {
	rows, err := db.Query(`SELECT p.id, COALESCE(p.tool_call_id, ''), p.command, p.status
		FROM processes p JOIN sessions s ON p.session_id = s.id WHERE s.run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, toolCallID, command, status string
		if err := rows.Scan(&id, &toolCallID, &command, &status); err != nil {
			return err
		}
		i.add("process", id, fmt.Sprintf("tool_call=%s status=%s command=%q", toolCallID, status, command))
	}
	return rows.Err()
}

func (i EvidenceIndex) loadBindings(db *sql.DB, runID string) error {
	rows, err := db.Query(`SELECT id, tool_call_id, process_id, container_id, cgroup_id, pid FROM execution_context_bindings WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, toolCallID, processID, containerID, cgroupID string
		var pid int64
		if err := rows.Scan(&id, &toolCallID, &processID, &containerID, &cgroupID, &pid); err != nil {
			return err
		}
		i.add("binding", id, fmt.Sprintf("tool_call=%s process=%s container=%s cgroup=%s pid=%d", toolCallID, processID, containerID, cgroupID, pid))
	}
	return rows.Err()
}

func (i EvidenceIndex) loadRuntimeEvents(db *sql.DB, runID string) error {
	rows, err := db.Query(`SELECT id, source, event_type, tool_call_id, process_id FROM events WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, source, eventType, toolCallID, processID string
		if err := rows.Scan(&id, &source, &eventType, &toolCallID, &processID); err != nil {
			return err
		}
		summary := fmt.Sprintf("%s source=%s tool_call=%s process=%s", eventType, source, toolCallID, processID)
		i.add("runtime_event", id, summary)
		switch eventType {
		case "exec_start", "execve", "process_observed":
			i.addAlias("exec_event", EvidenceRef{ID: id, Summary: summary})
		case "file_write", "file_open", "secret_path":
			i.addAlias("diff_blame", EvidenceRef{ID: id, Summary: summary})
		}
		if eventType == "metadata_ip" || eventType == "private_cidr" || eventType == "secret_path" || eventType == "abnormal_process_tree" {
			i.addAlias("suspicious_runtime", EvidenceRef{ID: id, Summary: summary})
		}
		if source == "record_file_diff" {
			i.addAlias("diff_blame", EvidenceRef{ID: id, Summary: summary})
		}
		if strings.Contains(eventType, "credential") {
			i.addAlias("credential_event", EvidenceRef{ID: id, Summary: summary})
		}
		if strings.Contains(eventType, "inter_agent") || strings.Contains(eventType, "a2a") {
			i.addAlias("inter_agent_event", EvidenceRef{ID: id, Summary: summary})
		}
	}
	return rows.Err()
}

func (i EvidenceIndex) loadPolicyDecisions(db *sql.DB, runID string) error {
	rows, err := db.Query(`SELECT id, rule_id, decision, reason FROM policy_decisions WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, ruleID, decision, reason string
		if err := rows.Scan(&id, &ruleID, &decision, &reason); err != nil {
			return err
		}
		i.add("policy_decision", id, fmt.Sprintf("decision=%s rule=%s reason=%s", decision, ruleID, reason))
		if strings.Contains(ruleID, "trust") {
			i.addAlias("trust_decision", EvidenceRef{ID: id, Summary: reason})
		}
	}
	return rows.Err()
}

func (i EvidenceIndex) loadRiskSignals(db *sql.DB, runID string) error {
	rows, err := db.Query(`SELECT id, signal_type, severity, reason, recommended_action FROM risk_signals WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, signalType, severity, reason, action string
		if err := rows.Scan(&id, &signalType, &severity, &reason, &action); err != nil {
			return err
		}
		i.add("risk_signal", id, fmt.Sprintf("%s severity=%s action=%s reason=%s", signalType, severity, action, reason))
	}
	return rows.Err()
}

func (i EvidenceIndex) loadBaselineDeviations(db *sql.DB, runID string) error {
	rows, err := db.Query(`SELECT id, deviation_type, status, recommended_action FROM baseline_deviations WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, deviationType, status, action string
		if err := rows.Scan(&id, &deviationType, &status, &action); err != nil {
			return err
		}
		i.add("baseline_deviation", id, fmt.Sprintf("%s status=%s action=%s", deviationType, status, action))
	}
	return rows.Err()
}

func (i EvidenceIndex) loadResponseActions(db *sql.DB, runID string) error {
	rows, err := db.Query(`SELECT id, action_type, target_type, target_id, status FROM response_actions WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, actionType, targetType, targetID, status string
		if err := rows.Scan(&id, &actionType, &targetType, &targetID, &status); err != nil {
			return err
		}
		i.add("response_action", id, fmt.Sprintf("%s target=%s/%s status=%s", actionType, targetType, targetID, status))
	}
	return rows.Err()
}

func (i EvidenceIndex) loadForensicsBundles(db *sql.DB, runID string) error {
	rows, err := db.Query(`SELECT id, sha256, status FROM forensics_bundles WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, sha, status string
		if err := rows.Scan(&id, &sha, &status); err != nil {
			return err
		}
		i.add("forensics_bundle", id, fmt.Sprintf("status=%s sha256=%s", status, sha))
	}
	return rows.Err()
}

func (i EvidenceIndex) loadProvenanceObjects(db *sql.DB, runID string) error {
	rows, err := db.Query(`SELECT hash, object_type, source_id FROM provenance_objects WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var hash, objectType, sourceID string
		if err := rows.Scan(&hash, &objectType, &sourceID); err != nil {
			return err
		}
		i.add("provenance_object", hash, fmt.Sprintf("type=%s source=%s", objectType, sourceID))
		if strings.Contains(objectType, "artifact") {
			i.addAlias("artifact", EvidenceRef{ID: hash, Summary: fmt.Sprintf("type=%s source=%s", objectType, sourceID)})
		}
	}
	return rows.Err()
}

func (i EvidenceIndex) loadGraphEdges(db *sql.DB, runID string) error {
	rows, err := db.Query(`SELECT id, from_id, to_id, edge_type FROM graph_edges WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, fromID, toID, edgeType string
		if err := rows.Scan(&id, &fromID, &toID, &edgeType); err != nil {
			return err
		}
		i.add("graph_edge", id, fmt.Sprintf("%s %s -> %s", edgeType, fromID, toID))
	}
	return rows.Err()
}

func (i EvidenceIndex) loadSnapshots(db *sql.DB, runID string) error {
	rows, err := db.Query(`SELECT DISTINCT s.id, s.status, s.kind
		FROM snapshots s
		LEFT JOIN sessions sess ON sess.parent_snapshot_id = s.id OR sess.resumed_from_snapshot_id = s.id
		LEFT JOIN rollouts r ON r.base_snapshot_id = s.id
		WHERE sess.run_id = ? OR r.run_id = ?`, runID, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, status, kind string
		if err := rows.Scan(&id, &status, &kind); err != nil {
			return err
		}
		i.add("snapshot", id, fmt.Sprintf("kind=%s status=%s", kind, status))
		if status == "tainted" {
			i.addAlias("taint", EvidenceRef{ID: id, Summary: "snapshot tainted"})
		}
	}
	return rows.Err()
}

func (i EvidenceIndex) loadTelemetryBatches(db *sql.DB, runID string) error {
	rows, err := db.Query(`SELECT id, format, ingested_count, failed_count FROM telemetry_batches WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, format string
		var ingested, failed int
		if err := rows.Scan(&id, &format, &ingested, &failed); err != nil {
			return err
		}
		i.add("telemetry_batch", id, fmt.Sprintf("format=%s ingested=%d failed=%d", format, ingested, failed))
	}
	return rows.Err()
}

func (i EvidenceIndex) deriveSyntheticKinds() {
	if len(i.byKind["runtime_event"]) > 0 || len(i.byKind["tool_call"]) > 0 || len(i.byKind["risk_signal"]) > 0 {
		i.add("timeline", "run", "timeline can be built from run evidence")
	}
	if len(i.byKind["graph_edge"]) > 0 || len(i.byKind["provenance_object"]) > 0 {
		i.add("explainable_graph", "run", "graph trace/explain evidence is available")
	}
	if len(i.byKind["tool_call"]) > 0 && len(i.byKind["inter_agent_event"]) == 0 {
		i.add("single_agent_run", "run", "no inter-agent evidence found for this run")
	}
	if len(i.byKind["session"]) > 0 || len(i.byKind["runtime_event"]) > 0 {
		i.add("resource_evidence", "run", "runtime/session evidence can support resource or cascade analysis")
	}
}
