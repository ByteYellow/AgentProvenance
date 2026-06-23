package provenance

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"text/tabwriter"
)

type TimelineOptions struct {
	RunID     string
	ToolCall  string
	ProcessID string
	Type      string
	Limit     int
}

type TimelineManifest struct {
	SchemaVersion string          `json:"schema_version"`
	RunID         string          `json:"run_id"`
	Filter        TimelineFilter  `json:"filter"`
	ResultSetID   string          `json:"result_set_id"`
	PageHash      string          `json:"page_hash"`
	EventCount    int             `json:"event_count"`
	Events        []TimelineEvent `json:"events"`
}

type TimelineFilter struct {
	ToolCall  string `json:"tool_call_id,omitempty"`
	ProcessID string `json:"process_id,omitempty"`
	Type      string `json:"type,omitempty"`
	Limit     int    `json:"limit,omitempty"`
}

type TimelineEvent struct {
	Time              string             `json:"time"`
	Type              string             `json:"type"`
	Source            string             `json:"source"`
	ID                string             `json:"id"`
	RunID             string             `json:"run_id"`
	SessionID         string             `json:"session_id,omitempty"`
	AttemptID         string             `json:"attempt_id,omitempty"`
	ToolCallID        string             `json:"tool_call_id,omitempty"`
	ProcessID         string             `json:"process_id,omitempty"`
	SnapshotID        string             `json:"snapshot_id,omitempty"`
	ObjectRef         string             `json:"object_ref,omitempty"`
	Summary           string             `json:"summary"`
	Evidence          map[string]any     `json:"evidence,omitempty"`
	Risk              map[string]any     `json:"risk,omitempty"`
	ExplainReplayRefs []ExplainReplayRef `json:"replay_refs,omitempty"`
}

func BuildTimeline(db *sql.DB, opts TimelineOptions) (TimelineManifest, error) {
	if opts.RunID == "" {
		return TimelineManifest{}, fmt.Errorf("run_id is required")
	}
	events := []TimelineEvent{}
	appenders := []func(*sql.DB, TimelineOptions, *[]TimelineEvent) error{
		appendTimelineToolCalls,
		appendTimelineProcesses,
		appendTimelineRuntimeEvents,
		appendTimelineEvidenceEvents,
		appendTimelinePolicyDecisions,
		appendTimelineRiskSignals,
		appendTimelineBaselineDeviations,
		appendTimelineResponseActions,
		appendTimelineExternalEffects,
	}
	for _, appendFn := range appenders {
		if err := appendFn(db, opts, &events); err != nil {
			return TimelineManifest{}, err
		}
	}
	events = filterTimeline(events, opts)
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].Time == events[j].Time {
			if events[i].Type == events[j].Type {
				return events[i].ID < events[j].ID
			}
			return events[i].Type < events[j].Type
		}
		return events[i].Time < events[j].Time
	})
	resultSetID, err := stableDigest(map[string]any{
		"kind":   "timeline_result_set",
		"run_id": opts.RunID,
		"filter": TimelineFilter{
			ToolCall:  opts.ToolCall,
			ProcessID: opts.ProcessID,
			Type:      opts.Type,
		},
		"events": timelineDigestEvents(events),
	})
	if err != nil {
		return TimelineManifest{}, err
	}
	if opts.Limit > 0 && len(events) > opts.Limit {
		events = events[:opts.Limit]
	}
	pageHash, err := stableDigest(map[string]any{
		"kind":          "timeline_page",
		"result_set_id": resultSetID,
		"limit":         opts.Limit,
		"events":        timelineDigestEvents(events),
	})
	if err != nil {
		return TimelineManifest{}, err
	}
	return TimelineManifest{
		SchemaVersion: "agentprovenance.timeline/v1",
		RunID:         opts.RunID,
		Filter: TimelineFilter{
			ToolCall:  opts.ToolCall,
			ProcessID: opts.ProcessID,
			Type:      opts.Type,
			Limit:     opts.Limit,
		},
		ResultSetID: resultSetID,
		PageHash:    pageHash,
		EventCount:  len(events),
		Events:      events,
	}, nil
}

func timelineDigestEvents(events []TimelineEvent) []map[string]string {
	out := make([]map[string]string, 0, len(events))
	for _, event := range events {
		out = append(out, map[string]string{
			"time":         event.Time,
			"type":         event.Type,
			"source":       event.Source,
			"id":           event.ID,
			"run_id":       event.RunID,
			"session_id":   event.SessionID,
			"attempt_id":   event.AttemptID,
			"tool_call_id": event.ToolCallID,
			"process_id":   event.ProcessID,
			"snapshot_id":  event.SnapshotID,
			"object_ref":   event.ObjectRef,
		})
	}
	return out
}

func PrintTimeline(db *sql.DB, opts TimelineOptions, out io.Writer) error {
	manifest, err := BuildTimeline(db, opts)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "run=%s schema=%s events=%d\n", manifest.RunID, manifest.SchemaVersion, manifest.EventCount)
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TIME\tTYPE\tSOURCE\tID\tSESSION\tATTEMPT\tTOOL_CALL\tPROCESS\tSUMMARY")
	for _, event := range manifest.Events {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			event.Time, event.Type, event.Source, event.ID, event.SessionID, event.AttemptID, event.ToolCallID, event.ProcessID, event.Summary)
	}
	return w.Flush()
}

func PrintTimelineJSON(db *sql.DB, opts TimelineOptions, out io.Writer) error {
	manifest, err := BuildTimeline(db, opts)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(manifest)
}

func appendTimelineToolCalls(db *sql.DB, opts TimelineOptions, events *[]TimelineEvent) error {
	rows, err := db.Query(`SELECT id, attempt_id, session_id, command, status, COALESCE(exit_code, -1), wall_ms, COALESCE(result_ref, ''), created_at, COALESCE(ended_at, '')
		FROM tool_calls WHERE run_id = ?`, opts.RunID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, attemptID, sessionID, command, status, resultRef, createdAt, endedAt string
		var exitCode int
		var wallMS int64
		if err := rows.Scan(&id, &attemptID, &sessionID, &command, &status, &exitCode, &wallMS, &resultRef, &createdAt, &endedAt); err != nil {
			return err
		}
		*events = append(*events, TimelineEvent{
			Time: createdAt, Type: "tool_call_start", Source: "application_context", ID: id, RunID: opts.RunID,
			SessionID: sessionID, AttemptID: attemptID, ToolCallID: id, ObjectRef: "tool_call/" + id,
			Summary:           fmt.Sprintf("command=%q status=%s", command, status),
			Evidence:          map[string]any{"command": command, "status": status},
			ExplainReplayRefs: []ExplainReplayRef{{Kind: "tool_call", ID: id, Ref: "graph explain --tool-call " + id}},
		})
		if endedAt != "" {
			*events = append(*events, TimelineEvent{
				Time: endedAt, Type: "tool_call_end", Source: "application_context", ID: id, RunID: opts.RunID,
				SessionID: sessionID, AttemptID: attemptID, ToolCallID: id, ObjectRef: "tool_call/" + id,
				Summary:           fmt.Sprintf("exit=%d wall_ms=%d result=%s", exitCode, wallMS, resultRef),
				Evidence:          map[string]any{"exit_code": exitCode, "wall_ms": wallMS, "result_ref": resultRef},
				ExplainReplayRefs: []ExplainReplayRef{{Kind: "tool_call", ID: id, Ref: "graph explain --tool-call " + id}},
			})
		}
	}
	return rows.Err()
}

func appendTimelineProcesses(db *sql.DB, opts TimelineOptions, events *[]TimelineEvent) error {
	rows, err := db.Query(`SELECT p.id, p.session_id, COALESCE(p.tool_call_id, ''), p.command, p.status, COALESCE(p.exit_code, -1), p.started_at, COALESCE(p.ended_at, '')
		FROM processes p JOIN sessions s ON p.session_id = s.id WHERE s.run_id = ?`, opts.RunID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, sessionID, toolCallID, command, status, startedAt, endedAt string
		var exitCode int
		if err := rows.Scan(&id, &sessionID, &toolCallID, &command, &status, &exitCode, &startedAt, &endedAt); err != nil {
			return err
		}
		*events = append(*events, TimelineEvent{
			Time: startedAt, Type: "process_start", Source: "runtime", ID: id, RunID: opts.RunID,
			SessionID: sessionID, ToolCallID: toolCallID, ProcessID: id, ObjectRef: "process/" + id,
			Summary:           fmt.Sprintf("command=%q", command),
			Evidence:          map[string]any{"command": command, "status": status},
			ExplainReplayRefs: []ExplainReplayRef{{Kind: "process", ID: id, Ref: "graph explain --process " + id}},
		})
		if endedAt != "" {
			*events = append(*events, TimelineEvent{
				Time: endedAt, Type: "process_end", Source: "runtime", ID: id, RunID: opts.RunID,
				SessionID: sessionID, ToolCallID: toolCallID, ProcessID: id, ObjectRef: "process/" + id,
				Summary:           fmt.Sprintf("status=%s exit=%d", status, exitCode),
				Evidence:          map[string]any{"status": status, "exit_code": exitCode},
				ExplainReplayRefs: []ExplainReplayRef{{Kind: "process", ID: id, Ref: "graph explain --process " + id}},
			})
		}
	}
	return rows.Err()
}

func appendTimelineRuntimeEvents(db *sql.DB, opts TimelineOptions, events *[]TimelineEvent) error {
	rows, err := db.Query(`SELECT id, COALESCE(session_id, ''), COALESCE(tool_call_id, ''), COALESCE(process_id, ''), COALESCE(snapshot_id, ''),
		source, event_type, COALESCE(raw_event_id, ''), COALESCE(correlation_method, ''), COALESCE(correlation_confidence, 0),
		COALESCE(container_id, ''), COALESCE(cgroup_id, ''), COALESCE(pid, 0), COALESCE(ppid, 0), COALESCE(payload, ''), created_at
		FROM events WHERE run_id = ?`, opts.RunID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, sessionID, toolCallID, processID, snapshotID, source, eventType, rawEventID, method, containerID, cgroupID, payload, createdAt string
		var confidence float64
		var pid, ppid int
		if err := rows.Scan(&id, &sessionID, &toolCallID, &processID, &snapshotID, &source, &eventType, &rawEventID, &method, &confidence, &containerID, &cgroupID, &pid, &ppid, &payload, &createdAt); err != nil {
			return err
		}
		summary := fmt.Sprintf("method=%s confidence=%.2f pid=%d ppid=%d", method, confidence, pid, ppid)
		evidence := map[string]any{"raw_event_id": rawEventID, "correlation_method": method, "correlation_confidence": confidence, "container_id": containerID, "cgroup_id": cgroupID, "pid": pid, "ppid": ppid}
		if source == "record_process_sample" && eventType == "process_observed" {
			summary, evidence = zeroSDKProcessObservationSummary(payload, evidence)
		}
		*events = append(*events, TimelineEvent{
			Time: createdAt, Type: eventType, Source: source, ID: id, RunID: opts.RunID,
			SessionID: sessionID, ToolCallID: toolCallID, ProcessID: processID, SnapshotID: snapshotID,
			ObjectRef:         "runtime_event/" + id,
			Summary:           summary,
			Evidence:          evidence,
			ExplainReplayRefs: []ExplainReplayRef{{Kind: "event", ID: id, Ref: "graph explain --event " + id}},
		})
	}
	return rows.Err()
}

func zeroSDKProcessObservationSummary(payload string, base map[string]any) (string, map[string]any) {
	var observed struct {
		PID          int64  `json:"pid"`
		RootPID      int64  `json:"root_pid"`
		PPID         int64  `json:"ppid"`
		Command      string `json:"command"`
		FirstSeen    string `json:"first_seen"`
		LastSeen     string `json:"last_seen"`
		OutlivedRoot bool   `json:"outlived_root"`
		CWD          string `json:"cwd"`
	}
	body := unwrapRecordProcessPayload(payload)
	if err := json.Unmarshal(body, &observed); err != nil {
		base["schema_status"] = "invalid_process_observation_payload"
		return fmt.Sprintf("zero_sdk_process_observed invalid_payload=%v", err), base
	}
	base["pid"] = observed.PID
	base["ppid"] = observed.PPID
	base["root_pid"] = observed.RootPID
	base["command"] = observed.Command
	base["first_seen"] = observed.FirstSeen
	base["last_seen"] = observed.LastSeen
	base["outlived_root"] = observed.OutlivedRoot
	base["cwd"] = observed.CWD
	base["scope_boundary"] = "root_pid_descendants+cwd+time_window"
	base["correlation_source"] = "zero_sdk_record_process_tree"
	base["schema_status"] = "valid"
	return fmt.Sprintf("zero_sdk_process_observed pid=%d ppid=%d outlived_root=%t command=%q",
		observed.PID, observed.PPID, observed.OutlivedRoot, observed.Command), base
}

func appendTimelineEvidenceEvents(db *sql.DB, opts TimelineOptions, events *[]TimelineEvent) error {
	rows, err := db.Query(`SELECT id, attempt_id, session_id, tool_call_id, snapshot_id, event_type, priority, status, created_at
		FROM evidence_events WHERE run_id = ?`, opts.RunID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, attemptID, sessionID, toolCallID, snapshotID, eventType, priority, status, createdAt string
		if err := rows.Scan(&id, &attemptID, &sessionID, &toolCallID, &snapshotID, &eventType, &priority, &status, &createdAt); err != nil {
			return err
		}
		*events = append(*events, TimelineEvent{
			Time: createdAt, Type: "evidence_" + eventType, Source: "evidence", ID: id, RunID: opts.RunID,
			SessionID: sessionID, AttemptID: attemptID, ToolCallID: toolCallID, SnapshotID: snapshotID,
			ObjectRef: "evidence/" + id,
			Summary:   fmt.Sprintf("priority=%s status=%s", priority, status),
			Evidence:  map[string]any{"event_type": eventType, "priority": priority, "status": status},
		})
	}
	return rows.Err()
}

func appendTimelinePolicyDecisions(db *sql.DB, opts TimelineOptions, events *[]TimelineEvent) error {
	rows, err := db.Query(`SELECT id, COALESCE(event_id, ''), COALESCE(session_id, ''), rule_id, decision, reason, created_at
		FROM policy_decisions WHERE run_id = ?`, opts.RunID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, eventID, sessionID, ruleID, decision, reason, createdAt string
		if err := rows.Scan(&id, &eventID, &sessionID, &ruleID, &decision, &reason, &createdAt); err != nil {
			return err
		}
		*events = append(*events, TimelineEvent{
			Time: createdAt, Type: "policy_decision", Source: "security", ID: id, RunID: opts.RunID,
			SessionID: sessionID, ObjectRef: "policy_decision/" + id,
			Summary:           fmt.Sprintf("decision=%s rule=%s reason=%s", decision, ruleID, reason),
			Evidence:          map[string]any{"event_id": eventID, "rule_id": ruleID, "decision": decision},
			Risk:              map[string]any{"decision": decision, "reason": reason},
			ExplainReplayRefs: []ExplainReplayRef{{Kind: "risk", ID: id, Ref: "graph explain --risk " + id}},
		})
	}
	return rows.Err()
}

func appendTimelineRiskSignals(db *sql.DB, opts TimelineOptions, events *[]TimelineEvent) error {
	rows, err := db.Query(`SELECT id, session_id, tool_call_id, process_id, snapshot_id, event_id, policy_decision_id, signal_type, severity, reason, recommended_action, created_at
		FROM risk_signals WHERE run_id = ?`, opts.RunID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, sessionID, toolCallID, processID, snapshotID, eventID, decisionID, signalType, severity, reason, action, createdAt string
		if err := rows.Scan(&id, &sessionID, &toolCallID, &processID, &snapshotID, &eventID, &decisionID, &signalType, &severity, &reason, &action, &createdAt); err != nil {
			return err
		}
		*events = append(*events, TimelineEvent{
			Time: createdAt, Type: "risk_signal", Source: "security", ID: id, RunID: opts.RunID,
			SessionID: sessionID, ToolCallID: toolCallID, ProcessID: processID, SnapshotID: snapshotID, ObjectRef: "risk_signal/" + id,
			Summary:  fmt.Sprintf("%s severity=%s action=%s", signalType, severity, action),
			Evidence: map[string]any{"event_id": eventID, "policy_decision_id": decisionID},
			Risk:     map[string]any{"signal_type": signalType, "severity": severity, "reason": reason, "recommended_action": action},
		})
	}
	return rows.Err()
}

func appendTimelineBaselineDeviations(db *sql.DB, opts TimelineOptions, events *[]TimelineEvent) error {
	rows, err := db.Query(`SELECT id, template_name, profile_id, deviation_type, status, expected_value, observed_value, recommended_action, created_at
		FROM baseline_deviations WHERE run_id = ?`, opts.RunID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, templateName, profileID, deviationType, status, action, createdAt string
		var expected, observed float64
		if err := rows.Scan(&id, &templateName, &profileID, &deviationType, &status, &expected, &observed, &action, &createdAt); err != nil {
			return err
		}
		*events = append(*events, TimelineEvent{
			Time: createdAt, Type: "baseline_deviation", Source: "security", ID: id, RunID: opts.RunID,
			ObjectRef: "baseline_deviation/" + id,
			Summary:   fmt.Sprintf("%s status=%s expected=%.3f observed=%.3f", deviationType, status, expected, observed),
			Risk:      map[string]any{"template_name": templateName, "profile_id": profileID, "deviation_type": deviationType, "status": status, "expected_value": expected, "observed_value": observed, "recommended_action": action},
		})
	}
	return rows.Err()
}

func appendTimelineResponseActions(db *sql.DB, opts TimelineOptions, events *[]TimelineEvent) error {
	rows, err := db.Query(`SELECT id, session_id, process_id, snapshot_id, risk_signal_id, policy_decision_id, action_type, target_type, target_id, status, result_ref, created_at
		FROM response_actions WHERE run_id = ?`, opts.RunID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, sessionID, processID, snapshotID, riskID, decisionID, actionType, targetType, targetID, status, resultRef, createdAt string
		if err := rows.Scan(&id, &sessionID, &processID, &snapshotID, &riskID, &decisionID, &actionType, &targetType, &targetID, &status, &resultRef, &createdAt); err != nil {
			return err
		}
		*events = append(*events, TimelineEvent{
			Time: createdAt, Type: "response_action", Source: "security", ID: id, RunID: opts.RunID,
			SessionID: sessionID, ProcessID: processID, SnapshotID: snapshotID, ObjectRef: "response_action/" + id,
			Summary:  fmt.Sprintf("%s target=%s/%s status=%s", actionType, targetType, targetID, status),
			Evidence: map[string]any{"risk_signal_id": riskID, "policy_decision_id": decisionID, "result_ref": resultRef},
			Risk:     map[string]any{"action_type": actionType, "target_type": targetType, "target_id": targetID, "status": status},
		})
	}
	return rows.Err()
}

func appendTimelineExternalEffects(db *sql.DB, opts TimelineOptions, events *[]TimelineEvent) error {
	rows, err := db.Query(`SELECT id, attempt_id, session_id, tool_call_id, process_id, effect_type, target, mode, decision, status, created_at
		FROM external_effects WHERE run_id = ?`, opts.RunID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, attemptID, sessionID, toolCallID, processID, effectType, target, mode, decision, status, createdAt string
		if err := rows.Scan(&id, &attemptID, &sessionID, &toolCallID, &processID, &effectType, &target, &mode, &decision, &status, &createdAt); err != nil {
			return err
		}
		*events = append(*events, TimelineEvent{
			Time: createdAt, Type: "external_effect", Source: "effect", ID: id, RunID: opts.RunID,
			SessionID: sessionID, AttemptID: attemptID, ToolCallID: toolCallID, ProcessID: processID, ObjectRef: "external_effect/" + id,
			Summary:  fmt.Sprintf("%s target=%s mode=%s decision=%s status=%s", effectType, target, mode, decision, status),
			Evidence: map[string]any{"effect_type": effectType, "target": target, "mode": mode, "decision": decision, "status": status},
		})
	}
	return rows.Err()
}

func filterTimeline(events []TimelineEvent, opts TimelineOptions) []TimelineEvent {
	filtered := make([]TimelineEvent, 0, len(events))
	for _, event := range events {
		if opts.ToolCall != "" && event.ToolCallID != opts.ToolCall {
			continue
		}
		if opts.ProcessID != "" && event.ProcessID != opts.ProcessID {
			continue
		}
		if opts.Type != "" && event.Type != opts.Type {
			continue
		}
		filtered = append(filtered, event)
	}
	return filtered
}
