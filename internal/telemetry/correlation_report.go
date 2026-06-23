package telemetry

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/correlation"
)

type CorrelationReportOptions struct {
	RunID   string
	EventID string
}

type CorrelationReport struct {
	SchemaVersion string                `json:"schema_version"`
	RunID         string                `json:"run_id,omitempty"`
	EventID       string                `json:"event_id,omitempty"`
	ResultSetID   string                `json:"result_set_id"`
	PageHash      string                `json:"page_hash"`
	Count         int                   `json:"count"`
	Items         []CorrelationEvidence `json:"correlations"`
}

type CorrelationEvidence struct {
	Event           CorrelationEvent    `json:"event"`
	RawIdentity     CorrelationIdentity `json:"raw_identity"`
	ResolvedContext CorrelationContext  `json:"resolved_context"`
	Binding         *CorrelationBinding `json:"binding,omitempty"`
	Match           CorrelationMatch    `json:"match"`
	Drilldowns      []string            `json:"drilldowns,omitempty"`
}

type CorrelationEvent struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Source     string `json:"source"`
	RawEventID string `json:"raw_event_id,omitempty"`
	CreatedAt  string `json:"created_at"`
}

type CorrelationIdentity struct {
	RunID       string   `json:"run_id,omitempty"`
	ProcessID   string   `json:"process_id,omitempty"`
	ContainerID string   `json:"container_id,omitempty"`
	CgroupID    string   `json:"cgroup_id,omitempty"`
	PID         int64    `json:"pid,omitempty"`
	TGID        int64    `json:"tgid,omitempty"`
	PPID        int64    `json:"ppid,omitempty"`
	Keys        []string `json:"keys,omitempty"`
}

type CorrelationContext struct {
	RunID      string `json:"run_id,omitempty"`
	SessionID  string `json:"session_id,omitempty"`
	AttemptID  string `json:"attempt_id,omitempty"`
	ToolCallID string `json:"tool_call_id,omitempty"`
	ProcessID  string `json:"process_id,omitempty"`
	SnapshotID string `json:"snapshot_id,omitempty"`
}

type CorrelationBinding struct {
	ID            string   `json:"id"`
	RunID         string   `json:"run_id,omitempty"`
	SessionID     string   `json:"session_id,omitempty"`
	AttemptID     string   `json:"attempt_id,omitempty"`
	ToolCallID    string   `json:"tool_call_id,omitempty"`
	ProcessID     string   `json:"process_id,omitempty"`
	ContainerID   string   `json:"container_id,omitempty"`
	CgroupID      string   `json:"cgroup_id,omitempty"`
	RootPID       int64    `json:"root_pid,omitempty"`
	PID           int64    `json:"pid,omitempty"`
	StartedAt     string   `json:"started_at,omitempty"`
	EndedAt       string   `json:"ended_at,omitempty"`
	BindingSource string   `json:"binding_source,omitempty"`
	Confidence    float64  `json:"confidence"`
	IdentityKeys  []string `json:"identity_keys,omitempty"`
}

type CorrelationMatch struct {
	Status      string   `json:"status"`
	Method      string   `json:"method"`
	Confidence  float64  `json:"confidence"`
	BindingID   string   `json:"binding_id,omitempty"`
	MatchedKeys []string `json:"matched_keys,omitempty"`
	Reason      string   `json:"reason"`
	TimeWindow  string   `json:"time_window,omitempty"`
}

func BuildCorrelationReport(db *sql.DB, opts CorrelationReportOptions) (CorrelationReport, error) {
	events, err := correlationReportEvents(db, opts)
	if err != nil {
		return CorrelationReport{}, err
	}
	items := make([]CorrelationEvidence, 0, len(events))
	for _, event := range events {
		item, err := buildCorrelationEvidence(db, event)
		if err != nil {
			return CorrelationReport{}, err
		}
		items = append(items, item)
	}
	report := CorrelationReport{
		SchemaVersion: "agentprovenance.telemetry_correlations/v1",
		RunID:         opts.RunID,
		EventID:       opts.EventID,
		Count:         len(items),
		Items:         items,
	}
	resultSetID, pageHash, err := correlationReportIntegrity(report)
	if err == nil {
		report.ResultSetID = resultSetID
		report.PageHash = pageHash
	}
	return report, nil
}

func correlationReportEvents(db *sql.DB, opts CorrelationReportOptions) ([]EventRecord, error) {
	filter := Filter{RunID: opts.RunID}
	if opts.EventID == "" {
		return ListEventsFiltered(db, filter)
	}
	var event EventRecord
	err := db.QueryRow(`SELECT id, COALESCE(run_id, ''), COALESCE(session_id, ''), COALESCE(tool_call_id, ''),
		COALESCE(process_id, ''), COALESCE(snapshot_id, ''), COALESCE(raw_event_id, ''),
		COALESCE(correlation_method, ''), COALESCE(correlation_confidence, 0),
		COALESCE(container_id, ''), COALESCE(cgroup_id, ''), COALESCE(pid, 0),
		COALESCE(tgid, 0), COALESCE(ppid, 0),
		source, event_type, payload, created_at
		FROM events WHERE id = ?`, opts.EventID).Scan(&event.ID, &event.RunID, &event.SessionID, &event.ToolCallID,
		&event.ProcessID, &event.SnapshotID, &event.RawEventID, &event.CorrelationMethod, &event.CorrelationConfidence,
		&event.ContainerID, &event.CgroupID, &event.PID, &event.TGID, &event.PPID, &event.Source, &event.EventType,
		&event.Payload, &event.CreatedAt)
	if err != nil {
		return nil, err
	}
	if opts.RunID != "" && event.RunID != opts.RunID {
		return nil, fmt.Errorf("event %s is not in run %s", opts.EventID, opts.RunID)
	}
	return []EventRecord{event}, nil
}

func buildCorrelationEvidence(db *sql.DB, event EventRecord) (CorrelationEvidence, error) {
	bindingID := correlationBindingID(event.Payload)
	if bindingID == "" && correlationStatus(event) == "resolved" {
		match, ok, err := correlation.Resolve(db, correlation.RawIdentity{
			RunID:       event.RunID,
			ProcessID:   event.ProcessID,
			ContainerID: event.ContainerID,
			CgroupID:    event.CgroupID,
			PID:         event.PID,
			TGID:        event.TGID,
			PPID:        event.PPID,
			Timestamp:   event.CreatedAt,
		})
		if err != nil {
			return CorrelationEvidence{}, err
		}
		if ok {
			bindingID = match.ID
		}
	}
	var binding *CorrelationBinding
	if bindingID != "" {
		found, ok, err := correlation.GetBinding(db, bindingID)
		if err != nil {
			return CorrelationEvidence{}, err
		}
		if ok {
			view := bindingView(found)
			binding = &view
		}
	}
	match := CorrelationMatch{
		Status:      correlationStatus(event),
		Method:      event.CorrelationMethod,
		Confidence:  event.CorrelationConfidence,
		BindingID:   bindingID,
		MatchedKeys: matchedCorrelationKeys(event.CorrelationMethod),
		Reason:      correlationReason(event, bindingID),
	}
	if binding != nil {
		match.TimeWindow = binding.StartedAt + ".." + binding.EndedAt
	}
	return CorrelationEvidence{
		Event: CorrelationEvent{
			ID: event.ID, Type: event.EventType, Source: event.Source, RawEventID: event.RawEventID, CreatedAt: event.CreatedAt,
		},
		RawIdentity: CorrelationIdentity{
			RunID: event.RunID, ProcessID: event.ProcessID, ContainerID: event.ContainerID, CgroupID: event.CgroupID,
			PID: event.PID, TGID: event.TGID, PPID: event.PPID, Keys: eventIdentityKeys(event),
		},
		ResolvedContext: CorrelationContext{
			RunID: event.RunID, SessionID: event.SessionID, ToolCallID: event.ToolCallID, ProcessID: event.ProcessID, SnapshotID: event.SnapshotID,
		},
		Binding:    binding,
		Match:      match,
		Drilldowns: correlationDrilldowns(event),
	}, nil
}

func bindingView(binding correlation.Binding) CorrelationBinding {
	record := EventRecord{ProcessID: binding.ProcessID, ContainerID: binding.ContainerID, CgroupID: binding.CgroupID, PID: binding.PID}
	return CorrelationBinding{
		ID: binding.ID, RunID: binding.RunID, SessionID: binding.SessionID, AttemptID: binding.AttemptID,
		ToolCallID: binding.ToolCallID, ProcessID: binding.ProcessID, ContainerID: binding.ContainerID,
		CgroupID: binding.CgroupID, RootPID: binding.RootPID, PID: binding.PID, StartedAt: binding.StartedAt,
		EndedAt: binding.EndedAt, BindingSource: binding.BindingSource, Confidence: binding.Confidence,
		IdentityKeys: eventIdentityKeys(record),
	}
}

func correlationBindingID(payload string) string {
	var decoded struct {
		Correlation struct {
			BindingID string `json:"binding_id"`
		} `json:"correlation"`
	}
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		return ""
	}
	return strings.TrimSpace(decoded.Correlation.BindingID)
}

func correlationStatus(event EventRecord) string {
	if event.CorrelationMethod == "" || event.CorrelationMethod == "unresolved" || event.CorrelationConfidence == 0 {
		return "unresolved"
	}
	if event.CorrelationMethod == "provided_context" {
		return "provided"
	}
	return "resolved"
}

func matchedCorrelationKeys(method string) []string {
	if method == "" {
		return nil
	}
	parts := strings.Split(method, ":")
	if len(parts) != 2 {
		return []string{method}
	}
	keys := strings.Split(parts[1], "+")
	sort.Strings(keys)
	return keys
}

func correlationReason(event EventRecord, bindingID string) string {
	switch correlationStatus(event) {
	case "resolved":
		return "runtime identity matched ToolCallScope binding"
	case "provided":
		return "application context was provided with the telemetry event"
	default:
		return "no ToolCallScope binding matched the raw runtime identity"
	}
}

func correlationDrilldowns(event EventRecord) []string {
	out := []string{"graph explain --event " + event.ID}
	if event.RunID != "" {
		out = append(out, "observe event --run "+event.RunID+" --event "+event.ID)
	}
	if event.ProcessID != "" && event.RunID != "" {
		out = append(out, "observe process --run "+event.RunID+" --process "+event.ProcessID)
	}
	if event.ToolCallID != "" && event.RunID != "" {
		out = append(out, "timeline --run "+event.RunID+" --tool-call "+event.ToolCallID+" --view causality")
	}
	return out
}

func correlationReportIntegrity(report CorrelationReport) (string, string, error) {
	resultSetID, err := digestCorrelation(map[string]any{
		"kind":     "telemetry_correlations_result_set",
		"run_id":   report.RunID,
		"event_id": report.EventID,
		"items":    report.Items,
	})
	if err != nil {
		return "", "", err
	}
	pageHash, err := digestCorrelation(map[string]any{
		"kind":          "telemetry_correlations_page",
		"result_set_id": resultSetID,
		"items":         report.Items,
	})
	if err != nil {
		return "", "", err
	}
	return resultSetID, pageHash, nil
}

func digestCorrelation(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
