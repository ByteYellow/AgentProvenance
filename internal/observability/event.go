package observability

import (
	"database/sql"
	"fmt"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

const EventSchemaVersion = "agentprovenance.observability_event/v1"

type EventOptions struct {
	RunID   string
	EventID string
}

type EventReport struct {
	SchemaVersion    string            `json:"schema_version"`
	RunID            string            `json:"run_id"`
	Event            EventDetail       `json:"event"`
	Context          EventContext      `json:"context"`
	RelatedRisks     []EvidenceSummary `json:"related_risks,omitempty"`
	RelatedPolicies  []EvidenceSummary `json:"related_policies,omitempty"`
	RelatedResponses []EvidenceSummary `json:"related_responses,omitempty"`
	RecommendedViews []string          `json:"recommended_views"`
}

type EventDetail struct {
	ID                    string         `json:"id"`
	Type                  string         `json:"type"`
	Source                string         `json:"source"`
	Time                  string         `json:"time"`
	Summary               string         `json:"summary"`
	ObjectRef             string         `json:"object_ref,omitempty"`
	CorrelationMethod     string         `json:"correlation_method,omitempty"`
	CorrelationConfidence float64        `json:"correlation_confidence,omitempty"`
	Evidence              map[string]any `json:"evidence,omitempty"`
}

type EventContext struct {
	SessionID  string `json:"session_id,omitempty"`
	AttemptID  string `json:"attempt_id,omitempty"`
	ToolCallID string `json:"tool_call_id,omitempty"`
	ProcessID  string `json:"process_id,omitempty"`
	SnapshotID string `json:"snapshot_id,omitempty"`
}

func BuildEvent(db *sql.DB, opts EventOptions) (EventReport, error) {
	if opts.EventID == "" {
		return EventReport{}, fmt.Errorf("event id is required")
	}
	manifest, err := provenance.BuildTimeline(db, provenance.TimelineOptions{RunID: opts.RunID})
	if err != nil {
		return EventReport{}, err
	}
	return BuildEventFromTimeline(manifest, opts)
}

func BuildEventFromTimeline(manifest provenance.TimelineManifest, opts EventOptions) (EventReport, error) {
	event, ok := findTimelineEvent(manifest.Events, opts.EventID)
	if !ok {
		return EventReport{}, fmt.Errorf("event %q not found in run %q", opts.EventID, manifest.RunID)
	}
	toolCallID := resolveToolCallForEvent(manifest.Events, event)
	context := EventContext{
		SessionID:  event.SessionID,
		AttemptID:  event.AttemptID,
		ToolCallID: toolCallID,
		ProcessID:  event.ProcessID,
		SnapshotID: event.SnapshotID,
	}
	if context.ToolCallID == "" {
		context.ToolCallID = event.ToolCallID
	}
	report := EventReport{
		SchemaVersion: EventSchemaVersion,
		RunID:         manifest.RunID,
		Event: EventDetail{
			ID:                    event.ID,
			Type:                  event.Type,
			Source:                event.Source,
			Time:                  event.Time,
			Summary:               event.Summary,
			ObjectRef:             event.ObjectRef,
			CorrelationMethod:     stringValue(event.Evidence, "correlation_method"),
			CorrelationConfidence: floatValue(event.Evidence, "correlation_confidence"),
			Evidence:              event.Evidence,
		},
		Context: context,
	}
	directRiskIDs := map[string]bool{}
	directPolicyIDs := map[string]bool{}
	for _, candidate := range manifest.Events {
		if candidate.Type == "risk_signal" && stringValue(candidate.Evidence, "event_id") == event.ID {
			report.RelatedRisks = append(report.RelatedRisks, evidenceSummary(candidate))
			directRiskIDs[candidate.ID] = true
		}
		if candidate.Type == "policy_decision" && stringValue(candidate.Evidence, "event_id") == event.ID {
			report.RelatedPolicies = append(report.RelatedPolicies, evidenceSummary(candidate))
			directPolicyIDs[candidate.ID] = true
		}
	}
	for _, candidate := range manifest.Events {
		if candidate.Type != "response_action" {
			continue
		}
		if directRiskIDs[stringValue(candidate.Evidence, "risk_signal_id")] || directPolicyIDs[stringValue(candidate.Evidence, "policy_decision_id")] {
			report.RelatedResponses = append(report.RelatedResponses, evidenceSummary(candidate))
		}
	}
	report.RecommendedViews = eventDrilldowns(manifest.RunID, report)
	return report, nil
}

func findTimelineEvent(events []provenance.TimelineEvent, eventID string) (provenance.TimelineEvent, bool) {
	for _, event := range events {
		if event.ID == eventID {
			return event, true
		}
	}
	return provenance.TimelineEvent{}, false
}

func resolveToolCallForEvent(events []provenance.TimelineEvent, target provenance.TimelineEvent) string {
	if target.ToolCallID != "" {
		return target.ToolCallID
	}
	if target.ProcessID != "" {
		for _, event := range events {
			if event.ProcessID == target.ProcessID && event.ToolCallID != "" {
				return event.ToolCallID
			}
		}
	}
	return ""
}

func evidenceSummary(event provenance.TimelineEvent) EvidenceSummary {
	return EvidenceSummary{Ref: event.ObjectRef, Type: event.Type, Source: event.Source, Summary: event.Summary}
}

func eventDrilldowns(runID string, report EventReport) []string {
	views := []string{"timeline --run " + runID + " --type " + report.Event.Type, "graph explain --event " + report.Event.ID}
	if report.Context.ToolCallID != "" {
		views = append(views, "timeline --run "+runID+" --tool-call "+report.Context.ToolCallID)
	}
	if report.Context.ProcessID != "" {
		views = append(views, "timeline --run "+runID+" --process "+report.Context.ProcessID)
	}
	if len(report.RelatedRisks) > 0 {
		views = append(views, "security risks --run "+runID)
	}
	if len(report.RelatedResponses) > 0 {
		views = append(views, "security responses --run "+runID)
	}
	return views
}

func stringValue(values map[string]any, key string) string {
	value, ok := values[key]
	if !ok {
		return ""
	}
	text, _ := value.(string)
	return text
}

func floatValue(values map[string]any, key string) float64 {
	value, ok := values[key]
	if !ok {
		return 0
	}
	number, _ := value.(float64)
	return number
}
