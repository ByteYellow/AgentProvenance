package observability

import (
	"database/sql"
	"fmt"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

const ProcessSchemaVersion = "agentprovenance.observability_process/v1"

type ProcessOptions struct {
	RunID     string
	ProcessID string
}

type ProcessReport struct {
	SchemaVersion    string            `json:"schema_version"`
	RunID            string            `json:"run_id"`
	ResultSetID      string            `json:"result_set_id"`
	PageHash         string            `json:"page_hash"`
	Process          ProcessDetail     `json:"process"`
	Context          EventContext      `json:"context"`
	RuntimeEvents    []EvidenceSummary `json:"runtime_events,omitempty"`
	RelatedRisks     []EvidenceSummary `json:"related_risks,omitempty"`
	RelatedPolicies  []EvidenceSummary `json:"related_policies,omitempty"`
	RelatedResponses []EvidenceSummary `json:"related_responses,omitempty"`
	RecommendedViews []string          `json:"recommended_views"`
}

type ProcessDetail struct {
	ID        string         `json:"id"`
	StartedAt string         `json:"started_at,omitempty"`
	EndedAt   string         `json:"ended_at,omitempty"`
	Summary   string         `json:"summary,omitempty"`
	Evidence  map[string]any `json:"evidence,omitempty"`
	ObjectRef string         `json:"object_ref,omitempty"`
}

func BuildProcess(db *sql.DB, opts ProcessOptions) (ProcessReport, error) {
	if opts.ProcessID == "" {
		return ProcessReport{}, fmt.Errorf("process id is required")
	}
	manifest, err := provenance.BuildTimeline(db, provenance.TimelineOptions{RunID: opts.RunID})
	if err != nil {
		return ProcessReport{}, err
	}
	return BuildProcessFromTimeline(manifest, opts)
}

func BuildProcessFromTimeline(manifest provenance.TimelineManifest, opts ProcessOptions) (ProcessReport, error) {
	start, ok := findProcessStart(manifest.Events, opts.ProcessID)
	if !ok {
		return ProcessReport{}, fmt.Errorf("process %q not found in run %q", opts.ProcessID, manifest.RunID)
	}
	end, hasEnd := findProcessEnd(manifest.Events, opts.ProcessID)
	context := EventContext{
		SessionID:  start.SessionID,
		AttemptID:  start.AttemptID,
		ToolCallID: resolveToolCallForEvent(manifest.Events, start),
		ProcessID:  opts.ProcessID,
		SnapshotID: start.SnapshotID,
	}
	if context.ToolCallID == "" {
		context.ToolCallID = start.ToolCallID
	}
	report := ProcessReport{
		SchemaVersion: ProcessSchemaVersion,
		RunID:         manifest.RunID,
		Process: ProcessDetail{
			ID:        opts.ProcessID,
			StartedAt: start.Time,
			Summary:   start.Summary,
			Evidence:  start.Evidence,
			ObjectRef: start.ObjectRef,
		},
		Context: context,
	}
	if hasEnd {
		report.Process.EndedAt = end.Time
	}
	riskIDs := map[string]bool{}
	policyIDs := map[string]bool{}
	for _, event := range manifest.Events {
		if event.ProcessID != opts.ProcessID {
			continue
		}
		switch {
		case isRuntimeEvent(event):
			report.RuntimeEvents = append(report.RuntimeEvents, evidenceSummary(event))
		case event.Type == "risk_signal":
			report.RelatedRisks = append(report.RelatedRisks, evidenceSummary(event))
			riskIDs[event.ID] = true
			if decisionID := stringValue(event.Evidence, "policy_decision_id"); decisionID != "" {
				policyIDs[decisionID] = true
			}
		case event.Type == "response_action":
			report.RelatedResponses = append(report.RelatedResponses, evidenceSummary(event))
		}
	}
	for _, event := range manifest.Events {
		if event.Type == "policy_decision" && policyIDs[event.ID] {
			report.RelatedPolicies = append(report.RelatedPolicies, evidenceSummary(event))
		}
		if event.Type == "response_action" && (riskIDs[stringValue(event.Evidence, "risk_signal_id")] || policyIDs[stringValue(event.Evidence, "policy_decision_id")]) {
			if !containsEvidence(report.RelatedResponses, event.ObjectRef) {
				report.RelatedResponses = append(report.RelatedResponses, evidenceSummary(event))
			}
		}
	}
	report.RecommendedViews = processDrilldowns(manifest.RunID, report)
	resultSetID, pageHash, err := processReportIntegrity(report)
	if err == nil {
		report.ResultSetID = resultSetID
		report.PageHash = pageHash
	}
	return report, nil
}

func processReportIntegrity(report ProcessReport) (string, string, error) {
	resultSetID, err := digestObservation(map[string]any{
		"kind":              "observability_process_result_set",
		"run_id":            report.RunID,
		"process":           report.Process,
		"context":           report.Context,
		"runtime_events":    report.RuntimeEvents,
		"related_risks":     report.RelatedRisks,
		"related_policies":  report.RelatedPolicies,
		"related_responses": report.RelatedResponses,
	})
	if err != nil {
		return "", "", err
	}
	pageHash, err := digestObservation(map[string]any{
		"kind":              "observability_process_page",
		"result_set_id":     resultSetID,
		"recommended_views": report.RecommendedViews,
	})
	if err != nil {
		return "", "", err
	}
	return resultSetID, pageHash, nil
}

func findProcessStart(events []provenance.TimelineEvent, processID string) (provenance.TimelineEvent, bool) {
	for _, event := range events {
		if event.Type == "process_start" && event.ProcessID == processID {
			return event, true
		}
	}
	for _, event := range events {
		if event.ProcessID == processID {
			return event, true
		}
	}
	return provenance.TimelineEvent{}, false
}

func findProcessEnd(events []provenance.TimelineEvent, processID string) (provenance.TimelineEvent, bool) {
	for _, event := range events {
		if event.Type == "process_end" && event.ProcessID == processID {
			return event, true
		}
	}
	return provenance.TimelineEvent{}, false
}

func containsEvidence(items []EvidenceSummary, ref string) bool {
	for _, item := range items {
		if item.Ref == ref {
			return true
		}
	}
	return false
}

func processDrilldowns(runID string, report ProcessReport) []string {
	views := []string{"timeline --run " + runID + " --process " + report.Process.ID, "graph explain --process " + report.Process.ID}
	if report.Context.ToolCallID != "" {
		views = append(views, "timeline --run "+runID+" --tool-call "+report.Context.ToolCallID)
	}
	if len(report.RuntimeEvents) > 0 {
		views = append(views, "telemetry list --run "+runID)
	}
	if len(report.RelatedRisks) > 0 {
		views = append(views, "security risks --run "+runID)
	}
	if len(report.RelatedResponses) > 0 {
		views = append(views, "security responses --run "+runID)
	}
	return views
}
