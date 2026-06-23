package observability

import (
	"testing"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func TestBuildFlowFromTimelineLinksRuntimeEventRiskPolicyResponse(t *testing.T) {
	manifest := provenance.TimelineManifest{
		SchemaVersion: "agentprovenance.timeline/v1",
		RunID:         "run-flow",
		EventCount:    5,
		Events: []provenance.TimelineEvent{
			{
				Time:       "2026-01-01T00:00:00Z",
				Type:       "execve",
				Source:     "falco_jsonl",
				ID:         "evt-exec",
				RunID:      "run-flow",
				ToolCallID: "tool-1",
				ProcessID:  "proc-1",
				Summary:    "execve",
			},
			{
				Time:       "2026-01-01T00:00:01Z",
				Type:       "metadata_ip",
				Source:     "falco_jsonl",
				ID:         "evt-risk",
				RunID:      "run-flow",
				ToolCallID: "tool-1",
				ProcessID:  "proc-1",
				Summary:    "metadata_ip",
			},
			{
				Time:     "2026-01-01T00:00:02Z",
				Type:     "risk_signal",
				Source:   "security",
				ID:       "risk-1",
				RunID:    "run-flow",
				Evidence: map[string]any{"event_id": "evt-risk", "policy_decision_id": "decision-1"},
			},
			{
				Time:     "2026-01-01T00:00:03Z",
				Type:     "policy_decision",
				Source:   "security",
				ID:       "decision-1",
				RunID:    "run-flow",
				Evidence: map[string]any{"event_id": "evt-risk"},
			},
			{
				Time:     "2026-01-01T00:00:04Z",
				Type:     "response_action",
				Source:   "security",
				ID:       "action-1",
				RunID:    "run-flow",
				Evidence: map[string]any{"risk_signal_id": "risk-1", "policy_decision_id": "decision-1"},
			},
		},
	}
	report := BuildFlowFromTimeline(manifest, FlowOptions{})
	if report.SchemaVersion != FlowSchemaVersion || report.RunID != "run-flow" || report.FlowCount != 2 {
		t.Fatalf("unexpected flow report: %+v", report)
	}
	if len(report.Flows[0].RiskSignals) != 0 || report.Flows[0].EventID != "evt-exec" {
		t.Fatalf("unexpected non-risk flow row: %+v", report.Flows[0])
	}
	row := report.Flows[1]
	if row.EventID != "evt-risk" || row.ToolCallID != "tool-1" || row.ProcessID != "proc-1" {
		t.Fatalf("unexpected risk flow identity: %+v", row)
	}
	if len(row.RiskSignals) != 1 || row.RiskSignals[0] != "risk-1" {
		t.Fatalf("unexpected risk links: %+v", row)
	}
	if len(row.PolicyDecisions) != 1 || row.PolicyDecisions[0] != "decision-1" {
		t.Fatalf("unexpected policy links: %+v", row)
	}
	if len(row.ResponseActions) != 1 || row.ResponseActions[0] != "action-1" {
		t.Fatalf("unexpected response links: %+v", row)
	}
	assertContainsStep(t, row.Drilldowns, "observe event --run run-flow --event evt-risk")
}
