package observability

import (
	"testing"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func TestBuildEventFromTimelineLinksRuntimeEventContext(t *testing.T) {
	manifest := provenance.TimelineManifest{
		SchemaVersion: "agentprovenance.timeline/v1",
		RunID:         "run-event",
		EventCount:    4,
		Events: []provenance.TimelineEvent{
			{
				Time:       "2026-01-01T00:00:00Z",
				Type:       "metadata_ip",
				Source:     "falco_jsonl",
				ID:         "evt-1",
				RunID:      "run-event",
				SessionID:  "session-1",
				AttemptID:  "attempt-1",
				ToolCallID: "tool-1",
				ProcessID:  "proc-1",
				ObjectRef:  "runtime_event/evt-1",
				Summary:    "metadata ip access",
				Evidence: map[string]any{
					"correlation_method":     "container_time_window",
					"correlation_confidence": 0.92,
				},
			},
			{
				Time:       "2026-01-01T00:00:01Z",
				Type:       "risk_signal",
				Source:     "security",
				ID:         "risk-1",
				RunID:      "run-event",
				SessionID:  "session-1",
				ToolCallID: "tool-1",
				ProcessID:  "proc-1",
				ObjectRef:  "risk_signal/risk-1",
				Evidence:   map[string]any{"event_id": "evt-1"},
				Risk:       map[string]any{"severity": "high"},
				Summary:    "metadata IP risk",
			},
			{
				Time:      "2026-01-01T00:00:02Z",
				Type:      "policy_decision",
				Source:    "security",
				ID:        "decision-1",
				RunID:     "run-event",
				SessionID: "session-1",
				ObjectRef: "policy_decision/decision-1",
				Evidence:  map[string]any{"event_id": "evt-1"},
				Summary:   "quarantine",
			},
			{
				Time:      "2026-01-01T00:00:03Z",
				Type:      "response_action",
				Source:    "security",
				ID:        "action-1",
				RunID:     "run-event",
				SessionID: "session-1",
				ProcessID: "proc-1",
				ObjectRef: "response_action/action-1",
				Evidence:  map[string]any{"policy_decision_id": "decision-1", "risk_signal_id": "risk-1"},
				Risk:      map[string]any{"target_id": "proc-1", "action_type": "quarantine"},
				Summary:   "quarantine target=process/proc-1",
			},
		},
	}
	report, err := BuildEventFromTimeline(manifest, EventOptions{EventID: "evt-1"})
	if err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != EventSchemaVersion || report.Event.ID != "evt-1" || report.Context.ToolCallID != "tool-1" {
		t.Fatalf("unexpected event report: %+v", report)
	}
	if report.Event.CorrelationMethod != "container_time_window" || report.Event.CorrelationConfidence != 0.92 {
		t.Fatalf("unexpected correlation detail: %+v", report.Event)
	}
	if len(report.RelatedRisks) != 1 || len(report.RelatedPolicies) != 1 || len(report.RelatedResponses) != 1 {
		t.Fatalf("unexpected related evidence: risks=%+v policies=%+v responses=%+v", report.RelatedRisks, report.RelatedPolicies, report.RelatedResponses)
	}
	assertContainsStep(t, report.RecommendedViews, "graph explain --event evt-1")
	assertContainsStep(t, report.RecommendedViews, "timeline --run run-event --tool-call tool-1")
}
