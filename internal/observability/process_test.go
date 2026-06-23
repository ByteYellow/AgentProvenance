package observability

import (
	"testing"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func TestBuildProcessFromTimelineAggregatesRuntimeRiskAndResponse(t *testing.T) {
	manifest := provenance.TimelineManifest{
		SchemaVersion: "agentprovenance.timeline/v1",
		RunID:         "run-process",
		EventCount:    6,
		Events: []provenance.TimelineEvent{
			{
				Time:       "2026-01-01T00:00:00Z",
				Type:       "process_start",
				Source:     "runtime",
				ID:         "proc-1",
				RunID:      "run-process",
				SessionID:  "session-1",
				ToolCallID: "tool-1",
				ProcessID:  "proc-1",
				ObjectRef:  "process/proc-1",
				Summary:    "command=\"pytest -q\"",
				Evidence:   map[string]any{"command": "pytest -q", "status": "running"},
			},
			{
				Time:       "2026-01-01T00:00:01Z",
				Type:       "execve",
				Source:     "falco_jsonl",
				ID:         "evt-1",
				RunID:      "run-process",
				SessionID:  "session-1",
				ToolCallID: "tool-1",
				ProcessID:  "proc-1",
				ObjectRef:  "runtime_event/evt-1",
				Summary:    "execve",
			},
			{
				Time:       "2026-01-01T00:00:02Z",
				Type:       "risk_signal",
				Source:     "security",
				ID:         "risk-1",
				RunID:      "run-process",
				SessionID:  "session-1",
				ToolCallID: "tool-1",
				ProcessID:  "proc-1",
				ObjectRef:  "risk_signal/risk-1",
				Evidence:   map[string]any{"event_id": "evt-1", "policy_decision_id": "decision-1"},
				Summary:    "policy violation",
			},
			{
				Time:      "2026-01-01T00:00:03Z",
				Type:      "policy_decision",
				Source:    "security",
				ID:        "decision-1",
				RunID:     "run-process",
				SessionID: "session-1",
				ObjectRef: "policy_decision/decision-1",
				Evidence:  map[string]any{"event_id": "evt-1"},
				Summary:   "kill",
			},
			{
				Time:      "2026-01-01T00:00:04Z",
				Type:      "response_action",
				Source:    "security",
				ID:        "action-1",
				RunID:     "run-process",
				SessionID: "session-1",
				ProcessID: "proc-1",
				ObjectRef: "response_action/action-1",
				Evidence:  map[string]any{"risk_signal_id": "risk-1", "policy_decision_id": "decision-1"},
				Summary:   "kill target=process/proc-1",
			},
			{
				Time:      "2026-01-01T00:00:05Z",
				Type:      "process_end",
				Source:    "runtime",
				ID:        "proc-1",
				RunID:     "run-process",
				SessionID: "session-1",
				ProcessID: "proc-1",
				ObjectRef: "process/proc-1",
				Summary:   "status=exited exit=1",
			},
		},
	}
	report, err := BuildProcessFromTimeline(manifest, ProcessOptions{ProcessID: "proc-1"})
	if err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != ProcessSchemaVersion || report.Context.ToolCallID != "tool-1" {
		t.Fatalf("unexpected process report: %+v", report)
	}
	if report.Process.StartedAt == "" || report.Process.EndedAt == "" {
		t.Fatalf("missing process lifecycle: %+v", report.Process)
	}
	if len(report.RuntimeEvents) != 1 || len(report.RelatedRisks) != 1 || len(report.RelatedPolicies) != 1 || len(report.RelatedResponses) != 1 {
		t.Fatalf("unexpected related evidence: runtime=%+v risks=%+v policies=%+v responses=%+v", report.RuntimeEvents, report.RelatedRisks, report.RelatedPolicies, report.RelatedResponses)
	}
	assertContainsStep(t, report.RecommendedViews, "graph explain --process proc-1")
	assertContainsStep(t, report.RecommendedViews, "timeline --run run-process --tool-call tool-1")
}
