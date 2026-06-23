package observability

import (
	"testing"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func TestBuildSummaryFromTimelineAggregatesCoverageRiskAndResponses(t *testing.T) {
	manifest := provenance.TimelineManifest{
		SchemaVersion: "agentprovenance.timeline/v1",
		RunID:         "run-observe",
		EventCount:    5,
		Events: []provenance.TimelineEvent{
			{
				Time:       "2026-01-01T00:00:00Z",
				Type:       "tool_call_start",
				Source:     "application_context",
				ID:         "tool-1",
				RunID:      "run-observe",
				SessionID:  "session-1",
				AttemptID:  "attempt-1",
				ToolCallID: "tool-1",
				ObjectRef:  "tool_call/tool-1",
				Summary:    "command=test",
			},
			{
				Time:       "2026-01-01T00:00:01Z",
				Type:       "execve",
				Source:     "falco_jsonl",
				ID:         "evt-1",
				RunID:      "run-observe",
				SessionID:  "session-1",
				ToolCallID: "tool-1",
				ProcessID:  "proc-1",
				ObjectRef:  "runtime_event/evt-1",
				Summary:    "execve",
			},
			{
				Time:      "2026-01-01T00:00:02Z",
				Type:      "connect",
				Source:    "falco_jsonl",
				ID:        "evt-2",
				RunID:     "run-observe",
				SessionID: "session-1",
				ObjectRef: "runtime_event/evt-2",
				Summary:   "connect",
			},
			{
				Time:      "2026-01-01T00:00:03Z",
				Type:      "risk_signal",
				Source:    "security",
				ID:        "risk-1",
				RunID:     "run-observe",
				SessionID: "session-1",
				ObjectRef: "risk_signal/risk-1",
				Risk:      map[string]any{"severity": "high"},
				Summary:   "metadata IP",
			},
			{
				Time:      "2026-01-01T00:00:04Z",
				Type:      "response_action",
				Source:    "security",
				ID:        "action-1",
				RunID:     "run-observe",
				SessionID: "session-1",
				Risk:      map[string]any{"action_type": "quarantine", "status": "recorded"},
				ObjectRef: "response_action/action-1",
				Summary:   "quarantine",
			},
		},
	}
	summary := BuildSummaryFromTimeline(manifest, SummaryOptions{TopN: 3})
	if summary.SchemaVersion != SummarySchemaVersion || summary.RunID != "run-observe" {
		t.Fatalf("unexpected summary header: %+v", summary)
	}
	if summary.Application.Sessions != 1 || summary.Application.ToolCalls != 1 || summary.Application.Processes != 1 {
		t.Fatalf("unexpected application summary: %+v", summary.Application)
	}
	if summary.Runtime.Events != 2 || summary.Runtime.EventsWithToolCall != 1 || summary.Runtime.EventsWithProcess != 1 {
		t.Fatalf("unexpected runtime summary: %+v", summary.Runtime)
	}
	if summary.Runtime.ToolCallCoverageRatio != 0.5 || summary.Runtime.ProcessCoverageRatio != 0.5 {
		t.Fatalf("unexpected coverage ratios: %+v", summary.Runtime)
	}
	if summary.Risk.Signals != 1 || summary.Risk.BySeverity["high"] != 1 {
		t.Fatalf("unexpected risk summary: %+v", summary.Risk)
	}
	if summary.Response.Actions != 1 || summary.Response.ByAction["quarantine"] != 1 || summary.Response.ByStatus["recorded"] != 1 {
		t.Fatalf("unexpected response summary: %+v", summary.Response)
	}
	if len(summary.TopEvidenceRefs) != 3 {
		t.Fatalf("top evidence refs=%d want 3", len(summary.TopEvidenceRefs))
	}
	assertHasView(t, summary.RecommendedViews, "telemetry bindings --run run-observe")
	assertHasView(t, summary.RecommendedViews, "security risks --run run-observe")
	assertHasView(t, summary.RecommendedViews, "security responses --run run-observe")
}

func assertHasView(t *testing.T, views []string, want string) {
	t.Helper()
	for _, view := range views {
		if view == want {
			return
		}
	}
	t.Fatalf("missing recommended view %q in %+v", want, views)
}
