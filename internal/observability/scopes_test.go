package observability

import (
	"testing"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func TestBuildScopesFromTimelineAggregatesToolCallScope(t *testing.T) {
	manifest := provenance.TimelineManifest{
		SchemaVersion: "agentprovenance.timeline/v1",
		RunID:         "run-scopes",
		EventCount:    6,
		Events: []provenance.TimelineEvent{
			{
				Time:       "2026-01-01T00:00:00Z",
				Type:       "tool_call_start",
				Source:     "application_context",
				ID:         "tool-1",
				RunID:      "run-scopes",
				SessionID:  "session-1",
				AttemptID:  "attempt-1",
				ToolCallID: "tool-1",
				Evidence:   map[string]any{"command": "pytest -q", "status": "running"},
				ObjectRef:  "tool_call/tool-1",
				Summary:    "pytest -q",
			},
			{
				Time:       "2026-01-01T00:00:01Z",
				Type:       "execve",
				Source:     "falco_jsonl",
				ID:         "evt-1",
				RunID:      "run-scopes",
				SessionID:  "session-1",
				AttemptID:  "attempt-1",
				ToolCallID: "tool-1",
				ProcessID:  "proc-1",
				ObjectRef:  "runtime_event/evt-1",
			},
			{
				Time:       "2026-01-01T00:00:02Z",
				Type:       "risk_signal",
				Source:     "security",
				ID:         "risk-1",
				RunID:      "run-scopes",
				SessionID:  "session-1",
				ToolCallID: "tool-1",
				ProcessID:  "proc-1",
				Risk:       map[string]any{"severity": "high"},
				ObjectRef:  "risk_signal/risk-1",
			},
			{
				Time:      "2026-01-01T00:00:03Z",
				Type:      "policy_decision",
				Source:    "security",
				ID:        "decision-1",
				RunID:     "run-scopes",
				SessionID: "session-1",
				Evidence:  map[string]any{"event_id": "evt-1"},
				ObjectRef: "policy_decision/decision-1",
			},
			{
				Time:      "2026-01-01T00:00:04Z",
				Type:      "response_action",
				Source:    "security",
				ID:        "action-1",
				RunID:     "run-scopes",
				SessionID: "session-1",
				ProcessID: "proc-1",
				Risk:      map[string]any{"action_type": "quarantine"},
				ObjectRef: "response_action/action-1",
			},
			{
				Time:       "2026-01-01T00:00:05Z",
				Type:       "tool_call_end",
				Source:     "application_context",
				ID:         "tool-1",
				RunID:      "run-scopes",
				SessionID:  "session-1",
				AttemptID:  "attempt-1",
				ToolCallID: "tool-1",
			},
		},
	}
	report := BuildScopesFromTimeline(manifest, ScopesOptions{})
	if report.SchemaVersion != ScopesSchemaVersion || report.RunID != "run-scopes" || report.ScopeCount != 1 {
		t.Fatalf("unexpected report header: %+v", report)
	}
	if report.ResultSetID == "" || report.PageHash == "" {
		t.Fatalf("scopes integrity hashes missing: result_set_id=%q page_hash=%q", report.ResultSetID, report.PageHash)
	}
	scope := report.Scopes[0]
	if scope.ToolCallID != "tool-1" || scope.Command != "pytest -q" || scope.Status != "running" {
		t.Fatalf("unexpected scope identity: %+v", scope)
	}
	if scope.ProcessCount != 1 || scope.RuntimeEvents != 1 || scope.RuntimeEventsByType["execve"] != 1 {
		t.Fatalf("unexpected runtime aggregation: %+v", scope)
	}
	if scope.RiskSignals != 1 || scope.RiskBySeverity["high"] != 1 {
		t.Fatalf("unexpected risk aggregation: %+v", scope)
	}
	if scope.PolicyDecisions != 1 {
		t.Fatalf("unexpected policy aggregation: %+v", scope)
	}
	if scope.ResponseActions != 1 || scope.ResponseByAction["quarantine"] != 1 {
		t.Fatalf("unexpected response aggregation: %+v", scope)
	}
	assertContainsStep(t, scope.RecommendedDrilldowns, "timeline --run run-scopes --tool-call tool-1")
}
