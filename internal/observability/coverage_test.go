package observability

import (
	"testing"

	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestBuildCoverageFromEventsReportsCorrelationGaps(t *testing.T) {
	events := []telemetry.EventRecord{
		{
			ID:          "evt-full",
			RunID:       "run-coverage",
			SessionID:   "session-1",
			ToolCallID:  "tool-1",
			ProcessID:   "proc-1",
			Source:      "falco_jsonl",
			EventType:   "execve",
			ContainerID: "container-1",
			PID:         100,
		},
		{
			ID:                    "evt-gap",
			RunID:                 "run-coverage",
			SessionID:             "session-1",
			Source:                "falco_jsonl",
			EventType:             "connect",
			CorrelationMethod:     "run_default",
			CorrelationConfidence: 0.2,
			ContainerID:           "container-2",
			PID:                   200,
		},
		{
			ID:        "evt-non-runtime",
			RunID:     "run-coverage",
			Source:    "security",
			EventType: "policy_decision",
		},
	}
	report := BuildCoverageFromEvents("run-coverage", events, CoverageOptions{})
	if report.SchemaVersion != CoverageSchemaVersion || report.RunID != "run-coverage" {
		t.Fatalf("unexpected report header: %+v", report)
	}
	if report.ResultSetID == "" || report.PageHash == "" {
		t.Fatalf("coverage integrity hashes missing: result_set_id=%q page_hash=%q", report.ResultSetID, report.PageHash)
	}
	if report.Summary.RuntimeEvents != 2 || report.Summary.FullyCorrelated != 1 || report.Summary.CorrelationGapCount != 1 {
		t.Fatalf("unexpected summary: %+v", report.Summary)
	}
	if report.Summary.FullyCorrelatedRatio != 0.5 || report.Summary.ToolCallCoverageRatio != 0.5 || report.Summary.ProcessCoverageRatio != 0.5 {
		t.Fatalf("unexpected ratios: %+v", report.Summary)
	}
	if report.MissingFields["tool_call_id"] != 1 || report.MissingFields["process_id"] != 1 {
		t.Fatalf("unexpected missing fields: %+v", report.MissingFields)
	}
	if len(report.Gaps) != 1 || report.Gaps[0].EventID != "evt-gap" {
		t.Fatalf("unexpected gaps: %+v", report.Gaps)
	}
	if report.Gaps[0].SuggestedBinding != "bind ToolCallScope using container_id=container-2" {
		t.Fatalf("unexpected suggested binding: %+v", report.Gaps[0])
	}
	assertContainsStep(t, report.NextSteps, "register ToolCallScope bindings with telemetry bind")
}

func assertContainsStep(t *testing.T, steps []string, want string) {
	t.Helper()
	for _, step := range steps {
		if step == want {
			return
		}
	}
	t.Fatalf("missing step %q in %+v", want, steps)
}
