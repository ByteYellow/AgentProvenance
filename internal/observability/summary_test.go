package observability

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/signals"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
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
	if summary.ResultSetID == "" || summary.PageHash == "" {
		t.Fatalf("summary integrity hashes missing: result_set_id=%q page_hash=%q", summary.ResultSetID, summary.PageHash)
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

func TestBuildSummaryIncludesTelemetryEventWindows(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	base := time.Date(2026, 1, 1, 12, 0, 1, 0, time.UTC)
	insertSummaryEvent(t, db, "evt-window-1", "run-window-summary", "session-1", "tool-1", "falco_jsonl", "execve", "container_time_window:container_id+time", base)
	insertSummaryEvent(t, db, "evt-window-2", "run-window-summary", "session-1", "tool-1", "falco_jsonl", "metadata_ip", "container_time_window:container_id+time", base.Add(time.Second))
	if _, err := telemetry.RebuildEventWindows(db, "run-window-summary"); err != nil {
		t.Fatal(err)
	}
	summary, err := BuildSummary(db, SummaryOptions{RunID: "run-window-summary", TopN: 3})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Windows.WindowCount != 4 {
		t.Fatalf("expected 4 windows for 2 events across 10s/60s, got %+v", summary.Windows)
	}
	if summary.Windows.AggregateWindow != 60 || summary.Windows.EventCount != 2 || summary.Windows.ResolvedCount != 2 || summary.Windows.HighRiskCount != 1 {
		t.Fatalf("unexpected window summary: %+v", summary.Windows)
	}
	if len(summary.Windows.WindowSeconds) != 2 || summary.Windows.WindowSeconds[0] != 10 || summary.Windows.WindowSeconds[1] != 60 {
		t.Fatalf("unexpected window seconds: %+v", summary.Windows.WindowSeconds)
	}
	assertHasView(t, summary.RecommendedViews, "telemetry windows --run run-window-summary --window 60 --json")
}

func insertSummaryEvent(t *testing.T, db *sql.DB, id, runID, sessionID, toolCallID, source, eventType, method string, createdAt time.Time) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO events
		(id, run_id, session_id, tool_call_id, source, event_type, payload, correlation_method, correlation_confidence, created_at)
		VALUES (?, ?, ?, ?, ?, ?, '{}', ?, 1, ?)`,
		id, runID, sessionID, toolCallID, source, eventType, method, createdAt.Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
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

func TestBuildSummaryIncludesUnifiedSignalDimensions(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	for _, s := range []signals.Signal{
		{Dimension: signals.Security, Type: "policy_violation", RunID: "run-sig", Severity: "high"},
		{Dimension: signals.Quality, Type: "task_success", RunID: "run-sig", Label: "pass", Value: 0.9},
		{Dimension: signals.Cost, Type: "resource_sample", RunID: "run-sig", Value: 3.2},
	} {
		if _, err := signals.Record(db, s); err != nil {
			t.Fatal(err)
		}
	}

	summary, err := BuildSummary(db, SummaryOptions{RunID: "run-sig", TopN: 3})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Signals.Total != 3 {
		t.Fatalf("signal total = %d, want 3", summary.Signals.Total)
	}
	if summary.Signals.ByDimension["security"] != 1 || summary.Signals.ByDimension["quality"] != 1 || summary.Signals.ByDimension["cost"] != 1 {
		t.Fatalf("unexpected by-dimension counts: %+v", summary.Signals.ByDimension)
	}
}
