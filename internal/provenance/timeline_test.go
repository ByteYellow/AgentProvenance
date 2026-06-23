package provenance

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestBuildTimelineMergesContextTelemetryRiskAndResponse(t *testing.T) {
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

	execSQL(t, db, `INSERT INTO leases (id, run_id, task_path, task_yaml, status, created_at, updated_at)
		VALUES ('lease-1', 'run-1', 'task.yaml', '{}', 'allocated', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`)
	execSQL(t, db, `INSERT INTO sessions (id, lease_id, run_id, workspace_host_path, status, created_at, updated_at)
		VALUES ('session-1', 'lease-1', 'run-1', '/tmp/work', 'running', '2026-01-01T00:00:01Z', '2026-01-01T00:00:01Z')`)
	execSQL(t, db, `INSERT INTO tool_calls (id, run_id, attempt_id, session_id, command, status, exit_code, wall_ms, result_ref, created_at, started_at, ended_at)
		VALUES ('tool-1', 'run-1', 'attempt-1', 'session-1', 'pytest -q', 'completed', 0, 20, 'artifact://patch', '2026-01-01T00:00:02Z', '2026-01-01T00:00:02Z', '2026-01-01T00:00:05Z')`)
	execSQL(t, db, `INSERT INTO processes (id, session_id, tool_call_id, command, status, exit_code, started_at, ended_at)
		VALUES ('proc-1', 'session-1', 'tool-1', 'pytest -q', 'completed', 0, '2026-01-01T00:00:03Z', '2026-01-01T00:00:05Z')`)
	execSQL(t, db, `INSERT INTO events (id, run_id, session_id, tool_call_id, process_id, raw_event_id, source, event_type, payload, correlation_method, correlation_confidence, pid, ppid, created_at)
		VALUES ('evt-1', 'run-1', 'session-1', 'tool-1', 'proc-1', 'raw-1', 'tetragon_jsonl', 'execve', '{}', 'pid', 1.0, 42, 1, '2026-01-01T00:00:04Z')`)
	execSQL(t, db, `INSERT INTO policy_decisions (id, event_id, run_id, session_id, rule_id, decision, reason, created_at)
		VALUES ('dec-1', 'evt-1', 'run-1', 'session-1', 'metadata_ip', 'quarantine', 'metadata access', '2026-01-01T00:00:06Z')`)
	execSQL(t, db, `INSERT INTO risk_signals (id, run_id, session_id, tool_call_id, process_id, event_id, policy_decision_id, signal_type, severity, reason, recommended_action, created_at)
		VALUES ('risk-1', 'run-1', 'session-1', 'tool-1', 'proc-1', 'evt-1', 'dec-1', 'policy_violation', 'high', 'metadata access', 'quarantine', '2026-01-01T00:00:07Z')`)
	execSQL(t, db, `INSERT INTO response_actions (id, run_id, session_id, process_id, risk_signal_id, policy_decision_id, action_type, target_type, target_id, status, created_at)
		VALUES ('resp-1', 'run-1', 'session-1', 'proc-1', 'risk-1', 'dec-1', 'quarantine', 'session', 'session-1', 'recorded', '2026-01-01T00:00:08Z')`)
	execSQL(t, db, `INSERT INTO baseline_deviations (id, run_id, template_name, profile_id, deviation_type, status, expected_value, observed_value, recommended_action, created_at)
		VALUES ('dev-1', 'run-1', 'coding-agent', 'base-1', 'network_event_count', 'anomalous', 1, 4, 'audit', '2026-01-01T00:00:09Z')`)

	manifest, err := BuildTimeline(db, TimelineOptions{RunID: "run-1"})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != "agentprovenance.timeline/v1" {
		t.Fatalf("schema_version=%q", manifest.SchemaVersion)
	}
	if manifest.EventCount < 8 {
		t.Fatalf("event_count=%d, want merged timeline events: %+v", manifest.EventCount, manifest.Events)
	}
	if manifest.ResultSetID == "" || manifest.PageHash == "" {
		t.Fatalf("timeline integrity hashes missing: result_set_id=%q page_hash=%q", manifest.ResultSetID, manifest.PageHash)
	}
	assertTimelineOrder(t, manifest.Events)
	for _, want := range []string{"tool_call_start", "process_start", "execve", "policy_decision", "risk_signal", "response_action", "baseline_deviation"} {
		if !timelineHasType(manifest.Events, want) {
			t.Fatalf("missing timeline type %s in %+v", want, manifest.Events)
		}
	}

	filtered, err := BuildTimeline(db, TimelineOptions{RunID: "run-1", ToolCall: "tool-1", Type: "execve"})
	if err != nil {
		t.Fatal(err)
	}
	if filtered.EventCount != 1 || filtered.Events[0].ID != "evt-1" {
		t.Fatalf("filtered timeline = %+v, want only evt-1", filtered.Events)
	}
	if filtered.Events[0].ToolCallID != "tool-1" || filtered.Events[0].ProcessID != "proc-1" {
		t.Fatalf("filtered event lost context: %+v", filtered.Events[0])
	}
	limited, err := BuildTimeline(db, TimelineOptions{RunID: "run-1", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if limited.EventCount != 1 {
		t.Fatalf("limited event_count=%d, want 1", limited.EventCount)
	}
	if limited.ResultSetID != manifest.ResultSetID {
		t.Fatalf("limited result_set_id changed: full=%s limited=%s", manifest.ResultSetID, limited.ResultSetID)
	}
	if limited.PageHash == manifest.PageHash {
		t.Fatalf("limited page_hash should differ from full page hash: %s", limited.PageHash)
	}
}

func assertTimelineOrder(t *testing.T, events []TimelineEvent) {
	t.Helper()
	for i := 1; i < len(events); i++ {
		if events[i-1].Time > events[i].Time {
			t.Fatalf("timeline out of order at %d: %s > %s", i, events[i-1].Time, events[i].Time)
		}
	}
}

func timelineHasType(events []TimelineEvent, eventType string) bool {
	for _, event := range events {
		if event.Type == eventType {
			return true
		}
	}
	return false
}

func execSQL(t *testing.T, db *sql.DB, query string) {
	t.Helper()
	if _, err := db.Exec(query); err != nil {
		t.Fatal(err)
	}
}
