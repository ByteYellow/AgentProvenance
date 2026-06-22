package compliance

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestMapRunProducesEvidenceBackedOWASPStatuses(t *testing.T) {
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

	now := "2026-01-01T00:00:00Z"
	execSQL(t, db, `INSERT INTO leases (id, run_id, task_path, task_yaml, status, created_at, updated_at)
		VALUES ('lease-1', 'run-compliance', 'task.yaml', '{}', 'allocated', ?, ?)`, now, now)
	execSQL(t, db, `INSERT INTO sessions (id, lease_id, run_id, runtime, workspace_host_path, status, created_at, updated_at)
		VALUES ('session-1', 'lease-1', 'run-compliance', 'record', '/tmp/work', 'stopped', ?, ?)`, now, now)
	execSQL(t, db, `INSERT INTO execution_context_bindings
		(id, run_id, session_id, tool_call_id, process_id, container_id, cgroup_id, pid, started_at, binding_source, confidence, created_at)
		VALUES ('bind-1', 'run-compliance', 'session-1', 'tool-1', 'proc-1', 'container-1', 'cgroup-1', 4242, ?, 'test', 1.0, ?)`, now, now)
	execSQL(t, db, `INSERT INTO tool_calls (id, run_id, attempt_id, session_id, command, status, created_at, started_at)
		VALUES ('tool-1', 'run-compliance', 'attempt-1', 'session-1', 'pytest -q', 'completed', ?, ?)`, now, now)
	execSQL(t, db, `INSERT INTO processes (id, session_id, tool_call_id, command, status, started_at)
		VALUES ('proc-1', 'session-1', 'tool-1', 'pytest -q', 'exited', ?)`, now)
	execSQL(t, db, `INSERT INTO events
		(id, run_id, session_id, tool_call_id, process_id, source, event_type, payload, created_at)
		VALUES ('evt-exec', 'run-compliance', 'session-1', 'tool-1', 'proc-1', 'falco_jsonl', 'execve', '{"argv":["pytest"]}', ?)`, now)
	execSQL(t, db, `INSERT INTO events
		(id, run_id, session_id, tool_call_id, process_id, source, event_type, payload, created_at)
		VALUES ('evt-secret', 'run-compliance', 'session-1', 'tool-1', 'proc-1', 'falco_jsonl', 'secret_path', '{"path":"/workspace/.env"}', ?)`, now)
	execSQL(t, db, `INSERT INTO policy_decisions
		(id, event_id, run_id, session_id, rule_id, decision, reason, created_at)
		VALUES ('dec-1', 'evt-secret', 'run-compliance', 'session-1', 'secret_path_access', 'kill', 'secret path access', ?)`, now)
	execSQL(t, db, `INSERT INTO risk_signals
		(id, run_id, session_id, tool_call_id, process_id, event_id, policy_decision_id, signal_type, severity, reason, recommended_action, created_at)
		VALUES ('risk-1', 'run-compliance', 'session-1', 'tool-1', 'proc-1', 'evt-secret', 'dec-1', 'policy_violation', 'high', 'secret path access', 'kill', ?)`, now)
	execSQL(t, db, `INSERT INTO baseline_deviations
		(id, run_id, template_name, profile_id, deviation_type, status, expected_value, observed_value, recommended_action, created_at)
		VALUES ('dev-1', 'run-compliance', 'coding-agent', 'base-1', 'secret_path_count', 'anomalous', 0, 1, 'review', ?)`, now)
	execSQL(t, db, `INSERT INTO response_actions
		(id, run_id, session_id, process_id, risk_signal_id, policy_decision_id, action_type, target_type, target_id, status, created_at)
		VALUES ('action-1', 'run-compliance', 'session-1', 'proc-1', 'risk-1', 'dec-1', 'kill', 'process', 'proc-1', 'recorded', ?)`, now)
	execSQL(t, db, `INSERT INTO graph_edges (id, run_id, from_id, to_id, edge_type, created_at)
		VALUES ('edge-1', 'run-compliance', 'tool-1', 'proc-1', 'tool_call_process', ?)`, now)
	execSQL(t, db, `INSERT INTO provenance_objects (hash, object_type, source_id, run_id, path, created_at)
		VALUES ('sha256-test', 'runtime_event', 'evt-exec', 'run-compliance', '/tmp/object.json', ?)`, now)

	report, err := MapRun(db, MappingOptions{Framework: "owasp-asi", RunID: "run-compliance"})
	if err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != SchemaVersion || report.Framework != "owasp-asi" {
		t.Fatalf("unexpected report header: %+v", report)
	}
	assertStatus(t, report, "ASI02", StatusCovered)
	assertStatus(t, report, "ASI03", StatusPartial)
	assertStatus(t, report, "ASI04", StatusPartial)
	assertStatus(t, report, "ASI05", StatusCovered)
	assertStatus(t, report, "ASI07", StatusNotApplicable)
	assertStatus(t, report, "ASI10", StatusCovered)
	assertStatus(t, report, "TRACE", StatusCovered)
	if report.Summary.Total == 0 || report.Summary.Covered == 0 || report.Summary.NotApplicable == 0 {
		t.Fatalf("unexpected summary: %+v", report.Summary)
	}
	for _, item := range report.Items {
		if item.Status == StatusCovered && len(item.EvidenceRefs) == 0 {
			t.Fatalf("covered item has no evidence refs: %+v", item)
		}
	}
}

func TestMapRunNISTReportsMissingWhenEvidenceAbsent(t *testing.T) {
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

	report, err := MapRun(db, MappingOptions{Framework: "nist-rfi-2026-00206", RunID: "empty-run"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.Missing != report.Summary.Total {
		t.Fatalf("empty run summary = %+v, want all missing", report.Summary)
	}
	assertStatus(t, report, "Q3", StatusMissing)
}

func TestCustomRuleSetCanMapBuiltInAndCustomRules(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "ruleset.yaml")
	raw := `
schema_version: agentprovenance.compliance_ruleset/v1
id: custom-review
title: Custom Review
frameworks:
  - id: custom-review
    title: Custom Agent Review
rules:
  - id: CUST-001
    title: Runtime evidence linked to context
    evidence: [runtime_event, binding]
    partial: [runtime_event]
    gap: runtime or binding evidence missing
    recommended_next_step: add ToolCallScope binding
mappings:
  - framework: custom-review
    builtin_controls: [ASI05, TRACE]
    rules: [CUST-001]
  - framework: owasp-asi
    rules: [CUST-001]
`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	ruleSet, err := LoadRuleSet(path)
	if err != nil {
		t.Fatal(err)
	}
	custom, ok := GetFramework("custom-review", ruleSet)
	if !ok {
		t.Fatalf("custom framework not found")
	}
	if len(custom.Controls) != 3 {
		t.Fatalf("custom controls = %d, want 3: %+v", len(custom.Controls), custom.Controls)
	}
	seen := map[string]bool{}
	for _, control := range custom.Controls {
		seen[control.ID] = true
	}
	if !seen["ASI05"] || !seen["TRACE"] || !seen["CUST-001"] {
		t.Fatalf("custom framework missing mapped controls: %+v", custom.Controls)
	}
	owasp, ok := GetFramework("owasp-asi", ruleSet)
	if !ok {
		t.Fatalf("owasp framework not found")
	}
	if !hasControl(owasp, "ASI05") || !hasControl(owasp, "CUST-001") {
		t.Fatalf("owasp framework should keep built-ins and append custom rule: %+v", owasp.Controls)
	}
}

func TestMapRunOnlyAndExcludeFiltersControls(t *testing.T) {
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

	report, err := MapRun(db, MappingOptions{
		Framework: "owasp-asi",
		RunID:     "run-filter",
		Only:      []string{"ASI05", "ASI10", "TRACE"},
		Exclude:   []string{"TRACE"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.Total != 2 {
		t.Fatalf("filtered total=%d want 2 items=%+v", report.Summary.Total, report.Items)
	}
	if len(report.Items) != 2 || report.Items[0].ControlID != "ASI05" || report.Items[1].ControlID != "ASI10" {
		t.Fatalf("unexpected filtered items: %+v", report.Items)
	}
}

func TestFindItemSupportsItemIDAndLegacyControlID(t *testing.T) {
	report := MappingReport{
		Items: []MappingResult{
			{Framework: "owasp-asi", ItemID: "ASI05", ControlID: "ASI05", Title: "Runtime telemetry correlation"},
		},
	}
	item, ok := FindItem(report, "ASI05")
	if !ok {
		t.Fatal("FindItem did not find item by item id")
	}
	if item.ItemID != "ASI05" || item.ControlID != "ASI05" {
		t.Fatalf("unexpected item ids: %+v", item)
	}
	report.Items[0].ItemID = ""
	item, ok = FindItem(report, "ASI05")
	if !ok || item.ControlID != "ASI05" {
		t.Fatalf("FindItem did not fall back to legacy control id: %+v", item)
	}
}

func assertStatus(t *testing.T, report MappingReport, controlID string, want Status) {
	t.Helper()
	for _, item := range report.Items {
		if item.ControlID == controlID {
			if item.Status != want {
				t.Fatalf("%s status=%s want=%s item=%+v", controlID, item.Status, want, item)
			}
			return
		}
	}
	t.Fatalf("missing control %s in %+v", controlID, report.Items)
}

func hasControl(framework Framework, id string) bool {
	for _, control := range framework.Controls {
		if control.ID == id {
			return true
		}
	}
	return false
}

func execSQL(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}
