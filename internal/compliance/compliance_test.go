package compliance

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/store"
)

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

func TestMapRunRulesFourStates(t *testing.T) {
	db := newComplianceTestDB(t)

	now := "2026-06-30T00:00:00Z"
	// Enforce-mode rule fired and blocked -> ASI03 enforced.
	execSQL(t, db, `INSERT INTO policy_decisions (id, event_id, run_id, session_id, rule_id, decision, reason, created_at)
		VALUES ('d1', '', 'run-rm', 's1', 'secret_path_access', 'kill', 'secret', ?)`, now)
	// Detect-mode rule fired as audit (observed, not blocked) -> ASI04 detected.
	execSQL(t, db, `INSERT INTO policy_decisions (id, event_id, run_id, session_id, rule_id, decision, reason, created_at)
		VALUES ('d2', '', 'run-rm', 's1', 'supply_chain_install', 'audit', 'install', ?)`, now)

	report, err := MapRunRules(db, RuleMappingOptions{Framework: "owasp-asi", RunID: "run-rm"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]RuleStatus{}
	for _, it := range report.Items {
		got[it.ControlID] = it.Status
	}
	cases := map[string]RuleStatus{
		"ASI03": RuleStatusEnforced,     // killed secret access
		"ASI04": RuleStatusDetected,     // detect-mode install, not blocked
		"ASI05": RuleStatusNotTriggered, // ptrace_access maps here, did not fire
		"ASI01": RuleStatusNoRule,       // no detector maps to goal-hijack
	}
	for control, want := range cases {
		if got[control] != want {
			t.Fatalf("%s = %q, want %q (all=%v)", control, got[control], want, got)
		}
	}
	if report.Summary.Enforced < 1 || report.Summary.Detected < 1 || report.Summary.NoRule < 1 {
		t.Fatalf("summary missing expected counts: %+v", report.Summary)
	}
	// A fired control must carry clickable entity refs (policy_decision/...).
	for _, it := range report.Items {
		if it.ControlID == "ASI03" {
			if len(it.EvidenceRefs) == 0 || it.EvidenceRefs[0].Kind != "policy_decision" {
				t.Fatalf("ASI03 should have a policy_decision evidence ref, got %+v", it.EvidenceRefs)
			}
			anyHit := false
			for _, r := range it.Rules {
				if len(r.Hits) > 0 {
					anyHit = true
				}
			}
			if !anyHit {
				t.Fatalf("ASI03 should carry per-rule hits, got %+v", it.Rules)
			}
		}
	}
}

func TestMapRunRulesFilterAndGaps(t *testing.T) {
	db := newComplianceTestDB(t)
	// Nothing fired: every mapped control is not_triggered, the rest no_rule.
	report, err := MapRunRules(db, RuleMappingOptions{
		Framework: "owasp-asi",
		RunID:     "empty-run",
		Only:      []string{"ASI03", "ASI05", "ASI01"},
		Exclude:   []string{"ASI05"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.Total != 2 {
		t.Fatalf("only/exclude should leave 2 controls, got %d: %+v", report.Summary.Total, report.Items)
	}
	// ASI01 has no rule -> RuleGaps keeps it; ASI03 not_triggered is not a gap.
	gaps := RuleGaps(report, false, 0)
	if gaps.Summary.NoRule != 1 || gaps.Summary.Total != 1 || gaps.Items[0].ControlID != "ASI01" {
		t.Fatalf("gaps should be just ASI01 (no_rule), got %+v", gaps)
	}
}

func newComplianceTestDB(t *testing.T) *sql.DB {
	t.Helper()
	paths, err := store.Init(filepath.Join(t.TempDir(), ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
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
