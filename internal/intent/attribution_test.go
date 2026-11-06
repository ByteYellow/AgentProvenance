package intent

import (
	"database/sql"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/hooksbridge"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/security"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func win(agent, tc, program, start, end string) toolCallWindow {
	s, _ := time.Parse(time.RFC3339Nano, start)
	e, _ := time.Parse(time.RFC3339Nano, end)
	return toolCallWindow{agent: agent, toolCall: tc, program: program,
		start: s.Add(-30 * time.Second), end: e.Add(30 * time.Second)}
}

func TestContainingRejectsOverlappingLegacyWindows(t *testing.T) {
	windows := toolCallWindows{
		win("alice", "a", "python", "2026-09-28T00:00:00Z", "2026-09-28T00:00:05Z"),
		win("bob", "b", "python", "2026-09-28T00:00:01Z", "2026-09-28T00:00:06Z"),
	}
	if _, ok := windows.containing("2026-09-28T00:00:02Z", "python"); ok {
		t.Fatal("ambiguous windows picked the most recent one")
	}
}

func attributionStore(t *testing.T, competing bool) *sql.DB {
	t.Helper()
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	calls := []string{"a"}
	if competing {
		calls = append(calls, "b")
	}
	for _, id := range calls {
		_, err := db.Exec(`INSERT INTO tool_calls (id,run_id,agent_id,command,status,created_at,started_at,ended_at)
			VALUES (?,'run',?,'python task.py','completed','2026-09-28T00:00:00Z','2026-09-28T00:00:00Z','2026-09-28T00:00:10Z')`, id, id)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO events (id,run_id,source,event_type,cgroup_id,pid,payload,created_at) VALUES
		('exec','run','agentprov_ebpf','execve','cg',100,'{"command":"python task.py","comm":"python"}','2026-09-28T00:00:01Z'),
		('secret','run','agentprov_ebpf','secret_path','cg',100,'{"path":"/home/example/.aws/credentials","comm":"python"}','2026-09-28T00:00:02Z')`); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestNewCorrelationDoesNotFallBackAfterAmbiguity(t *testing.T) {
	db := attributionStore(t, true)
	r, err := Materialize(db, "run")
	if err != nil || r.CoverageGaps == 0 || r.Mismatches != 0 {
		t.Fatalf("ambiguous evidence turned into a finding: %+v %v", r, err)
	}
	effects, err := normalizeEffects(db, "run", security.DefaultEngine(), false)
	if err != nil || len(effects) != 2 {
		t.Fatalf("effects: %+v %v", effects, err)
	}
	for _, e := range effects {
		if e.AgentID != "" {
			t.Fatalf("weaker fallback guessed an agent: %+v", e)
		}
	}
}

func TestDerivedEffectConfidenceIsNotKernelIdentity(t *testing.T) {
	db := attributionStore(t, false)
	if _, err := hooksbridge.CorrelateSyscalls(db, "run"); err != nil {
		t.Fatal(err)
	}
	effects, err := normalizeEffects(db, "run", security.DefaultEngine(), false)
	if err != nil || len(effects) != 2 {
		t.Fatalf("effects: %+v %v", effects, err)
	}
	for _, e := range effects {
		if e.AgentID != "a" || e.ToolCallID != "a" || e.Confidence != correlation.AppProcessConfidence {
			t.Fatalf("inferred identity overstated: %+v", e)
		}
	}
}

func TestMaterializeToolCoverageGapKeepsReferences(t *testing.T) {
	db := attributionStore(t, false)
	for _, statement := range []string{
		`INSERT INTO tool_calls (id,run_id,agent_id,command,status,created_at) VALUES ('no-intent','run','a','','completed','2026-09-28T00:01:00Z')`,
		`INSERT INTO events (id,run_id,tool_call_id,source,event_type,payload,correlation_confidence,created_at) VALUES ('uncovered-secret','run','no-intent','agentprov_ebpf','secret_path','{"path":"/home/example/.aws/credentials","comm":"cat"}',1,'2026-09-28T00:01:01Z')`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if result, err := Materialize(db, "run"); err != nil || result.RuleVersion != RuleVersion {
			t.Fatal(err)
		}
		var id, agent, status string
		if err := db.QueryRow(`SELECT id,agent_id,status FROM intent_diffs WHERE run_id='run' AND tool_call_id='no-intent'`).Scan(&id, &agent, &status); err != nil {
			t.Fatalf("tool gap not stored: %v", err)
		}
		if agent != "a" || status != StatusCoverageGap {
			t.Fatalf("tool gap scope: agent=%s status=%s", agent, status)
		}
		graph, err := provenance.BuildGraphLens(db, provenance.GraphLensOptions{RunID: "run", Lens: "intent", Detail: "raw"})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, node := range graph.Nodes {
			if node.ID == id {
				found = node.Data["rule_version"] == RuleVersion && node.Data["tool_call_id"] == "no-intent"
			}
		}
		if !found {
			t.Fatal("graph lost tool gap identity or rule version")
		}
		refs := 0
		for _, edge := range graph.DerivedEdges {
			if edge.FromID == id || edge.ToID == id {
				refs++
				if edge.DerivationRule != RuleVersion || edge.Confidence == nil || len(edge.EvidenceRefs) != 2 {
					t.Fatalf("graph lost analysis support: %+v", edge)
				}
			}
		}
		if refs != 2 {
			t.Fatalf("want tool and event references, got %d", refs)
		}
		for _, query := range []string{
			`SELECT COUNT(*) FROM graph_edges WHERE from_id='no-intent' AND to_id=? AND edge_type='intent_contract'`,
			`SELECT COUNT(*) FROM graph_edges WHERE from_id=? AND to_id='runtime_event/uncovered-secret' AND edge_type='intent_diff_effect'`,
			`SELECT COUNT(*) FROM signals WHERE source_id=? AND tool_call_id='no-intent' AND signal_type='intent_coverage_gap' AND severity='info'`,
		} {
			var n int
			if err := db.QueryRow(query, id).Scan(&n); err != nil || n != 1 {
				t.Fatalf("gap reference missing/duplicated: n=%d err=%v query=%s", n, err, query)
			}
		}
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE id='uncovered-secret'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("raw evidence was changed: %d %v", count, err)
	}
}

func TestMaterializeUnattributedGapsDoNotCollideAcrossRuns(t *testing.T) {
	db := attributionStore(t, false)
	for _, run := range []string{"one", "two", "one"} {
		if _, err := db.Exec(`INSERT OR IGNORE INTO events (id,run_id,event_type,source,payload,created_at) VALUES (?,?,'secret_path','agentprov_ebpf','{"path":"/work/.aws/credentials"}','2026-11-06T00:00:00Z')`, "secret-"+run, run); err != nil {
			t.Fatal(err)
		}
		if _, err := Materialize(db, run); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(DISTINCT id) FROM intent_diffs WHERE run_id IN ('one','two') AND rule_version=?`, RuleVersion).Scan(&count); err != nil || count != 2 {
		t.Fatalf("run-local gaps collided: %d %v", count, err)
	}
}

func TestConflictingStoredEdgesRemainUnattributed(t *testing.T) {
	db := attributionStore(t, true)
	if _, err := db.Exec(`INSERT INTO graph_edges (id,run_id,from_id,to_id,edge_type,created_at) VALUES
		('old-a','run','a','runtime_event/secret','agent_syscall','2026-09-28T00:00:00Z'),
		('old-b','run','b','runtime_event/secret','agent_syscall','2026-09-28T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	effects, err := normalizeEffects(db, "run", security.DefaultEngine(), true)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range effects {
		if e.EventID == "secret" && (e.AgentID != "" || e.ToolCallID != "") {
			t.Fatalf("last stored edge won: %+v", e)
		}
	}
}

// TestContainingCommGate is the regression guard for the false-FLAGGED class:
// a background harness read (comm=claude) in a benign tool's window must NOT be
// attributed to that tool, while the tool's own subprocess read (comm matching
// the tool program) must be -- even when the syscall lands seconds after the
// hook window (PostToolUse fires early).
func TestContainingCommGate(t *testing.T) {
	windows := toolCallWindows{
		win("main", "tc-echo", "echo", "2026-07-06T08:45:00.000Z", "2026-07-06T08:45:00.100Z"),
		win("main", "tc-cat", "cat", "2026-07-06T08:45:12.180Z", "2026-07-06T08:45:12.331Z"),
	}

	// The cat subprocess reads the secret 3s after PostToolUse: still attributed
	// (wide window) and to the cat tool (comm match), not the echo tool.
	w, ok := windows.containing("2026-07-06T08:45:15.341Z", "cat")
	if !ok || w.toolCall != "tc-cat" {
		t.Fatalf("cat read should attribute to tc-cat, got ok=%v tc=%q", ok, w.toolCall)
	}

	// A background harness read (comm=claude) in the same window matches NO tool
	// program -> not attributed (becomes a coverage gap, never a mismatch).
	if _, ok := windows.containing("2026-07-06T08:45:13.000Z", "claude"); ok {
		t.Fatal("a comm=claude background read must not attribute to any tool call")
	}
	if _, ok := windows.containing("2026-07-06T08:45:13.000Z", "Bun Pool 1"); ok {
		t.Fatal("a comm=Bun read must not attribute to any tool call")
	}

	// No comm at all -> no time-window attribution.
	if _, ok := windows.containing("2026-07-06T08:45:15.341Z", ""); ok {
		t.Fatal("an effect with no comm must not be time-window attributed")
	}
}

func TestProgramName(t *testing.T) {
	cases := map[string]string{
		"cat /home/x/.aws/credentials": "cat",
		"/usr/bin/python3 setup.py":    "python3",
		"echo hello":                   "echo",
		"":                             "",
	}
	for in, want := range cases {
		if got := programName(in); got != want {
			t.Errorf("programName(%q)=%q want %q", in, got, want)
		}
	}
}
