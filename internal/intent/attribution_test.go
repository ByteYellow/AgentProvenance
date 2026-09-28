package intent

import (
	"database/sql"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/hooksbridge"
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
