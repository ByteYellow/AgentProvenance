package provenance

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func intentTestStore(t *testing.T) (ObjectStore, *sql.DB) {
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
	return ObjectStore{DB: db, Paths: paths}, db
}

func intentTestEvent(t *testing.T, db *sql.DB, id, typ, at, cgroup, command string) {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"argv": strings.Fields(command), "command": command, "node_name": "node-a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO events (id,run_id,source,event_type,created_at,cgroup_id,pid,payload)
		VALUES (?,'intent-test','agentprov_ebpf',?,?,?,100,?)`, id, typ, at, cgroup, string(payload)); err != nil {
		t.Fatal(err)
	}
}

func intentTestDecision(t *testing.T, db *sql.DB, id, at, cgroup, command string) {
	t.Helper()
	intentTestEvent(t, db, id+"-req", "tls_write", "2026-01-01T00:00:00Z", cgroup, "")
	intentTestEvent(t, db, id+"-resp", "tls_read", at, cgroup, "")
	content, _ := json.Marshal(map[string]any{"content": []any{map[string]any{
		"type": "tool_use", "name": "Bash", "input": map[string]any{"command": command},
	}}})
	payload, _ := json.Marshal(map[string]any{"content": string(content), "node_name": "node-a"})
	if _, err := db.Exec(`UPDATE events SET payload=? WHERE id=?`, tlsTestIdentity(t, string(payload), id, "tls_read"), id+"-resp"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE events SET payload=? WHERE id=?`, tlsTestIdentity(t, `{"node_name":"node-a"}`, id, "tls_write"), id+"-req"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO graph_edges (id,run_id,from_id,to_id,edge_type,created_at)
		VALUES (?,'intent-test',?,?,'llm_call',?)`, id, "runtime_event/"+id+"-req", "runtime_event/"+id+"-resp", at); err != nil {
		t.Fatal(err)
	}
}

func intentCausedCount(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM graph_edges WHERE run_id='intent-test' AND edge_type='llm_caused'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestLLMCommandAssociationBoundaries(t *testing.T) {
	const command = "python3 /work/Build.py install"
	for _, tt := range []struct {
		name, at, scope, actual    string
		secondExec, secondDecision bool
		want                       int
	}{
		{"exact", "2026-01-01T00:00:02Z", "cg-a", command, false, false, 1},
		{"timezone equivalent", "2026-01-01T08:00:02+08:00", "cg-a", command, false, false, 1},
		{"before decision", "2026-01-01T00:00:00.9Z", "cg-a", command, false, false, 0},
		{"same timestamp", "2026-01-01T00:00:01Z", "cg-a", command, false, false, 0},
		{"outside window", "2026-01-01T00:02:02Z", "cg-a", command, false, false, 0},
		{"invalid timestamp", "not-a-time", "cg-a", command, false, false, 0},
		{"other cgroup", "2026-01-01T00:00:02Z", "cg-b", command, false, false, 0},
		{"missing scope", "2026-01-01T00:00:02Z", "", command, false, false, 0},
		{"case sensitive", "2026-01-01T00:00:02Z", "cg-a", "python3 /work/build.py install", false, false, 0},
		{"extra argument", "2026-01-01T00:00:02Z", "cg-a", command + " --user", false, false, 0},
		{"truncated prefix", "2026-01-01T00:00:02Z", "cg-a", "python3 /work/Build.py", false, false, 0},
		{"two executions", "2026-01-01T00:00:02Z", "cg-a", command, true, false, 0},
		{"two decisions", "2026-01-01T00:00:02Z", "cg-a", command, false, true, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			st, db := intentTestStore(t)
			intentTestDecision(t, db, "decision", "2026-01-01T00:00:01Z", "cg-a", command)
			intentTestEvent(t, db, "action", "execve", tt.at, tt.scope, tt.actual)
			if tt.secondExec {
				intentTestEvent(t, db, "action-2", "execve", "2026-01-01T00:00:03Z", tt.scope, tt.actual)
			}
			if tt.secondDecision {
				intentTestDecision(t, db, "decision-2", "2026-01-01T00:00:01.5Z", "cg-a", command)
			}
			if _, err := MaterializeLLMCalls(st, db, "intent-test"); err != nil {
				t.Fatal(err)
			}
			if n := intentCausedCount(t, db); n != tt.want {
				t.Fatalf("llm_caused=%d, want %d", n, tt.want)
			}
		})
	}
}

func TestLLMArgumentBoundaries(t *testing.T) {
	for _, tt := range []struct {
		name, command, decided string
		argv                   []string
		want                   bool
	}{
		{"command text only", "python3 /work/Build.py install", "python3 /work/Build.py install", nil, false},
		{"short exact command", "ls", "ls", []string{"ls"}, true},
		{"whole arguments", "", "cat /work/Report.txt", []string{"cat", "/work/Report.txt"}, true},
		{"joined arguments collide", "cat /work/Report.txt", "cat /work/Report.txt", []string{"cat /work/Report.txt"}, false},
		{"literal quotes", `printf 'a  b'`, `printf 'a b'`, nil, false},
		{"joined quote boundaries unknown", `printf 'a b'`, `printf 'a b'`, nil, false},
		{"absolute path different", "/opt/python3 setup.py install", "python3 setup.py install", nil, false},
		{"extra argument", "", "python3 setup.py install", []string{"python3", "setup.py", "install", "--user"}, false},
		{"shell script exact", "", `printf 'a  b'`, []string{"/bin/bash", "-lc", `printf 'a  b'`}, true},
		{"shell script whitespace", "", `printf 'a b'`, []string{"/bin/bash", "-lc", `printf 'a  b'`}, false},
		{"shell script extra", "", "python3 setup.py install", []string{"/bin/sh", "-c", "python3 setup.py install && curl example.test"}, false},
		{"wrapper prefix", "/bin/bash -c source /tmp/env && python3 setup.py install", "python3 setup.py install", nil, false},
		{"nonbreaking space in path", "", "cat /work/A B", []string{"cat", "/work/A\u00a0B"}, false},
		{"literal nonbreaking space", "", "cat /work/A\u00a0B", []string{"cat", "/work/A\u00a0B"}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := llmActionMatches(llmAction{argv: tt.argv}, tt.decided); got != tt.want {
				t.Fatalf("matched=%v, want %v", got, tt.want)
			}
		})
	}
}

func TestLLMScopeIsolation(t *testing.T) {
	a := llmScope{source: "agentprov_ebpf", origin: "node-a", cgroup: "cg-a", container: "container-a", session: "session-a"}
	for _, field := range []string{"source", "origin", "cgroup", "container", "session", "missing_origin"} {
		t.Run(field, func(t *testing.T) {
			b := a
			switch field {
			case "source":
				b.source = "other"
			case "origin":
				b.origin = "node-b"
			case "cgroup":
				b.cgroup = "cg-b"
			case "container":
				b.container = "container-b"
			case "session":
				b.session = "session-b"
			case "missing_origin":
				b.origin = ""
			}
			if llmScopesMatch(a, b) || llmScopesMatch(b, a) {
				t.Fatal("conflicting scopes matched")
			}
		})
	}
	if !llmScopesMatch(a, a) {
		t.Fatal("identical scope did not match")
	}
}

func TestLLMCommandCaptureFlags(t *testing.T) {
	for _, raw := range []string{
		`{"node_name":"node-a","argv":["cat","/work/config"],"argv_truncated":true}`,
		`{"node_name":"node-a","argv":["cat /work/config"],"command":"cat /work/config"}`,
		`{"node_name":"node-a","argv":[],"command":"cat /work/config"}`,
		`{"node_name":"node-a","argv":["cat",42],"command":"cat /work/config"}`,
	} {
		t.Run(raw, func(t *testing.T) {
			st, db := intentTestStore(t)
			intentTestDecision(t, db, "d", "2026-01-01T00:00:01Z", "cg-a", "cat /work/config")
			intentTestEvent(t, db, "action", "execve", "2026-01-01T00:00:02Z", "cg-a", "")
			if _, err := db.Exec(`UPDATE events SET payload=? WHERE id='action'`, raw); err != nil {
				t.Fatal(err)
			}
			if _, err := MaterializeLLMCalls(st, db, "intent-test"); err != nil {
				t.Fatal(err)
			}
			if n := intentCausedCount(t, db); n != 0 {
				t.Fatalf("invalid argv linked: %d", n)
			}
		})
	}
}

func TestLLMCommandIgnoresLegacyDuplicateEdges(t *testing.T) {
	st, db := intentTestStore(t)
	intentTestDecision(t, db, "d", "2026-01-01T00:00:01Z", "cg-a", "cat /work/config")
	intentTestEvent(t, db, "action", "execve", "2026-01-01T00:00:02Z", "cg-a", "cat /work/config")
	if _, err := db.Exec(`INSERT INTO graph_edges SELECT 'duplicate',run_id,rollout_id,from_id,to_id,edge_type,source_event_id,created_at FROM graph_edges WHERE id='d'`); err != nil {
		t.Fatal(err)
	}
	if _, err := MaterializeLLMCalls(st, db, "intent-test"); err != nil {
		t.Fatal(err)
	}
	if n := intentCausedCount(t, db); n != 1 {
		t.Fatalf("legacy edge changed identity-based pairing: %d", n)
	}
}

func TestLLMCommandEdgesCarryDerivation(t *testing.T) {
	st, db := intentTestStore(t)
	intentTestDecision(t, db, "d", "2026-01-01T00:00:01Z", "cg-a", "cat /work/config")
	intentTestEvent(t, db, "action", "execve", "2026-01-01T00:00:02Z", "cg-a", "cat /work/config")
	db.SetMaxOpenConns(1)
	if _, err := MaterializeLLMCalls(st, db, "intent-test"); err != nil {
		t.Fatal(err)
	}
	edges, err := graphLensEdges(db, "intent-test")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, edge := range edges {
		if edge.EdgeType != edgeLLMCaused {
			continue
		}
		found = true
		if !edge.Derived || edge.DerivationRule != llmCommandRule || edge.Confidence == nil || *edge.Confidence != llmCommandConfidence ||
			!reflect.DeepEqual(edge.EvidenceRefs, []string{"llm_call/d-req", "runtime_event/action", "runtime_event/d-resp"}) {
			t.Fatalf("derivation metadata: %+v", edge)
		}
	}
	if !found {
		t.Fatal("missing command edge")
	}
}

func TestLLMReanalysisFailureKeepsLastGraph(t *testing.T) {
	st, db := intentTestStore(t)
	intentTestDecision(t, db, "d", "2026-01-01T00:00:01Z", "cg-a", "cat /work/config")
	intentTestEvent(t, db, "action", "execve", "2026-01-01T00:00:02Z", "cg-a", "cat /work/config")
	if _, err := MaterializeLLMCalls(st, db, "intent-test"); err != nil {
		t.Fatal(err)
	}
	before := intentDerivedSnapshot(t, db)
	if _, err := db.Exec(`CREATE TRIGGER fail_llm BEFORE INSERT ON graph_edges WHEN NEW.edge_type='llm_response' BEGIN SELECT RAISE(ABORT,'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := MaterializeLLMCalls(st, db, "intent-test"); err == nil || !strings.Contains(err.Error(), "injected failure") {
		t.Fatalf("failure=%v", err)
	}
	if after := intentDerivedSnapshot(t, db); !reflect.DeepEqual(before, after) {
		t.Fatalf("failed replacement changed graph: %v / %v", before, after)
	}
	if _, err := db.Exec(`DROP TRIGGER fail_llm`); err != nil {
		t.Fatal(err)
	}
	if _, err := MaterializeLLMCalls(st, db, "intent-test"); err != nil {
		t.Fatal(err)
	}
	if n := intentCausedCount(t, db); n != 1 {
		t.Fatalf("retry edges=%d", n)
	}
}

func intentDerivedSnapshot(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT id,from_id,to_id,edge_type FROM graph_edges WHERE run_id='intent-test' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id, from, to, typ string
		if err := rows.Scan(&id, &from, &to, &typ); err != nil {
			t.Fatal(err)
		}
		out = append(out, strings.Join([]string{id, from, to, typ}, "\x00"))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestLLMMatchDecisionLimit(t *testing.T) {
	_, err := matchLLMDecisions(make([]llmDecision, maxLLMDecisions+1), nil)
	if err == nil {
		t.Fatal("expected input limit error")
	}
	at := time.Now()
	actions := make([]llmAction, maxLLMComparisons/20+1)
	decisions := make([]llmDecision, 20)
	for i := range decisions {
		decisions[i] = llmDecision{command: "cat /work/config", at: at}
	}
	if _, err := matchLLMDecisions(decisions, actions); err == nil {
		t.Fatal("expected comparison limit error")
	}
}

func TestLLMNativeBootScope(t *testing.T) {
	const bootA = "12345678-1234-1234-1234-123456789abc"
	const bootB = "abcdefab-1234-1234-1234-123456789abc"
	for _, tt := range []struct {
		name, actionInstance string
		want                 int
	}{
		{"same boot", bootA + ":200:900", 1},
		{"other boot", bootB + ":200:900", 0},
		{"wrong pid", bootA + ":201:900", 0},
		{"invalid birth time", bootA + ":200:0", 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			st, db := intentTestStore(t)
			intentTestDecision(t, db, "d", "2026-01-01T00:00:01Z", "cg-a", "cat /work/config")
			intentTestEvent(t, db, "action", "execve", "2026-01-01T00:00:02Z", "cg-a", "cat /work/config")
			for id, instance := range map[string]string{"d-req": bootA + ":100:800", "d-resp": bootA + ":100:800", "action": tt.actionInstance} {
				var raw string
				if err := db.QueryRow(`SELECT payload FROM events WHERE id=?`, id).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				var payload map[string]any
				if err := json.Unmarshal([]byte(raw), &payload); err != nil {
					t.Fatal(err)
				}
				delete(payload, "node_name")
				payload["process_instance_id"] = instance
				encoded, _ := json.Marshal(payload)
				pid := 100
				if id == "action" {
					pid = 200
				}
				if _, err := db.Exec(`UPDATE events SET pid=?,payload=? WHERE id=?`, pid, string(encoded), id); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := MaterializeLLMCalls(st, db, "intent-test"); err != nil {
				t.Fatal(err)
			}
			if n := intentCausedCount(t, db); n != tt.want {
				t.Fatalf("edges=%d, want %d", n, tt.want)
			}
		})
	}
}

func TestLLMPlainCommandIgnoresShellLauncher(t *testing.T) {
	st, db := intentTestStore(t)
	intentTestDecision(t, db, "d", "2026-01-01T00:00:01Z", "cg-a", "cat /work/config")
	intentTestEvent(t, db, "exec", "execve", "2026-01-01T00:00:02Z", "cg-a", "cat /work/config")
	intentTestEvent(t, db, "shell", "execve", "2026-01-01T00:00:01.5Z", "cg-a", "")
	payload, _ := json.Marshal(map[string]any{"node_name": "node-a", "argv": []string{"/bin/bash", "-c", "cat /work/config"}})
	if _, err := db.Exec(`UPDATE events SET payload=? WHERE id='shell'`, string(payload)); err != nil {
		t.Fatal(err)
	}
	if _, err := MaterializeLLMCalls(st, db, "intent-test"); err != nil {
		t.Fatal(err)
	}
	var action string
	if err := db.QueryRow(`SELECT to_id FROM graph_edges WHERE edge_type='llm_caused'`).Scan(&action); err != nil {
		t.Fatal(err)
	}
	if n := intentCausedCount(t, db); n != 1 || action != "runtime_event/exec" {
		t.Fatalf("matched %d executions, target=%s", n, action)
	}
}
