package provenance

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/ids"
	"github.com/byteyellow/agentprovenance/internal/store"
)

// A scoped, chronological, complete command match creates one inferred link.
func TestMaterializeLLMCallsDirectLink(t *testing.T) {
	paths, err := store.Init(filepath.Join(t.TempDir(), ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st := ObjectStore{DB: db, Paths: paths}
	const run = "run-dl"
	ins := func(id, etype, payload string) {
		at := "2026-01-01T00:00:01Z"
		if etype == "tls_write" {
			at = "2026-01-01T00:00:00Z"
		}
		if etype == "execve" {
			at = "2026-01-01T00:00:02Z"
		}
		payload = `{"node_name":"node-a",` + payload[1:]
		if etype == "tls_write" || etype == "tls_read" {
			payload = tlsTestIdentity(t, payload, "connection-a", etype)
		}
		if _, err := db.Exec(`INSERT INTO events (id, run_id, source, event_type, payload, created_at, cgroup_id, pid)
			VALUES (?, ?, 'agentprov_ebpf', ?, ?, ?, 'cg-a', 100)`, id, run, etype, payload, at); err != nil {
			t.Fatal(err)
		}
	}
	ins("ev-req", "tls_write", `{"content":"{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":\"go\"}]}"}`)
	// The model decides to run a specific command via tool_use.
	ins("ev-resp", "tls_read", `{"content":"{\"model\":\"m\",\"stop_reason\":\"tool_use\",\"content\":[{\"type\":\"tool_use\",\"name\":\"bash\",\"input\":{\"command\":\"cat /home/u/.aws/credentials\"}}]}"}`)
	// The syscall that ran exactly that command -- and an unrelated one that must NOT link.
	ins("ev-exec", "execve", `{"payload":{"raw":{"argv":["cat","/home/u/.aws/credentials"],"command":"cat /home/u/.aws/credentials"}}}`)
	ins("ev-other", "execve", `{"payload":{"raw":{"argv":["ls","-la","/tmp"],"command":"ls -la /tmp"}}}`)
	if _, err := db.Exec(`INSERT INTO graph_edges (id, run_id, from_id, to_id, edge_type, created_at)
		VALUES (?, ?, 'runtime_event/ev-req', 'runtime_event/ev-resp', 'llm_call', '2026-01-01T00:00:02Z')`, ids.New("edge"), run); err != nil {
		t.Fatal(err)
	}

	if _, err := MaterializeLLMCalls(st, db, run); err != nil {
		t.Fatal(err)
	}
	// Only the command-matched execve links; the unrelated one does not.
	var caused, other int
	db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE run_id=? AND from_id='llm_call/ev-req' AND to_id='runtime_event/ev-exec' AND edge_type='llm_caused'`, run).Scan(&caused)
	db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE run_id=? AND to_id='runtime_event/ev-other' AND edge_type='llm_caused'`, run).Scan(&other)
	if caused != 1 {
		t.Errorf("llm_caused edge llm_call -> matching execve = %d, want 1", caused)
	}
	if other != 0 {
		t.Errorf("unrelated execve got %d llm_caused edges, want 0 (command-match must be precise)", other)
	}
}

// A later process sample does not establish when that command was executed.
// Keep the observation, but do not use it to fill a truncated exec's intent edge.
func TestLLMCommandMatchDoesNotUpgradeProcessSamples(t *testing.T) {
	paths, err := store.Init(filepath.Join(t.TempDir(), ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const run = "run-trunc"
	ins := func(id, etype, payload string) {
		payload = `{"node_name":"node-a",` + payload[1:]
		if _, err := db.Exec(`INSERT INTO events (id, run_id, source, event_type, payload, created_at, cgroup_id, pid)
			VALUES (?, ?, 'agentprov_ebpf', ?, ?, '2026-01-01T00:00:01Z', 'cg-a', 100)`, id, run, etype, payload); err != nil {
			t.Fatal(err)
		}
	}
	decided := "python3 ../pysnake-helper/setup.py install --user"
	// The execve for that command came through truncated to just the program.
	ins("ev-exec", "execve", `{"payload":{"raw":{"argv":["/usr/bin/python3"],"argv_truncated":true,"command":"/usr/bin/python3"}}}`)
	// The record sample has a complete command but no execution-time anchor.
	ins("ev-proc", "process_observed", `{"payload":{"argv":["python3","../pysnake-helper/setup.py","install","--user"],"command":"python3 ../pysnake-helper/setup.py install --user","pid":913280}}`)
	// The shell wrapper Claude runs the command through CONTAINS the decided
	// command among additional setup steps; it is not an exact execution anchor.
	ins("ev-wrap", "process_observed", `{"payload":{"command":"/bin/bash -c source /home/u/.claude/shell-snapshots/snap.sh && python3 ../pysnake-helper/setup.py install","pid":913279}}`)
	// A different command that merely shares the workspace path must not match.
	ins("ev-other", "process_observed", `{"payload":{"command":"ls -la ../pysnake-helper","pid":42}}`)

	actions, err := readLLMActions(db, run, false)
	if err != nil {
		t.Fatal(err)
	}
	got, err := matchLLMDecisions([]llmDecision{{command: decided, at: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		scope: llmScope{source: "agentprov_ebpf", origin: "origin:node-a", cgroup: "cg-a"}}}, actions)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("sample-only attribution: %v", got)
	}
}

func TestMaterializeLLMCalls(t *testing.T) {
	paths, err := store.Init(filepath.Join(t.TempDir(), ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st := ObjectStore{DB: db, Paths: paths}
	const run = "run-llm"

	ins := func(id, etype, payload string) {
		payload = tlsTestIdentity(t, `{"node_name":"node-a",`+payload[1:], "connection-a", etype)
		at := "2026-01-01T00:00:01Z"
		if etype == "tls_read" {
			at = "2026-01-01T00:00:02Z"
		}
		if _, err := db.Exec(`INSERT INTO events (id, run_id, source, event_type, payload, created_at, cgroup_id, pid)
			VALUES (?, ?, 'agentprov_ebpf', ?, ?, ?, 'cg-a', 100)`, id, run, etype, payload, at); err != nil {
			t.Fatal(err)
		}
	}
	ins("ev-req", "tls_write", `{"model":"claude-opus-4-8","content":"{\"model\":\"claude-opus-4-8\",\"messages\":[{\"role\":\"user\",\"content\":\"read creds\"}]}"}`)
	ins("ev-resp", "tls_read", `{"model":"claude-opus-4-8","content":"{\"model\":\"claude-opus-4-8\",\"content\":[{\"type\":\"tool_use\",\"name\":\"bash\"}]}"}`)
	// A legacy ingest-time edge is ignored and replaced by identity-based analysis.
	if _, err := db.Exec(`INSERT INTO graph_edges (id, run_id, from_id, to_id, edge_type, created_at)
		VALUES ('e1', ?, 'runtime_event/ev-req', 'runtime_event/ev-resp', 'llm_call', '2026-01-01T00:00:02Z')`, run); err != nil {
		t.Fatal(err)
	}

	n, err := MaterializeLLMCalls(st, db, run)
	if err != nil {
		t.Fatalf("MaterializeLLMCalls: %v", err)
	}
	if n != 1 {
		t.Errorf("llm_call nodes = %d, want 1", n)
	}
	// Two bodies objectified as content-addressed evidence.
	var objs int
	db.QueryRow(`SELECT COUNT(*) FROM provenance_objects WHERE run_id=? AND object_type='llm_message'`, run).Scan(&objs)
	if objs != 2 {
		t.Errorf("llm_message objects = %d, want 2", objs)
	}
	// The llm_call node references both the request and the response body.
	var reqEdges, respEdges int
	db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE run_id=? AND from_id='llm_call/ev-req' AND edge_type='llm_request'`, run).Scan(&reqEdges)
	db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE run_id=? AND from_id='llm_call/ev-req' AND edge_type='llm_response'`, run).Scan(&respEdges)
	if reqEdges != 1 || respEdges != 1 {
		t.Errorf("llm_call edges: request=%d response=%d, want 1/1", reqEdges, respEdges)
	}
	// Each tls event links to its body object.
	var bodyEdges int
	db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE run_id=? AND edge_type='llm_body'`, run).Scan(&bodyEdges)
	if bodyEdges != 2 {
		t.Errorf("llm_body edges = %d, want 2", bodyEdges)
	}

	// Direct link is exercised in TestMaterializeLLMCallsDirectLink.

	// Idempotent: a second pass must not duplicate objects or edges.
	if _, err := MaterializeLLMCalls(st, db, run); err != nil {
		t.Fatal(err)
	}
	db.QueryRow(`SELECT COUNT(*) FROM provenance_objects WHERE run_id=? AND object_type='llm_message'`, run).Scan(&objs)
	db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE run_id=? AND edge_type='llm_body'`, run).Scan(&bodyEdges)
	if objs != 2 || bodyEdges != 2 {
		t.Errorf("after re-run: objects=%d body edges=%d, want 2/2 (idempotent)", objs, bodyEdges)
	}
}

func TestLLMMessageMeta(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "obj.json")
	if err := os.WriteFile(f, []byte(`{"type":"llm_message","payload":{"model":"claude-opus-4-8","semantics":{"tool_calls":["bash","read_file"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	meta := llmMessageMeta(f)
	if meta.Model != "claude-opus-4-8" || len(meta.ToolCalls) != 2 || meta.ToolCalls[0] != "bash" {
		t.Errorf("llmMessageMeta = %+v", meta)
	}
	// Missing file degrades quietly.
	if missing := llmMessageMeta(filepath.Join(dir, "nope.json")); missing.Model != "" || missing.ToolCalls != nil {
		t.Errorf("missing file should yield empty, got %+v", missing)
	}
}
