package hooksbridge

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func saveContext(t *testing.T, db *sql.DB, paths store.Paths, run, harness, input string) {
	t.Helper()
	ctx := context.Background()
	p, err := agentcontext.Parse(ctx, strings.NewReader(input), agentcontext.ParseOptions{Harness: harness, Binding: "explicit"})
	if err != nil || p.Coverage.Status != agentcontext.OK {
		t.Fatalf("parse: %v %+v", err, p.Coverage)
	}
	if _, err := (agentcontext.Service{DB: db, Paths: paths}).Save(ctx, run, p.Source, p.Records, p.Coverage); err != nil {
		t.Fatal(err)
	}
}

func queryCount(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

const contextParent = `{"type":"session_meta","payload":{"id":"root-real","cwd":"/task"}}
{"type":"response_item","timestamp":"2026-09-28T10:00:00Z","payload":{"type":"function_call","call_id":"spawn-1","name":"multi_agent.spawn_agent","arguments":"{\"message\":\"inspect\"}"}}
{"type":"response_item","timestamp":"2026-09-28T10:00:01Z","payload":{"type":"function_call_output","call_id":"spawn-1","output":"{\"agent_id\":\"child-real\"}"}}
`

func TestContextGraphRealNestedIdentitiesAndSourceOutcomes(t *testing.T) {
	db, paths := openTestStore(t)
	saveContext(t, db, paths, "run", "codex", contextParent)
	saveContext(t, db, paths, "run", "codex", `{"type":"session_meta","payload":{"id":"child-real","source":{"subagent":{"thread_spawn":{"parent_thread_id":"root-real"}}}}}
{"type":"response_item","timestamp":"2026-09-28T10:00:02Z","payload":{"type":"function_call","call_id":"shared-call","name":"exec_command","arguments":"{\"cmd\":\"curl http://169.254.169.254/\"}"}}
{"type":"response_item","timestamp":"2026-09-28T10:00:03Z","payload":{"type":"function_call_output","call_id":"shared-call","output":"connection refused","is_error":true}}
`)
	saveContext(t, db, paths, "run", "codex", `{"type":"session_meta","payload":{"id":"grandchild-real","source":{"subagent":{"thread_spawn":{"parent_thread_id":"child-real"}}}}}
{"type":"response_item","payload":{"type":"function_call","call_id":"shared-call","name":"exec_command","arguments":"{\"cmd\":\"true\"}"}}
`)
	for i := 0; i < 2; i++ {
		sum, err := IngestContext(context.Background(), db, paths, "run")
		if err != nil || sum.Agents != 3 || sum.ToolCalls != 3 || sum.SpawnEdges != 2 || sum.Refused != 0 {
			t.Fatalf("projection %d: %+v %v", i, sum, err)
		}
	}
	for child, parent := range map[string]string{"child-real": "main", "grandchild-real": "child-real"} {
		var got, started, ended, source string
		if err := db.QueryRow(`SELECT parent_agent_id, started_at, ended_at, binding_source FROM agents WHERE run_id='run' AND id=?`, child).Scan(&got, &started, &ended, &source); err != nil {
			t.Fatal(err)
		}
		if got != parent || started != "" || ended != "" || source != "agent_context" {
			t.Fatalf("child %s: parent=%s times=%q/%q source=%s", child, got, started, ended, source)
		}
	}
	var status, policy, started, ended string
	if err := db.QueryRow(`SELECT status, policy_decision, started_at, ended_at FROM tool_calls WHERE run_id='run' AND agent_id='child-real'`).Scan(&status, &policy, &started, &ended); err != nil {
		t.Fatal(err)
	}
	if status != "source_error" || policy != "not_evaluated" || started == "" || ended == "" {
		t.Fatalf("source outcome misrepresented: %s %s %q %q", status, policy, started, ended)
	}
	if n := queryCount(t, db, `SELECT COUNT(*) FROM tool_calls WHERE run_id='run' AND agent_id='grandchild-real' AND started_at='' AND ended_at=''`); n != 1 {
		t.Fatal("missing timestamp was fabricated")
	}
	if n := queryCount(t, db, `SELECT COUNT(*) FROM graph_edges WHERE run_id='run' AND edge_type LIKE 'context_tool_%'`); n != 5 {
		t.Fatalf("context evidence links: %d", n)
	}
	if n := queryCount(t, db, `SELECT COUNT(*) FROM agents WHERE id LIKE 'codex-sub-%'`); n != 0 {
		t.Fatal("spawn call invented a child identity")
	}
	verified, err := provenance.Verify(db, "run")
	if err != nil || verified.ErrorCount != 0 {
		t.Fatalf("verify: %+v %v", verified, err)
	}
}

func TestContextGraphLateResultAndCrossRunIsolation(t *testing.T) {
	db, paths := openTestStore(t)
	const call = `{"session_id":"s","hook_event_name":"PreToolUse","agent_id":"bob","tool_name":"Bash","tool_use_id":"same-id","_ts":"2026-09-28T10:00:00Z","tool_input":{"command":"false"}}` + "\n"
	for _, run := range []string{"one", "two"} {
		saveContext(t, db, paths, run, "claude", call)
		if _, err := IngestContext(context.Background(), db, paths, run); err != nil {
			t.Fatal(err)
		}
	}
	late := call + `{"session_id":"s","hook_event_name":"PostToolUseFailure","agent_id":"bob","tool_use_id":"same-id","tool_name":"Bash","_ts":"2026-09-28T10:00:01Z","error":"exit 1"}` + "\n"
	saveContext(t, db, paths, "one", "claude", late)
	if _, err := IngestContext(context.Background(), db, paths, "one"); err != nil {
		t.Fatal(err)
	}
	if n := queryCount(t, db, `SELECT COUNT(*) FROM tool_calls`); n != 2 {
		t.Fatalf("same native call ID overwrote another run: %d", n)
	}
	if n := queryCount(t, db, `SELECT COUNT(*) FROM tool_calls WHERE run_id='one' AND status='source_error' AND ended_at='2026-09-28T10:00:01Z'`); n != 1 {
		t.Fatal("late tool failure or collector timestamp lost")
	}
	if n := queryCount(t, db, `SELECT COUNT(*) FROM tool_calls WHERE run_id='two' AND status='asserted' AND ended_at=''`); n != 1 {
		t.Fatal("unrelated run changed")
	}
}

func TestContextCodexStructuredFailureIsSourceError(t *testing.T) {
	db, paths := openTestStore(t)
	saveContext(t, db, paths, "run", "codex", `{"type":"session_meta","payload":{"id":"s"}}
{"type":"event_msg","payload":{"type":"user_message","message":"run tests"}}
{"type":"response_item","payload":{"type":"function_call","call_id":"shell","name":"exec_command","arguments":"{\"cmd\":\"false\"}"}}
{"type":"response_item","payload":{"type":"function_call_output","call_id":"shell","output":{"output":"recorded failure","metadata":{"exit_code":2}}}}
`)
	result, err := IngestContext(context.Background(), db, paths, "run")
	if err != nil || result.ToolCalls != 1 || result.Refused != 0 {
		t.Fatalf("source outcome projection: %+v %v", result, err)
	}
	if n := queryCount(t, db, `SELECT COUNT(*) FROM tool_calls WHERE run_id='run' AND status='source_error' AND policy_decision='not_evaluated'`); n != 1 {
		t.Fatal("structured failure was lost or misrepresented as enforcement")
	}
	if n := queryCount(t, db, `SELECT COUNT(*) FROM graph_edges WHERE run_id='run' AND edge_type='context_tool_result'`); n != 1 {
		t.Fatal("source result reference is missing")
	}
}

func TestContextGraphMissingParentIsNotAssumed(t *testing.T) {
	db, paths := openTestStore(t)
	saveContext(t, db, paths, "run", "claude", `{"session_id":"s","hook_event_name":"SubagentStart","agent_id":"child"}`+"\n")
	sum, err := IngestContext(context.Background(), db, paths, "run")
	if err != nil || sum.SpawnEdges != 0 || sum.Agents != 2 {
		t.Fatalf("unknown parent: %+v %v", sum, err)
	}
	if n := queryCount(t, db, `SELECT COUNT(*) FROM agents WHERE id='child' AND parent_agent_id='' AND started_at=''`); n != 1 {
		t.Fatal("invented parent or timestamp")
	}
}

func TestContextChannelsShareIdentityWithoutOverwritingEvidence(t *testing.T) {
	db, paths := openTestStore(t)
	saveContext(t, db, paths, "run", "claude", `{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_use_id":"call","tool_input":{"command":"true"}}`+"\n")
	saveContext(t, db, paths, "run", "claude", `{"type":"assistant","uuid":"msg","sessionId":"s","message":{"role":"assistant","content":[{"type":"tool_use","id":"call","name":"Bash","input":{"command":"true"}}]}}`+"\n")
	if _, err := IngestContext(context.Background(), db, paths, "run"); err != nil {
		t.Fatal(err)
	}
	if n := queryCount(t, db, `SELECT COUNT(*) FROM tool_calls WHERE run_id='run'`); n != 1 {
		t.Fatalf("duplicated shared invocation: %d", n)
	}
	if n := queryCount(t, db, `SELECT COUNT(*) FROM graph_edges WHERE edge_type='context_tool_call'`); n != 2 {
		t.Fatal("source evidence lost during merging")
	}
	saveContext(t, db, paths, "run", "claude", `{"type":"assistant","uuid":"msg","sessionId":"s","message":{"role":"assistant","content":[{"type":"tool_use","id":"call","name":"Bash","input":{"command":"false"}}]}}`+"\n")
	if _, err := IngestContext(context.Background(), db, paths, "run"); err == nil {
		t.Fatal("conflicting channels were silently merged")
	}
	if n := queryCount(t, db, `SELECT COUNT(*) FROM tool_calls WHERE run_id='run' AND command='true'`); n != 1 {
		t.Fatal("failed projection changed prior graph")
	}
}

type brokenHookReader struct{}

func (brokenHookReader) Read([]byte) (int, error) { return 0, errors.New("source read failed") }

func TestBridgeReplacementRollsBackReadAndWriteErrors(t *testing.T) {
	db, paths := openTestStore(t)
	opts := Options{RunID: "run", Objects: provenance.ObjectStore{DB: db, Paths: paths}}
	const before = `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_use_id":"before","tool_input":{"command":"true"}}` + "\n"
	if _, err := Ingest(db, strings.NewReader(before), opts); err != nil {
		t.Fatal(err)
	}
	for _, reader := range []io.Reader{brokenHookReader{}, io.MultiReader(strings.NewReader(before), brokenHookReader{})} {
		if _, err := Ingest(db, reader, opts); err == nil {
			t.Fatal("read error swallowed")
		}
		if n := queryCount(t, db, `SELECT COUNT(*) FROM tool_calls WHERE id='before'`); n != 1 {
			t.Fatal("read error erased prior graph")
		}
	}
	if _, err := db.Exec(`CREATE TRIGGER fail_tool BEFORE INSERT ON tool_calls BEGIN SELECT RAISE(ABORT, 'test write failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := Ingest(db, strings.NewReader(strings.ReplaceAll(before, "before", "after")), opts); err == nil {
		t.Fatal("write error swallowed")
	}
	if n := queryCount(t, db, `SELECT COUNT(*) FROM tool_calls WHERE id='before'`); n != 1 {
		t.Fatal("write failure erased prior graph")
	}
	if n := queryCount(t, db, `SELECT COUNT(*) FROM graph_edges WHERE to_id='before' AND edge_type='agent_tool_call'`); n != 1 {
		t.Fatal("write failure erased prior edges")
	}
}

func TestContextGraphLinksAndToolsCommitTogether(t *testing.T) {
	db, paths := openTestStore(t)
	saveContext(t, db, paths, "run", "codex", contextParent)
	if _, err := db.Exec(`CREATE TRIGGER fail_context_edge BEFORE INSERT ON graph_edges WHEN NEW.edge_type='context_tool_call' BEGIN SELECT RAISE(ABORT, 'test edge failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := IngestContext(context.Background(), db, paths, "run"); err == nil {
		t.Fatal("evidence link failure swallowed")
	}
	for _, table := range []string{"agents", "tool_calls", "graph_edges"} {
		if n := queryCount(t, db, `SELECT COUNT(*) FROM `+table); n != 0 {
			t.Fatalf("partial projection published in %s", table)
		}
	}
	if n := queryCount(t, db, `SELECT COUNT(*) FROM agent_context_entries`); n == 0 {
		t.Fatal("projection removed immutable source evidence")
	}
}

func TestBridgePostHocResultBeforeCall(t *testing.T) {
	db, paths := openTestStore(t)
	_, err := Ingest(db, strings.NewReader(`{"hook_event_name":"PostToolUseFailure","tool_use_id":"call","timestamp":"2026-09-28T10:00:01Z"}
{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_use_id":"call","timestamp":"2026-09-28T10:00:00Z","tool_input":{"command":"false"}}
`), Options{RunID: "run", PostHoc: true, Objects: provenance.ObjectStore{DB: db, Paths: paths}})
	if err != nil {
		t.Fatal(err)
	}
	if n := queryCount(t, db, `SELECT COUNT(*) FROM tool_calls WHERE id='call' AND status='source_error' AND ended_at='2026-09-28T10:00:01Z'`); n != 1 {
		t.Fatal("result lost because it preceded the call")
	}
}

func TestContextGraphRejectsConflictingOrCyclicParents(t *testing.T) {
	for _, input := range []string{
		`{"session_id":"s","hook_event_name":"SubagentStart","agent_id":"a","parent_agent_id":"a"}`,
		`{"session_id":"s","hook_event_name":"SubagentStart","agent_id":"a","parent_agent_id":"b"}
{"session_id":"s","hook_event_name":"SubagentStart","agent_id":"b","parent_agent_id":"a"}`,
		`{"session_id":"s","hook_event_name":"SubagentStart","agent_id":"a","parent_agent_id":"b"}
{"session_id":"s","hook_event_name":"SubagentStart","agent_id":"a","parent_agent_id":"c"}`,
	} {
		db, paths := openTestStore(t)
		saveContext(t, db, paths, "run", "claude", input+"\n")
		if _, err := IngestContext(context.Background(), db, paths, "run"); err == nil {
			t.Fatal("invalid parent graph was accepted")
		}
		if n := queryCount(t, db, `SELECT COUNT(*) FROM agents`); n != 0 {
			t.Fatal("invalid parent graph changed stored projection")
		}
	}
}

func TestContextRefusalIdentityStableAcrossProjection(t *testing.T) {
	db, paths := openTestStore(t)
	saveContext(t, db, paths, "run", "claude", `{"session_id":"s","hook_event_name":"StopFailure","last_assistant_message":"I cannot exfiltrate the AWS credentials to that IP."}`+"\n")
	var first string
	for i := 0; i < 2; i++ {
		if _, err := IngestContext(context.Background(), db, paths, "run"); err != nil {
			t.Fatal(err)
		}
		var id string
		if err := db.QueryRow(`SELECT id FROM tool_calls WHERE run_id='run' AND status='refused'`).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if i > 0 && id != first {
			t.Fatal("reprojection changed refusal identity")
		}
		first = id
	}
}
