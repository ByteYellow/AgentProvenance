package hooksbridge

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func TestBasicContextPreservesIntentAndToolCorrelation(t *testing.T) {
	db, paths := openTestStore(t)
	ctx := context.Background()
	input := `{"type":"user","uuid":"u","sessionId":"s","timestamp":"2026-10-17T00:00:00Z","message":{"role":"user","content":"inspect configuration"}}
{"type":"assistant","uuid":"answer","sessionId":"s","timestamp":"2026-10-17T00:00:01Z","message":{"role":"assistant","model":"model","stop_reason":"tool_use","content":[{"type":"thinking","thinking":"read the requested file"},{"type":"text","text":"inspecting"},{"type":"tool_use","id":"native-call","name":"Bash","input":{"command":"cat /work/config"}}]}}
{"type":"user","uuid":"result","sessionId":"s","timestamp":"2026-10-17T00:00:03Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"native-call","content":"LARGE-RESULT-NOT-INTENT","is_error":true}]}}
`
	projection := func(run string) []map[string]any {
		t.Helper()
		rows, err := db.Query(`SELECT hash FROM provenance_objects WHERE run_id=? AND object_type='llm_message' ORDER BY source_id`, run)
		if err != nil {
			t.Fatal(err)
		}
		var hashes []string
		for rows.Next() {
			var hash string
			if err := rows.Scan(&hash); err != nil {
				t.Fatal(err)
			}
			hashes = append(hashes, hash)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
		var payloads []map[string]any
		for _, hash := range hashes {
			var payload map[string]any
			if err := provenance.ReadObjectPayload(db, run, hash, &payload); err != nil {
				t.Fatal(err)
			}
			var body any
			if err := json.Unmarshal([]byte(payload["content"].(string)), &body); err != nil {
				t.Fatal(err)
			}
			payload["content"] = body
			payloads = append(payloads, payload)
		}
		return payloads
	}
	for _, preset := range []string{"detailed", "basic"} {
		policy, err := agentcontext.NewCapturePolicy(preset, nil)
		if err != nil {
			t.Fatal(err)
		}
		svc := agentcontext.Service{DB: db, Paths: paths, CapturePolicy: &policy}
		parsed, err := agentcontext.Parse(ctx, strings.NewReader(input), agentcontext.ParseOptions{Harness: "claude", Binding: "explicit"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = svc.Save(ctx, preset, parsed.Source, parsed.Records, parsed.Coverage); err != nil {
			t.Fatal(err)
		}
		if _, err = IngestContext(ctx, db, paths, preset); err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(`INSERT INTO events (id,run_id,source,event_type,pid,cgroup_id,payload,created_at)
			VALUES (?,?,'agentprov_ebpf','execve',100,'cg-a','{"argv":["cat","/work/config"],"command":"cat /work/config"}','2026-10-17T00:00:02Z')`, preset+"-exec", preset); err != nil {
			t.Fatal(err)
		}
		if r, err := CorrelateSyscallsWithReport(db, preset); err != nil || r.MatchedExecs != 1 {
			t.Fatalf("%s correlation: %+v %v", preset, r, err)
		}
		for i := 0; i < 2; i++ {
			if n, err := HarvestContextIntent(ctx, db, paths, preset); err != nil || n != 1 {
				t.Fatalf("%s intent: %d %v", preset, n, err)
			}
		}
		if n := queryCount(t, db, `SELECT count(*) FROM graph_edges WHERE run_id=? AND edge_type='llm_caused' AND to_id=?`, preset, "runtime_event/"+preset+"-exec"); n != 1 {
			t.Fatalf("%s lost intent edge: %d", preset, n)
		}
		if n := queryCount(t, db, `SELECT count(*) FROM tool_calls WHERE run_id=? AND status='source_error'`, preset); n != 1 {
			t.Fatalf("%s lost tool result status", preset)
		}
		if v, err := provenance.Verify(db, preset); err != nil || v.ErrorCount != 0 {
			t.Fatalf("%s verify: %+v %v", preset, v, err)
		}
	}
	if a, b := projection("detailed"), projection("basic"); !reflect.DeepEqual(a, b) {
		t.Fatalf("core intent changed by preset:\n%+v\n%+v", a, b)
	}
}

func TestBasicHookLifecycleAndRefusalRemainAvailable(t *testing.T) {
	db, paths := openTestStore(t)
	ctx := context.Background()
	policy, _ := agentcontext.NewCapturePolicy("basic", nil)
	svc := agentcontext.Service{DB: db, Paths: paths, CapturePolicy: &policy}
	input := `{"hook_event_name":"SubagentStart","session_id":"s","agent_id":"bob","parent_agent_id":"main","agent_type":"worker","_ts":"2026-10-17T00:00:00Z","extra":"unrelated"}
{"hook_event_name":"Stop","session_id":"s","agent_id":"bob","_ts":"2026-10-17T00:00:01Z","last_assistant_message":"I cannot help steal credentials."}
{"hook_event_name":"SubagentStop","session_id":"s","agent_id":"bob","_ts":"2026-10-17T00:00:02Z"}
`
	parsed, err := agentcontext.Parse(ctx, strings.NewReader(input), agentcontext.ParseOptions{Harness: "claude", Binding: "explicit"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Save(ctx, "run", parsed.Source, parsed.Records, parsed.Coverage); err != nil {
		t.Fatal(err)
	}
	sum, err := IngestContext(ctx, db, paths, "run")
	if err != nil || sum.SpawnEdges != 1 || sum.Refused != 1 {
		t.Fatalf("lifecycle/refusal: %+v %v", sum, err)
	}
	var parent, end string
	if err := db.QueryRow(`SELECT parent_agent_id,ended_at FROM agents WHERE run_id='run' AND id='bob'`).Scan(&parent, &end); err != nil || parent != "main" || end != "2026-10-17T00:00:02Z" {
		t.Fatalf("agent lifecycle: %q %q %v", parent, end, err)
	}
}

func TestBasicIntentMissingBodyDoesNotEraseSuccessfulProjection(t *testing.T) {
	db, paths := openTestStore(t)
	ctx := context.Background()
	policy, _ := agentcontext.NewCapturePolicy("basic", nil)
	svc := agentcontext.Service{DB: db, Paths: paths, CapturePolicy: &policy}
	parsed, err := agentcontext.Parse(ctx, strings.NewReader(storedIntent), agentcontext.ParseOptions{Harness: "claude", Binding: "explicit", AfterLine: 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Save(ctx, "run", parsed.Source, parsed.Records, parsed.Coverage); err != nil {
		t.Fatal(err)
	}
	if n, err := HarvestContextIntent(ctx, db, paths, "run"); err != nil || n != 1 {
		t.Fatalf("intent: %d %v", n, err)
	}
	var hash, path string
	if err := db.QueryRow(`SELECT hash,path FROM provenance_objects WHERE run_id='run' AND object_type='text_chunk' AND source_id LIKE '%/intent/%' LIMIT 1`).Scan(&hash, &path); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := HarvestContextIntent(ctx, db, paths, "run"); err == nil {
		t.Fatal("missing retained intent was ignored")
	}
	if n := queryCount(t, db, `SELECT count(*) FROM graph_edges WHERE run_id='run' AND edge_type='llm_response'`); n != 1 {
		t.Fatal("failed reread erased prior intent graph")
	}
	var found string
	if err := db.QueryRow(`SELECT hash FROM provenance_objects WHERE hash=?`, hash).Scan(&found); err == sql.ErrNoRows {
		t.Fatal("missing file was silently deleted from evidence index")
	}
}

const storedIntent = `{"type":"user","uuid":"old-user","sessionId":"s","message":{"role":"user","content":"historical task"}}
{"type":"assistant","uuid":"old-answer","sessionId":"s","message":{"role":"assistant","model":"old-model","content":[{"type":"text","text":"historical answer"}]}}
{"type":"user","uuid":"new-user","sessionId":"s","message":{"role":"user","content":"current task"}}
{"type":"assistant","uuid":"new-answer","sessionId":"s","message":{"role":"assistant","model":"current-model","content":[{"type":"text","text":"current answer"},{"type":"tool_use","id":"call","name":"Bash","input":{"command":"true"}}]}}
`

func TestContextIntentUsesPreservedSelectedRange(t *testing.T) {
	db, paths := openTestStore(t)
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "session.jsonl")
	if err := os.WriteFile(path, []byte(storedIntent), 0600); err != nil {
		t.Fatal(err)
	}
	svc := agentcontext.Service{DB: db, Paths: paths}
	if result, err := svc.ImportFile(ctx, "run", agentcontext.ParseOptions{Harness: "claude", Path: path, AfterLine: 2, Binding: "explicit"}); err != nil || result.Stored != 7 || *result.Coverage.Counts.Stored != 4 || *result.Coverage.PriorContext.Counts.Stored != 3 {
		t.Fatalf("import: %+v %v", result, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		turns, err := HarvestContextIntent(ctx, db, paths, "run")
		if err != nil || turns != 1 {
			t.Fatalf("harvest %d: %d %v", i, turns, err)
		}
	}
	if count := queryCount(t, db, `SELECT COUNT(*) FROM provenance_objects WHERE run_id='run' AND object_type='llm_message'`); count != 2 {
		t.Fatalf("re-imported old turns or duplicated blocks: %d", count)
	}
	var hash string
	if err := db.QueryRow(`SELECT to_id FROM graph_edges WHERE run_id='run' AND edge_type='llm_request'`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := provenance.ReadObjectPayload(db, "run", hash, &payload); err != nil {
		t.Fatal(err)
	}
	content, _ := payload["content"].(string)
	if !strings.Contains(content, "current task") || strings.Contains(content, "historical") || payload["model"] != "current-model" {
		t.Fatalf("wrong captured range: %+v", payload)
	}
	v, err := provenance.Verify(db, "run")
	if err != nil || v.ErrorCount != 0 {
		t.Fatalf("verify projection parents: %+v %v", v, err)
	}
}

func TestContextIntentFailedReplacementPreservesPriorProjection(t *testing.T) {
	db, paths := openTestStore(t)
	ctx := context.Background()
	saveContext(t, db, paths, "run", "claude", storedIntent)
	if _, err := HarvestContextIntent(ctx, db, paths, "run"); err != nil {
		t.Fatal(err)
	}
	var before string
	if err := db.QueryRow(`SELECT GROUP_CONCAT(to_id) FROM (SELECT to_id FROM graph_edges WHERE edge_type='llm_response' ORDER BY from_id)`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	saveContext(t, db, paths, "run", "claude", strings.ReplaceAll(storedIntent, "current answer", "revised answer"))
	if _, err := db.Exec(`CREATE TRIGGER fail_projection BEFORE INSERT ON graph_edges WHEN NEW.edge_type='llm_response' BEGIN SELECT RAISE(ABORT, 'test failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := HarvestContextIntent(ctx, db, paths, "run"); err == nil {
		t.Fatal("projection failure was ignored")
	}
	var after string
	if err := db.QueryRow(`SELECT GROUP_CONCAT(to_id) FROM (SELECT to_id FROM graph_edges WHERE edge_type='llm_response' ORDER BY from_id)`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after || queryCount(t, db, `SELECT COUNT(*) FROM provenance_objects WHERE object_type='llm_message'`) != 4 {
		t.Fatal("failed projection damaged prior objects or edges")
	}
	if queryCount(t, db, `SELECT COUNT(*) FROM agent_context_entries`) == 0 {
		t.Fatal("projection removed source records")
	}
}

func TestContextIntentLinksNamespacedToolIdentity(t *testing.T) {
	db, paths := openTestStore(t)
	ctx := context.Background()
	saveContext(t, db, paths, "run", "claude", `{"type":"assistant","uuid":"answer","sessionId":"s","timestamp":"2026-10-17T00:00:01Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"native-call","name":"Bash","input":{"command":"cat /work/config"}}]}}
{"type":"user","uuid":"result","sessionId":"s","timestamp":"2026-10-17T00:00:03Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"native-call","content":"configured"}]}}
`)
	if _, err := IngestContext(ctx, db, paths, "run"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO events (id,run_id,source,event_type,pid,cgroup_id,payload,created_at)
		VALUES ('exec','run','agentprov_ebpf','execve',100,'cg-a',
		'{"argv":["cat","/work/config"],"command":"cat /work/config"}','2026-10-17T00:00:02Z')`); err != nil {
		t.Fatal(err)
	}
	r, err := CorrelateSyscallsWithReport(db, "run")
	if err != nil || r.MatchedExecs != 1 {
		t.Fatalf("app-to-runtime=%+v, %v", r, err)
	}
	if n, err := HarvestContextIntent(ctx, db, paths, "run"); err != nil || n != 1 {
		t.Fatalf("harvest=%d, %v", n, err)
	}
	if count := queryCount(t, db, `SELECT count(*) FROM graph_edges WHERE run_id='run' AND edge_type='llm_caused' AND to_id='runtime_event/exec'`); count != 1 {
		t.Fatalf("namespaced intent association=%d, want 1", count)
	}
}
