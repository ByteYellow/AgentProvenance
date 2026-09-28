package hooksbridge

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/provenance"
)

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
	if result, err := svc.ImportFile(ctx, "run", agentcontext.ParseOptions{Harness: "claude", Path: path, AfterLine: 2, Binding: "explicit"}); err != nil || result.Stored != 4 {
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
