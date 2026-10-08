package hooksbridge

import (
	"context"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func TestResumedHistoryDoesNotProjectCurrentExecution(t *testing.T) {
	db, paths := openTestStore(t)
	ctx := context.Background()
	input := `{"type":"session_meta","payload":{"id":"s"}}
{"type":"response_item","payload":{"type":"function_call","call_id":"old","name":"exec_command","arguments":"{\"cmd\":\"curl http://169.254.169.254/\"}"}}
{"type":"response_item","payload":{"type":"function_call","call_id":"spawn","name":"spawn_agent","arguments":"{}"}}
{"type":"response_item","payload":{"type":"function_call_output","call_id":"spawn","output":"{\"agent_id\":\"old-child\"}"}}
{"type":"response_item","payload":{"type":"function_call_output","call_id":"old","output":"late response"}}
{"type":"response_item","payload":{"type":"function_call","call_id":"new","name":"exec_command","arguments":"{\"cmd\":\"true\"}"}}
{"type":"response_item","payload":{"type":"function_call_output","call_id":"new","output":"done"}}
`
	svc := agentcontext.Service{DB: db, Paths: paths}
	p, err := agentcontext.Parse(ctx, strings.NewReader(input), agentcontext.ParseOptions{Harness: "codex", Binding: "explicit", AfterLine: 4})
	if err != nil || p.Coverage.Status != agentcontext.OK {
		t.Fatalf("parse: %+v %v", p.Coverage, err)
	}
	for i := 0; i < 2; i++ {
		if _, err := svc.Save(ctx, "run", p.Source, p.Records, p.Coverage); err != nil {
			t.Fatal(err)
		}
		sum, err := IngestContext(ctx, db, paths, "run")
		if err != nil || sum.ToolCalls != 1 || sum.Agents != 1 || sum.SpawnEdges != 0 {
			t.Fatalf("old tools/children projected: %+v %v", sum, err)
		}
	}
	page, err := svc.Entries(ctx, agentcontext.PageOptions{RunID: "run"})
	if err != nil || len(page.Entries) != 8 {
		t.Fatalf("history missing: %+v %v", page, err)
	}
	for _, e := range page.Entries {
		links, err := svc.Links(ctx, "run", e.ID)
		if err != nil {
			t.Fatal(err)
		}
		if e.ExecutionScope == agentcontext.PriorContext {
			if len(links.Links) != 0 || links.Reason != "prior_context_not_current_execution" {
				t.Fatalf("historical link invented: %+v", links)
			}
		} else if e.ToolCallID == "old" && len(links.Links) != 0 {
			t.Fatalf("late result invented a current call: %+v", links)
		} else if e.ToolCallID == "new" && len(links.Links) != 1 {
			t.Fatalf("new call association lost: %+v", links)
		}
	}
	if n := queryCount(t, db, `SELECT COUNT(*) FROM graph_edges WHERE run_id='run' AND edge_type IN ('context_tool_call','context_tool_result')`); n != 2 {
		t.Fatalf("wrong execution edge count: %d", n)
	}
	v, err := provenance.Verify(db, "run")
	if err != nil || v.ErrorCount != 0 {
		t.Fatalf("verify: %+v %v", v, err)
	}
}
