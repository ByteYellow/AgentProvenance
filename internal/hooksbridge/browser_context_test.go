package hooksbridge

import (
	"context"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func TestBrowserMCPBidirectionalProjectionAndConflictingCaller(t *testing.T) {
	db, paths := openTestStore(t)
	ctx := context.Background()
	scope := `"producer_id":"p","namespace":"n","instance_id":"i","generation":"g","browser_id":"b","context_id":"c"`
	result := `{"schema_version":"agentprovenance.browser_tool_result/v1","operation":"execute","browser_operation":{"scope":{` + scope + `},"target_id":"page","operation_id":"op","operation":"navigate"}}`
	call := `{"session_id":"agent","hook_event_name":"PreToolUse","tool_use_id":"call","tool_name":"mcp__browser__browser_execute","tool_input":{"action":"navigate","value":"https://example.test/"}}` + "\n"
	post := `{"session_id":"agent","hook_event_name":"PostToolUse","tool_use_id":"call","tool_name":"mcp__browser__browser_execute","tool_response":` + result + "}\n"
	saveContext(t, db, paths, "run", "claude", call+post)
	svc := agentcontext.Service{DB: db, Paths: paths}
	if _, err := IngestContext(ctx, db, paths, "run"); err != nil {
		t.Fatal(err)
	}
	page, _ := svc.Entries(ctx, agentcontext.PageOptions{RunID: "run", Kind: "tool_result"})
	links, err := svc.Links(ctx, "run", page.Entries[0].ID)
	if err != nil || links.Reason != "browser_operation_unresolved" {
		t.Fatalf("early result must wait for native capture: %+v %v", links, err)
	}
	native := `{"type":"browser_session","schema_version":"agentprovenance.browser_capture/v1",` + scope + `}` + "\n" +
		`{"type":"browser_event","schema_version":"agentprovenance.browser_capture/v1","context_id":"c","event_id":"start","kind":"action_start","target_id":"page","target_type":"page","cdp_session_id":"cdp","operation_id":"op","operation":"navigate","payload":{"url":"https://example.test/"}}` + "\n"
	saveContext(t, db, paths, "run", "browser", native)
	for i := 0; i < 2; i++ {
		if _, err := IngestContext(ctx, db, paths, "run"); err != nil {
			t.Fatal(err)
		}
		if n := queryCount(t, db, `SELECT COUNT(*) FROM graph_edges WHERE run_id='run' AND edge_type IN ('context_browser_operation','context_browser_caller')`); n != 2 {
			t.Fatalf("native directional edges: %d", n)
		}
	}
	transcript := `{"sessionId":"agent","type":"assistant","message":{"content":[{"type":"tool_use","id":"call","name":"mcp__browser__browser_execute","input":{"action":"navigate","value":"https://example.test/"}}]}}` + "\n" +
		`{"sessionId":"agent","type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"call","content":` + result + `}]}}` + "\n"
	saveContext(t, db, paths, "run", "claude", transcript)
	if _, err := IngestContext(ctx, db, paths, "run"); err != nil {
		t.Fatal(err)
	}
	page, err = svc.Entries(ctx, agentcontext.PageOptions{RunID: "run", Kind: "tool_result"})
	if err != nil || len(page.Entries) != 2 {
		t.Fatalf("mirrored results: %+v %v", page, err)
	}
	for _, entry := range page.Entries {
		links, err := svc.Links(ctx, "run", entry.ID)
		if err != nil || len(links.Links) != 2 || links.Reason != "" {
			t.Fatalf("each observation must resolve: %+v %v", links, err)
		}
		for _, link := range links.Links {
			if link.Relation == "context_browser_operation" && (link.Basis != "source_asserted_native_identity" || link.Rule != "browser-mcp/v1") {
				t.Fatalf("native association basis absent: %+v", link)
			}
		}
	}
	verified, err := provenance.Verify(db, "run")
	if err != nil || verified.ErrorCount != 0 {
		t.Fatalf("verify: %+v %v", verified, err)
	}
	conflictingNative := strings.ReplaceAll(native, `"target_id":"page"`, `"target_id":"other-page"`)
	conflictingNative = strings.ReplaceAll(conflictingNative, `"event_id":"start"`, `"event_id":"other-start"`)
	saveContext(t, db, paths, "run", "browser", conflictingNative)
	if _, err := IngestContext(ctx, db, paths, "run"); err != nil {
		t.Fatal(err)
	}
	if n := queryCount(t, db, `SELECT COUNT(*) FROM graph_edges WHERE run_id='run' AND edge_type IN ('context_browser_operation','context_browser_caller')`); n != 0 {
		t.Fatal("conflicting native observations left stale associations")
	}
	saveContext(t, db, paths, "run", "claude", strings.ReplaceAll(call+post, `"call"`, `"competing-call"`))
	if _, err := IngestContext(ctx, db, paths, "run"); err != nil {
		t.Fatal(err)
	}
	if n := queryCount(t, db, `SELECT COUNT(*) FROM graph_edges WHERE run_id='run' AND edge_type IN ('context_browser_operation','context_browser_caller')`); n != 0 {
		t.Fatal("ambiguous callers left stale associations")
	}
}
