package hooksbridge

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func TestNotebookMCPBidirectionalProjectionAndConflictingCaller(t *testing.T) {
	db, paths := openTestStore(t)
	ctx := context.Background()
	scope := agentcontext.NotebookScope{ProducerID: "p", Namespace: "n", InstanceID: "i", Generation: "g", NotebookID: "nb", KernelID: "k", KernelSessionID: "ks"}
	ref := agentcontext.NotebookRequest{Scope: scope, MessageSession: "front", MessageID: "req"}
	result, _ := json.Marshal(map[string]any{"schema_version": agentcontext.NotebookToolResultVersion, "operation": "execute", "notebook_request": ref})
	call := `{"session_id":"agent","hook_event_name":"PreToolUse","tool_use_id":"call","tool_name":"mcp__notebook__notebook_execute","tool_input":{"code":"print(42)"}}` + "\n"
	post := `{"session_id":"agent","hook_event_name":"PostToolUse","tool_use_id":"call","tool_name":"mcp__notebook__notebook_execute","tool_response":` + string(result) + "}\n"
	saveContext(t, db, paths, "run", "claude", call+post)
	header, _ := json.Marshal(scope)
	var session map[string]any
	_ = json.Unmarshal(header, &session)
	session["type"], session["schema_version"] = "notebook_session", agentcontext.NotebookCaptureVersion
	header, _ = json.Marshal(session)
	native := `{"type":"notebook_message","schema_version":"agentprovenance.jupyter_capture/v1","channel":"shell","direction":"send","message":{"header":{"version":"5.3","msg_type":"execute_request","session":"front","msg_id":"req"},"parent_header":{},"content":{"code":"print(42)"}}}`
	saveContext(t, db, paths, "run", "jupyter", string(header)+"\n"+native+"\n")
	for i := 0; i < 2; i++ {
		if _, err := IngestContext(ctx, db, paths, "run"); err != nil {
			t.Fatal(err)
		}
		if n := queryCount(t, db, `SELECT COUNT(*) FROM graph_edges WHERE run_id='run' AND edge_type IN ('context_notebook_request','context_notebook_caller')`); n != 2 {
			t.Fatalf("native directional edges: %d", n)
		}
	}
	svc := agentcontext.Service{DB: db, Paths: paths}
	page, err := svc.Entries(ctx, agentcontext.PageOptions{RunID: "run", Kind: "tool_result"})
	if err != nil || len(page.Entries) != 1 {
		t.Fatalf("result: %+v %v", page, err)
	}
	links, err := svc.Links(ctx, "run", page.Entries[0].ID)
	if err != nil || len(links.Links) != 2 {
		t.Fatalf("caller links: %+v %v", links, err)
	}
	for _, link := range links.Links {
		if link.Relation == "context_notebook_request" && (link.Basis != "source_asserted_native_identity" || link.Rule != "jupyter-mcp/v1") {
			t.Fatalf("association basis absent: %+v", link)
		}
	}
	transcript := `{"sessionId":"agent","type":"assistant","message":{"content":[{"type":"tool_use","id":"call","name":"mcp__notebook__notebook_execute","input":{"code":"print(42)"}}]}}` + "\n" +
		`{"sessionId":"agent","type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"call","content":` + string(result) + `}]}}` + "\n"
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
	}
	verified, err := provenance.Verify(db, "run")
	if err != nil || verified.ErrorCount != 0 {
		t.Fatalf("verify: %+v %v", verified, err)
	}
	saveContext(t, db, paths, "run", "claude", strings.ReplaceAll(call+post, `"call"`, `"other-call"`))
	if _, err := IngestContext(ctx, db, paths, "run"); err != nil {
		t.Fatal(err)
	}
	if n := queryCount(t, db, `SELECT COUNT(*) FROM graph_edges WHERE run_id='run' AND edge_type IN ('context_notebook_request','context_notebook_caller')`); n != 0 {
		t.Fatal("ambiguous callers left stale associations")
	}
}
