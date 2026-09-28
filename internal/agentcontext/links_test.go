package agentcontext

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
)

func TestContextLinksUseRecordedEdgesAndKeepSessionIsolation(t *testing.T) {
	s := testService(t)
	ctx := context.Background()
	body := `{"command":"same command"}`
	for _, session := range []string{"alice", "bob"} {
		src := testSource()
		src.ID, src.SessionID = session, session
		_, err := s.Save(ctx, "run", src, []Record{
			{Key: "call", Kind: "tool_call", Sequence: 1, ToolCallID: "reused", Body: &body},
			{Key: "result", Kind: "tool_result", Sequence: 2, ToolCallID: "reused", Body: &body},
			{Key: "config", Kind: "configuration", Sequence: 3, Body: &body},
		}, Coverage{Status: OK})
		if err != nil {
			t.Fatal(err)
		}
	}
	page, err := s.Entries(ctx, PageOptions{RunID: "run", SessionID: "alice", Group: "conversation"})
	if err != nil || len(page.Entries) != 2 {
		t.Fatalf("conversation: %+v %v", page, err)
	}
	call := ToolNodeID(page.Entries[0])
	for _, entry := range page.Entries {
		_, err = s.DB.Exec(`INSERT INTO graph_edges (id, run_id, from_id, to_id, edge_type, created_at)
			VALUES (?, 'run', ?, ?, ?, '')`, entry.ID, entry.ObjectHash, call, "context_"+entry.Kind)
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err = s.DB.Exec(`INSERT INTO graph_edges (id, run_id, from_id, to_id, edge_type, created_at)
		VALUES ('runtime-link', 'run', ?, 'runtime_event/exec', 'agent_syscall', ''),
		('other-run', 'unrelated', ?, 'runtime_event/wrong-run', 'agent_syscall', '')`, call, call)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range []string{call, "runtime_event/exec"} {
		linked, err := s.Entries(ctx, PageOptions{RunID: "run", NodeID: node, Limit: 1})
		if err != nil || !linked.HasMore || len(linked.Entries) != 1 || linked.Entries[0].Source.SessionID != "alice" {
			t.Fatalf("linked: %+v %v", linked, err)
		}
		next, err := s.Entries(ctx, PageOptions{RunID: "run", NodeID: node, Cursor: linked.NextCursor, Limit: 1})
		if err != nil || next.HasMore || len(next.Entries) != 1 || next.Entries[0].Source.SessionID != "alice" {
			t.Fatalf("next: %+v %v", next, err)
		}
		_, err = s.Entries(ctx, PageOptions{RunID: "run", NodeID: "other", Cursor: linked.NextCursor, Limit: 1})
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("node filter not bound to cursor: %v", err)
		}
	}
	for _, node := range []string{"same command", "reused", "runtime_event/wrong-run"} {
		linked, err := s.Entries(ctx, PageOptions{RunID: "run", NodeID: node})
		if err != nil || len(linked.Entries) != 0 {
			t.Fatalf("guessed link %q: %+v %v", node, linked, err)
		}
	}
	links, err := s.Links(ctx, "run", page.Entries[0].ID)
	if err != nil || len(links.Links) != 1 || links.Links[0].NodeID != call || links.Basis != "recorded_graph_edge" {
		t.Fatalf("links: %+v %v", links, err)
	}
	configs, err := s.Entries(ctx, PageOptions{RunID: "run", Group: "configuration"})
	if err != nil || len(configs.Entries) != 2 {
		t.Fatalf("configurations: %+v %v", configs, err)
	}
	links, err = s.Links(ctx, "run", configs.Entries[0].ID)
	if err != nil || len(links.Links) != 0 || links.Reason != "no_recorded_graph_link" {
		t.Fatalf("missing link: %+v %v", links, err)
	}
	w := httptest.NewRecorder()
	s.ReadHandler().ServeHTTP(w, httptest.NewRequest("GET", "/context/links?run=run&entry="+page.Entries[0].ID, nil))
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &links) != nil || len(links.Links) != 1 {
		t.Fatalf("link API: %d %s", w.Code, w.Body.String())
	}
}
