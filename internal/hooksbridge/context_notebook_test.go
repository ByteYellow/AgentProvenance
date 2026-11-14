package hooksbridge

import (
	"context"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
)

func TestNotebookOutputDoesNotFinishExecution(t *testing.T) {
	for _, terminal := range []string{"", "returned", "error", "aborted", "outcome_unknown"} {
		t.Run(terminal, func(t *testing.T) {
			db, paths := openTestStore(t)
			ctx := context.Background()
			source := agentcontext.Source{Harness: "jupyter", SessionID: "kernel-scope", Channel: "jupyter_protocol",
				ParserVersion: "jupyter-messaging/v1", Binding: "explicit"}
			body := `{"code":"print(42)"}`
			records := []agentcontext.Record{
				{Key: "call", Sequence: 1, Kind: "tool_call", ToolCallID: "request", ToolName: "jupyter.execute",
					Body: &body, Status: "sent", RecordedAt: "2026-11-14T10:00:00Z",
					Notebook: &agentcontext.NotebookMessage{MessageType: "execute_request"}},
				{Key: "output", Sequence: 3, Kind: "tool_result", ToolCallID: "request", Status: "output_observed",
					RecordedAt: "2026-11-14T10:00:03Z", Notebook: &agentcontext.NotebookMessage{MessageType: "stream"}},
			}
			if terminal != "" {
				records = append(records, agentcontext.Record{Key: "reply", Sequence: 2, Kind: "tool_result", ToolCallID: "request", Status: terminal,
					RecordedAt: "2026-11-14T10:00:02Z", Notebook: &agentcontext.NotebookMessage{MessageType: "execute_reply"}})
			}
			_, err := (agentcontext.Service{DB: db, Paths: paths}).Save(ctx, "run", source, records, agentcontext.Coverage{Status: agentcontext.OK})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := IngestContext(ctx, db, paths, "run"); err != nil {
				t.Fatal(err)
			}
			var ended, status string
			if err := db.QueryRow(`SELECT ended_at,status FROM tool_calls WHERE run_id='run'`).Scan(&ended, &status); err != nil {
				t.Fatal(err)
			}
			if terminal == "" || terminal == "outcome_unknown" {
				if ended != "" {
					t.Fatalf("output completed a request: %s %s", status, ended)
				}
			} else if ended != "2026-11-14T10:00:02Z" || (terminal == "error" || terminal == "aborted") && status != "source_error" {
				t.Fatalf("terminal result overridden by late output: %s %s", status, ended)
			}
			if queryCount(t, db, `SELECT COUNT(*) FROM graph_edges WHERE run_id='run' AND edge_type='context_tool_result'`) != len(records)-1 {
				t.Fatal("output lost its native request evidence edge")
			}
		})
	}
}
