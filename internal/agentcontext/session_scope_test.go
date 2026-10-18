package agentcontext

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
)

func TestSessionScopeRejectsUnverifiedIdentityAndPriorExecution(t *testing.T) {
	s, ctx := testService(t), context.Background()
	src := testSource()
	_, err := s.Save(ctx, "run", src, []Record{{Key: "old", Kind: "tool_call", Sequence: 1, ToolCallID: "old", ExecutionScope: PriorContext}}, Coverage{Status: OK, PriorContext: &PriorRange{FirstLine: 1, LastLine: 1}})
	if err != nil {
		t.Fatal(err)
	}
	entries, err := s.Entries(ctx, PageOptions{RunID: "run"})
	if err != nil {
		t.Fatal(err)
	}
	e := entries.Entries[0]
	// Even a stale projection must not turn prior context into this run's work.
	if _, err = s.DB.Exec(`INSERT INTO graph_edges (id,run_id,from_id,to_id,edge_type,created_at) VALUES ('stale','run',?,'old-tool','context_tool_call','')`, e.ObjectHash); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`INSERT INTO tool_calls (id,run_id,command,status,created_at) VALUES ('old-tool','run','true','completed','')`); err != nil {
		t.Fatal(err)
	}
	scope, err := s.SessionGraphScope(ctx, "run", src.Harness, src.SessionID)
	if err != nil || len(scope.ToolIDs) != 0 || len(scope.EventIDs) != 0 {
		t.Fatalf("prior context scope: %+v %v", scope, err)
	}
	for _, input := range [][3]string{{"", "codex", "s"}, {"run", "", "s"}, {"run", "codex", ""}, {"run", strings.Repeat("x", 129), "s"}} {
		if _, err := s.SessionGraphScope(ctx, input[0], input[1], input[2]); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("invalid input: %v", err)
		}
	}
	if _, err := s.SessionGraphScope(ctx, "run", "claude", src.SessionID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("foreign namespace: %v", err)
	}
	if _, err = s.DB.Exec(`UPDATE agent_context_reports SET session_id='different' WHERE run_id='run'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionGraphScope(ctx, "run", src.Harness, "different"); err == nil || errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("tampered index became a valid or missing identity: %v", err)
	}
}

func TestSessionScopeDiagnosticsAreNotNativeSessions(t *testing.T) {
	s, ctx := testService(t), context.Background()
	for _, channel := range []string{"processing", "discovery", "runtime_correlation"} {
		src := testSource()
		src.Channel = channel
		if _, err := s.Save(ctx, "run", src, nil, Coverage{Status: Partial}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.SessionGraphScope(ctx, "run", "codex", "thread-one"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("diagnostics accepted: %v", err)
	}
	if _, err := s.DB.Exec(`DROP TABLE agent_context_reports`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionGraphScope(ctx, "run", "codex", "thread-one"); err == nil || errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("store failure hidden: %v", err)
	}
}
