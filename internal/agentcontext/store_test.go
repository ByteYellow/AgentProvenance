package agentcontext

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func testService(t *testing.T) Service {
	t.Helper()
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return Service{DB: db, Paths: paths}
}

func testSource() Source {
	return Source{Harness: "codex", SessionID: "thread-one", ParserVersion: "codex/v1", Binding: "explicit"}
}

func TestSavePreservesRevisionsAndLateResults(t *testing.T) {
	s, ctx := testService(t), context.Background()
	body := "original task"
	r := Record{Key: "one", Sequence: 1, Kind: "message", Role: "user", Body: &body}
	first, err := s.Save(ctx, "run", testSource(), []Record{r}, Coverage{Status: OK})
	if err != nil || first.Stored != 1 {
		t.Fatalf("first: %+v %v", first, err)
	}
	repeat, err := s.Save(ctx, "run", testSource(), []Record{r}, Coverage{Status: OK})
	if err != nil || repeat.Stored != 0 || repeat.Duplicates != 1 {
		t.Fatalf("repeat: %+v %v", repeat, err)
	}
	body = "changed task"
	result := "tool completed later"
	_, err = s.Save(ctx, "run", testSource(), []Record{r, {Key: "result", Sequence: 2, Kind: "tool_result", ToolCallID: "call-one", Body: &result}}, Coverage{Status: OK})
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Entries(ctx, PageOptions{RunID: "run"})
	if err != nil || len(p.Entries) != 2 {
		t.Fatalf("latest: %+v %v", p, err)
	}
	content, err := provenance.ReadTextContentPage(s.DB, "run", p.Entries[0].Content.Ref, 0, 100)
	if err != nil || content.Content != "changed task" {
		t.Fatalf("latest body: %+v %v", content, err)
	}
	all, err := s.Entries(ctx, PageOptions{RunID: "run", IncludeRevisions: true})
	if err != nil || len(all.Entries) != 3 {
		t.Fatalf("history: %+v %v", all, err)
	}
	var reports int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM agent_context_reports WHERE run_id='run'`).Scan(&reports); err != nil || reports != 3 {
		t.Fatalf("reports=%d %v", reports, err)
	}
}

func TestSaveRollbackDoesNotPublishPartialContext(t *testing.T) {
	s := testService(t)
	body := "one valid body"
	_, err := s.Save(context.Background(), "run", testSource(), []Record{
		{Key: "one", Kind: "message", Body: &body}, {Key: "bad", Kind: "invalid"},
	}, Coverage{Status: OK})
	if err == nil {
		t.Fatal("invalid record accepted")
	}
	for _, table := range []string{"agent_context_entries", "agent_context_reports", "provenance_objects"} {
		var count int
		if err := s.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s count=%d err=%v", table, count, err)
		}
	}
}

func TestUnknownCoverageDoesNotInventZeroCounts(t *testing.T) {
	s := testService(t)
	o, err := s.Overview(context.Background(), "legacy-run")
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Coverage) != 1 || o.Coverage[0].Status != LegacyNotRecorded || o.Messages != nil || o.Coverage[0].Counts.Read != nil {
		t.Fatalf("unknown coverage: %+v", o)
	}
	raw, _ := json.Marshal(o)
	if !strings.Contains(string(raw), `"messages":null`) {
		t.Fatalf("unknown count: %s", raw)
	}
}

func TestAmbiguousSourceCannotWriteRecords(t *testing.T) {
	s := testService(t)
	src := testSource()
	src.Binding = "ambiguous"
	_, err := s.Save(context.Background(), "run", src, []Record{{Key: "one", Kind: "message"}}, Coverage{Status: Ambiguous})
	if err == nil {
		t.Fatal("ambiguous records were bound")
	}
	_, err = s.Save(context.Background(), "run", src, nil, Coverage{Status: Ambiguous, Issues: []Issue{{Code: "multiple_session_candidates"}}})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPaginationAndRunIsolation(t *testing.T) {
	s, ctx := testService(t), context.Background()
	body := "visible"
	for _, run := range []string{"one", "two"} {
		_, err := s.Save(ctx, run, testSource(), []Record{
			{Key: "a", Sequence: 1, Kind: "message", Body: &body},
			{Key: "b", Sequence: 2, Kind: "tool_call", ToolCallID: "call", Body: &body},
		}, Coverage{Status: OK})
		if err != nil {
			t.Fatal(err)
		}
	}
	a, err := s.Entries(ctx, PageOptions{RunID: "one", Limit: 1})
	if err != nil || !a.HasMore || len(a.Entries) != 1 {
		t.Fatalf("first: %+v %v", a, err)
	}
	b, err := s.Entries(ctx, PageOptions{RunID: "one", Limit: 1, Cursor: a.NextCursor})
	if err != nil || b.HasMore || len(b.Entries) != 1 || a.Entries[0].ID == b.Entries[0].ID {
		t.Fatalf("second: %+v %v", b, err)
	}
	if _, err := s.Entries(ctx, PageOptions{RunID: "two", Cursor: a.NextCursor}); err == nil {
		t.Fatal("cross-run cursor accepted")
	}
	if _, err := provenance.ReadTextContentPage(s.DB, "two", a.Entries[0].Content.Ref, 0, 100); err == nil {
		t.Fatal("cross-run body lookup accepted")
	}
}

func TestContextRedactsBeforeIndexingAndHashing(t *testing.T) {
	s := testService(t)
	secret := "sk-" + strings.Repeat("a", 40)
	body := "API key: " + secret
	_, err := s.Save(context.Background(), "run", testSource(), []Record{{Key: "one", Kind: "tool_result", ToolName: secret, Body: &body}}, Coverage{Status: OK})
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Entries(context.Background(), PageOptions{RunID: "run"})
	if err != nil {
		t.Fatal(err)
	}
	entry := p.Entries[0]
	page, err := provenance.ReadTextContentPage(s.DB, "run", entry.Content.Ref, 0, 100)
	if err != nil || strings.Contains(page.Content, secret) || !page.Redacted {
		t.Fatalf("redaction failed: %v", err)
	}
	var tool string
	if err := s.DB.QueryRow(`SELECT tool_name FROM agent_context_entries`).Scan(&tool); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(tool, secret) || strings.Contains(entry.ToolName, secret) {
		t.Fatal("secret in context index")
	}
}
