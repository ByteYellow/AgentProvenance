package agentcontext

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func relationSource(t *testing.T, s Service, run, harness, session, parent string, records ...Record) {
	t.Helper()
	_, err := s.Save(context.Background(), run, Source{Harness: harness, SessionID: session, ParentSessionID: parent,
		Channel: "transcript", ParserVersion: "relation-fixture/v1", Binding: "explicit", Workdir: "/same-directory"}, records, Coverage{Status: OK})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSessionRelationsKeepRunAndNamespaceBoundaries(t *testing.T) {
	s := testService(t)
	relationSource(t, s, "a", "codex", "root", "")
	relationSource(t, s, "b", "codex", "root", "")
	relationSource(t, s, "b", "codex", "child", "root")
	relationSource(t, s, "c", "codex", "unrelated", "")
	relationSource(t, s, "c", "claude", "root", "")
	relationSource(t, s, "d", "codex", "orphan", "missing")
	get := func(run, session string, visible []string) SessionRelationsPage {
		t.Helper()
		p, err := s.SessionRelations(context.Background(), SessionRelationOptions{RunID: run, Harness: "codex", SessionID: session, VisibleRuns: visible})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := get("a", "root", nil)
	if len(p.Relations) != 2 || p.Limited {
		t.Fatalf("relations: %+v", p)
	}
	kinds := map[string]SessionRelation{}
	for _, r := range p.Relations {
		kinds[r.Kind] = r
		if r.From.RunID == "c" || r.To.RunID == "c" || len(r.Evidence) == 0 {
			t.Fatalf("unrelated or ungrounded relationship: %+v", r)
		}
	}
	if kinds["same_session"].From.RunID != "a" || kinds["same_session"].To.RunID != "b" || len(kinds["same_session"].Evidence) != 2 {
		t.Fatalf("same identity evidence: %+v", kinds)
	}
	if kinds["parent"].From.RunID != "b" || kinds["parent"].To.SessionID != "child" {
		t.Fatal("parent assertion was incorrectly reassigned to another run")
	}
	if got := get("a", "root", []string{"a"}); len(got.Relations) != 0 {
		t.Fatal("export leaked privately collected occurrences")
	}
	orphan := get("d", "orphan", nil)
	if len(orphan.Relations) != 1 || orphan.Relations[0].From.Available || orphan.Relations[0].From.RunID != "" || orphan.Relations[0].From.SessionID != "missing" {
		t.Fatalf("missing reference: %+v", orphan)
	}
	// A parent imported later becomes navigable without rewriting the child.
	relationSource(t, s, "e", "codex", "missing", "")
	orphan = get("d", "orphan", nil)
	if orphan.Relations[0].From.RunID != "e" || !orphan.Relations[0].From.Available {
		t.Fatalf("late parent: %+v", orphan)
	}
	if got := get("d", "orphan", []string{"d"}); got.Relations[0].From.Available || got.Relations[0].From.RunID != "" {
		t.Fatal("selected-run export widened discovery")
	}
}

func TestSessionRelationsReadNativeActionsAndExcludePriorContext(t *testing.T) {
	s := testService(t)
	spawn, message, fork := `{"session_id":"worker","parent_session_id":"root"}`, `{"id":"worker","message":"hello"}`, `{"id":"branch","forked_from_id":"root"}`
	relationSource(t, s, "a", "codex", "root", "",
		Record{Key: "child", Kind: "session", ToolName: "spawn_agent", Status: "started", Body: &spawn},
		Record{Key: "send", Kind: "tool_call", ToolName: "functions.send_input", Body: &message})
	relationSource(t, s, "b", "codex", "worker", "")
	relationSource(t, s, "b", "codex", "branch", "", Record{Key: "meta", Kind: "configuration", Status: "session_metadata", Body: &fork})
	// An ordinary message containing identical JSON is not a native action.
	relationSource(t, s, "a", "codex", "prose", "", Record{Key: "text", Kind: "message", Body: &message})
	prior := `{"id":"root","message":"past"}`
	_, err := s.Save(context.Background(), "b", Source{Harness: "codex", SessionID: "prior-only", ParserVersion: "test/v1", Binding: "explicit"},
		[]Record{{Key: "prior", Kind: "tool_call", Sequence: 1, ToolName: "send_input", Body: &prior, ExecutionScope: PriorContext}},
		Coverage{Status: OK, PriorContext: &PriorRange{FirstLine: 1, LastLine: 1}})
	if err != nil {
		t.Fatal(err)
	}
	opts := SessionRelationOptions{RunID: "a", Harness: "codex", SessionID: "root", Limit: 1}
	all := []SessionRelation{}
	firstCursor := ""
	for {
		p, err := s.SessionRelations(context.Background(), opts)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, p.Relations...)
		if !p.HasMore {
			break
		}
		if firstCursor == "" {
			firstCursor = p.NextCursor
		}
		opts.Cursor = p.NextCursor
	}
	kinds := []string{}
	for _, r := range all {
		kinds = append(kinds, r.Kind)
		if r.From.SessionID != "root" || r.To.RunID != "b" || !r.To.Available || r.Evidence[0].EntryID == "" {
			t.Fatalf("action: %+v", r)
		}
	}
	slices.Sort(kinds)
	if !slices.Equal(kinds, []string{"delegation", "fork", "message_request"}) {
		t.Fatalf("unexpected kinds %v", kinds)
	}
	opts.SessionID, opts.Cursor = "prose", firstCursor
	if _, err := s.SessionRelations(context.Background(), opts); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("cursor crossed identity: %v", err)
	}
	opts.SessionID = "root"
	relationSource(t, s, "later", "codex", "root", "")
	if _, err := s.SessionRelations(context.Background(), opts); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("changed evidence retained cursor: %v", err)
	}
}

func TestSessionRelationsDoNotMultiplyActionsAcrossRunOccurrences(t *testing.T) {
	s := testService(t)
	body := `{"id":"worker","message":"one request"}`
	relationSource(t, s, "sender-run", "codex", "sender", "", Record{Key: "send", Kind: "tool_call", ToolName: "send_input", Body: &body})
	relationSource(t, s, "worker-a", "codex", "worker", "")
	relationSource(t, s, "worker-b", "codex", "worker", "")
	p, err := s.SessionRelations(context.Background(), SessionRelationOptions{RunID: "sender-run", Harness: "codex", SessionID: "sender"})
	if err != nil || len(p.Relations) != 1 {
		t.Fatalf("one message must remain one relationship: %v %+v", err, p)
	}
	target := p.Relations[0].To
	if target.RunID != "" || !target.Available || !slices.Equal(target.RunIDs, []string{"worker-a", "worker-b"}) {
		t.Fatalf("native target occurrences: %+v", target)
	}
}

func TestSessionRelationsExposeConflictsCyclesAndErrors(t *testing.T) {
	s := testService(t)
	relationSource(t, s, "a", "codex", "one", "two")
	relationSource(t, s, "b", "codex", "two", "one")
	relationSource(t, s, "c", "codex", "one", "other")
	opts := SessionRelationOptions{RunID: "a", Harness: "codex", SessionID: "one"}
	p, err := s.SessionRelations(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	cycle, conflict := false, false
	for _, r := range p.Relations {
		cycle = cycle || slices.Contains(r.Issues, "parent_cycle")
		conflict = conflict || slices.Contains(r.Issues, "conflicting_parents")
	}
	if !cycle || !conflict {
		t.Fatalf("conflicts hidden: %+v", p)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.SessionRelations(ctx, opts); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	if _, err := s.DB.Exec(`UPDATE agent_context_reports SET session_id='other' WHERE run_id='a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionRelations(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "identity mismatch") {
		t.Fatalf("corrupt index accepted: %v", err)
	}
	if err := s.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionRelations(context.Background(), opts); err == nil {
		t.Fatal("database failure became empty relations")
	}
}

func TestSessionRelationsHTTP(t *testing.T) {
	s := testService(t)
	relationSource(t, s, "a", "codex", "root", "")
	relationSource(t, s, "b", "codex", "root", "")
	for _, tc := range []struct {
		query string
		code  int
	}{{"run=a&harness=codex&session=root", 200}, {"run=a&session=root", 400}, {"run=a&harness=codex&session=absent", 404}, {"run=a&harness=codex&session=root&limit=0", 400}} {
		w := httptest.NewRecorder()
		s.ReadHandler().ServeHTTP(w, httptest.NewRequest("GET", "/context/session-relations?"+tc.query, nil))
		if w.Code != tc.code {
			t.Fatalf("%s: %d %s", tc.query, w.Code, w.Body.String())
		}
		if w.Code == 200 {
			var p SessionRelationsPage
			if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil || len(p.Relations) != 1 {
				t.Fatalf("HTTP result: %v %+v", err, p)
			}
		}
	}
}
