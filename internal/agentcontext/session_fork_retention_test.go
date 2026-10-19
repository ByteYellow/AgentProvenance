package agentcontext

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func saveForkTranscript(t *testing.T, s Service, run, path, transcript string) SaveResult {
	t.Helper()
	p, err := Parse(context.Background(), strings.NewReader(transcript), ParseOptions{Harness: "codex", Path: path, Binding: "explicit"})
	if err != nil || p.Coverage.Status != OK {
		t.Fatalf("parse: %+v %v", p.Coverage, err)
	}
	r, err := s.Save(context.Background(), run, p.Source, p.Records, p.Coverage)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSessionForkMetadataExtraction(t *testing.T) {
	for _, tc := range []struct {
		name, harness, kind, body string
		want                      *SessionMetadata
	}{
		{"fork", "codex", "configuration", `{"id":"branch","forked_from_id":"root"}`, &SessionMetadata{ForkedFromID: "root"}},
		{"session-alias", "codex", "configuration", `{"session_id":"branch","forked_from_id":"root"}`, &SessionMetadata{ForkedFromID: "root"}},
		{"no-fork", "codex", "configuration", `{"id":"branch"}`, &SessionMetadata{}},
		{"empty-fork", "codex", "configuration", `{"id":"branch","forked_from_id":""}`, &SessionMetadata{}},
		{"wrong-identity", "codex", "configuration", `{"id":"other","forked_from_id":"root"}`, nil},
		{"wrong-type", "codex", "configuration", `{"id":"branch","forked_from_id":123}`, nil},
		{"whitespace", "codex", "configuration", `{"id":"branch","forked_from_id":" root "}`, nil},
		{"long-id", "codex", "configuration", `{"id":"branch","forked_from_id":"` + strings.Repeat("x", 513) + `"}`, nil},
		{"other-harness", "claude", "configuration", `{"id":"branch","forked_from_id":"root"}`, nil},
		{"prose", "codex", "message", `{"id":"branch","forked_from_id":"root"}`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := codexSessionMetadata(Source{Harness: tc.harness, SessionID: "branch"}, Record{Kind: tc.kind, Status: "session_metadata", Body: &tc.body})
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("metadata=%+v want=%+v", got, tc.want)
			}
		})
	}
}

func rewriteForkEntry(t *testing.T, s Service, e Entry, change func(*Entry)) {
	t.Helper()
	oldID := e.ID
	change(&e)
	payload, err := entryPayload(e)
	if err != nil {
		t.Fatal(err)
	}
	e.ID = "context-" + digest(payload)
	payload["id"] = e.ID
	parents := []string{}
	for _, ref := range e.ContentReferences() {
		if ref.Ref != "" {
			parents = append(parents, ref.Ref)
		}
	}
	object, err := (provenance.ObjectStore{DB: s.DB, Paths: s.Paths}).PutExternalObject(provenance.ExternalObjectInput{
		RunID: e.RunID, Type: "agent_context", SourceID: e.ID, Payload: payload, Parents: parents,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE agent_context_entries SET id=?,object_hash=?,content_ref=? WHERE run_id=? AND id=?`, e.ID, object.Hash, e.Content.Ref, e.RunID, oldID); err != nil {
		t.Fatal(err)
	}
}

func TestSessionForkHistoricalFallbackAndStructuredPrecedence(t *testing.T) {
	for _, mode := range []string{"historical-stored", "historical-omitted", "structured-preferred", "large-configuration", "no-fork"} {
		t.Run(mode, func(t *testing.T) {
			s := testService(t)
			if mode == "historical-omitted" || mode == "no-fork" {
				s.CapturePolicy = capturePreset(t, "basic", nil)
			}
			body := `{"id":"branch","forked_from_id":"root"}`
			if mode == "large-configuration" {
				body = `{"id":"branch","forked_from_id":"root","instructions":"` + strings.Repeat("x", 70<<10) + `"}`
			} else if mode == "no-fork" {
				body = `{"id":"branch"}`
			}
			saveForkTranscript(t, s, "run", "/branch.jsonl", `{"type":"session_meta","payload":`+body+`}`)
			entries, err := s.Entries(context.Background(), PageOptions{RunID: "run"})
			if err != nil || len(entries.Entries) != 1 {
				t.Fatalf("entries: %+v %v", entries, err)
			}
			if mode == "historical-stored" || mode == "historical-omitted" {
				rewriteForkEntry(t, s, entries.Entries[0], func(e *Entry) { e.SessionMetadata = nil })
			} else if mode == "structured-preferred" {
				stored, err := (provenance.ObjectStore{DB: s.DB, Paths: s.Paths}).PutTextContent(provenance.TextContentInput{RunID: "run", SourceID: "different-body", Text: `{"id":"branch","forked_from_id":"wrong-parent"}`, MediaType: "application/json"})
				if err != nil {
					t.Fatal(err)
				}
				rewriteForkEntry(t, s, entries.Entries[0], func(e *Entry) { e.Content = contentReference(stored) })
			}
			page, err := s.SessionRelations(context.Background(), SessionRelationOptions{RunID: "run", Harness: "codex", SessionID: "branch"})
			if err != nil || page.Limited {
				t.Fatalf("relations: %+v %v", page, err)
			}
			if mode == "historical-omitted" {
				if len(page.Relations) != 0 || !slices.Equal(page.Issues, []string{"session_relation_metadata_unavailable"}) {
					t.Fatalf("old omitted metadata must remain unavailable: %+v", page)
				}
			} else if mode == "no-fork" {
				if len(page.Relations) != 0 || len(page.Issues) != 0 {
					t.Fatalf("observed absence was confused with unavailable metadata: %+v", page)
				}
			} else if len(page.Relations) != 1 || page.Relations[0].Kind != "fork" || page.Relations[0].From.SessionID != "root" || page.Relations[0].From.Available || len(page.Issues) != 0 {
				t.Fatalf("fork metadata: %+v", page)
			}
		})
	}
}

func TestSessionForkCrossRunConflictingClaimsAndVisibility(t *testing.T) {
	s := testService(t)
	s.CapturePolicy = capturePreset(t, "basic", nil)
	for _, run := range []string{"parent-a", "parent-b"} {
		relationSource(t, s, run, "codex", "root", "")
	}
	relationSource(t, s, "foreign", "claude", "root", "")
	for _, origin := range []string{"root", "other"} {
		input := `{"type":"session_meta","payload":{"id":"branch","forked_from_id":"` + origin + `"}}`
		// Paths do not distinguish native sources. Separate runs preserve both
		// claims instead of treating the second as a revision of the same row.
		saveForkTranscript(t, s, "child-"+origin, "/"+origin+".jsonl", input)
		if duplicate := saveForkTranscript(t, s, "child-"+origin, "/"+origin+".jsonl", input); duplicate.Stored != 0 || duplicate.Duplicates != 1 {
			t.Fatalf("duplicate changed the evidence: %+v", duplicate)
		}
	}
	for _, visible := range [][]string{nil, {"child-root", "child-other"}} {
		p, err := s.SessionRelations(context.Background(), SessionRelationOptions{RunID: "child-root", Harness: "codex", SessionID: "branch", VisibleRuns: visible})
		if err != nil || len(p.Relations) != 3 || p.Limited {
			t.Fatalf("conflicting claims lost or multiplied: %+v %v", p, err)
		}
		origins := map[string]bool{}
		for _, r := range p.Relations {
			if r.Kind == "same_session" {
				if r.From.RunID != "child-root" || r.To.RunID != "child-other" || r.From.Harness != "codex" || r.To.Harness != "codex" || len(r.Evidence) != 2 {
					t.Fatalf("duplicate session occurrence: %+v", r)
				}
				continue
			}
			origins[r.From.SessionID] = true
			if r.Kind != "fork" || r.From.Harness != "codex" || r.To.Harness != "codex" || r.To.RunID != "child-"+r.From.SessionID || len(r.Evidence) != 1 || r.Evidence[0].RunID != r.To.RunID || r.From.RunID != "" {
				t.Fatalf("fork crossed identity/evidence boundaries: %+v", r)
			}
			if visible != nil || r.From.SessionID == "other" {
				if r.From.Available || len(r.From.RunIDs) != 0 {
					t.Fatalf("uncollected/private endpoint leaked: %+v", r)
				}
			} else if !r.From.Available || !slices.Equal(r.From.RunIDs, []string{"parent-a", "parent-b"}) {
				t.Fatalf("ambiguous parent occurrences: %+v", r)
			}
		}
		if !origins["root"] || !origins["other"] {
			t.Fatalf("a conflicting origin was selected arbitrarily: %+v", p)
		}
	}
}

func TestSessionForkIsDistinctFromSpawnAndPriorContext(t *testing.T) {
	for _, preset := range []string{"basic", "detailed"} {
		t.Run(preset, func(t *testing.T) {
			s := testService(t)
			s.CapturePolicy = capturePreset(t, preset, nil)
			saveForkTranscript(t, s, "run", "/root.jsonl", `{"type":"session_meta","payload":{"id":"root"}}
{"type":"response_item","payload":{"type":"function_call","call_id":"spawn","name":"spawn_agent","arguments":"{}"}}
{"type":"response_item","payload":{"type":"function_call_output","call_id":"spawn","output":"{\"agent_id\":\"worker\"}"}}`)
			saveForkTranscript(t, s, "run", "/worker.jsonl", `{"type":"session_meta","payload":{"id":"worker","source":{"subagent":{"thread_spawn":{"parent_thread_id":"root"}}}}}`)
			saveForkTranscript(t, s, "run", "/branch.jsonl", `{"type":"session_meta","payload":{"id":"branch","forked_from_id":"root"}}`)
			prior, err := Parse(context.Background(), strings.NewReader(`{"type":"session_meta","payload":{"id":"prior","forked_from_id":"root"}}`), ParseOptions{Harness: "codex", Binding: "explicit", AfterLine: 1})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Save(context.Background(), "run", prior.Source, prior.Records, prior.Coverage); err != nil {
				t.Fatal(err)
			}
			page, err := s.SessionRelations(context.Background(), SessionRelationOptions{RunID: "run", Harness: "codex", SessionID: "root"})
			if err != nil || len(page.Relations) != 3 || len(page.Issues) != 0 {
				t.Fatalf("native lineage: %+v %v", page, err)
			}
			kinds := map[string]string{}
			for _, r := range page.Relations {
				kinds[r.Kind] = r.To.SessionID
			}
			if !reflect.DeepEqual(kinds, map[string]string{"parent": "worker", "delegation": "worker", "fork": "branch"}) {
				t.Fatalf("fork/spawn/prior-context conflated: %+v", page)
			}
		})
	}
}

func TestSessionForkCaptureRetention(t *testing.T) {
	var detailed SessionRelation
	for _, preset := range []string{"detailed", "basic"} {
		t.Run(preset, func(t *testing.T) {
			s := testService(t)
			s.CapturePolicy = capturePreset(t, preset, nil)
			relationSource(t, s, "parent-run", "codex", "root", "")
			transcript := `{"timestamp":"2026-10-19T00:00:00Z","type":"session_meta","payload":{"id":"branch","forked_from_id":"root","cwd":"/workspace","instructions":"private configuration"}}`
			saved := saveForkTranscript(t, s, "child-run", "/branch.jsonl", transcript)
			if saved.Coverage.Source.ParentSessionID != "" || saved.Coverage.Source.AgentID != "" {
				t.Fatal("fork was conflated with subagent spawning")
			}
			p, err := s.SessionRelations(context.Background(), SessionRelationOptions{RunID: "child-run", Harness: "codex", SessionID: "branch"})
			if err != nil || len(p.Relations) != 1 || p.Limited || p.HasMore {
				t.Fatalf("expected exactly one retained fork: %+v %v", p, err)
			}
			r := p.Relations[0]
			wantFrom := SessionRef{RunID: "parent-run", Harness: "codex", SessionID: "root", Available: true}
			wantTo := SessionRef{RunID: "child-run", Harness: "codex", SessionID: "branch", Available: true}
			if r.Kind != "fork" || !reflect.DeepEqual(r.From, wantFrom) || !reflect.DeepEqual(r.To, wantTo) || len(r.Evidence) != 1 {
				t.Fatalf("fork endpoints/type/evidence: %+v", r)
			}
			ev := r.Evidence[0]
			if ev.RunID != "child-run" || ev.SourceID != saved.Coverage.Source.ID || ev.EntryID == "" || ev.ObjectHash == "" || ev.Basis != "native_fork_metadata" || ev.RecordedAt != "2026-10-19T00:00:00Z" {
				t.Fatalf("fork evidence reference: %+v", ev)
			}
			var entry Entry
			if err := provenance.ReadObjectPayload(s.DB, ev.RunID, ev.ObjectHash, &entry); err != nil {
				t.Fatal(err)
			}
			if entry.ID != ev.EntryID || entry.Source.ID != ev.SourceID || entry.Source.SessionID != "branch" || entry.Source.Harness != "codex" || entry.Sequence != 1 || entry.Status != "session_metadata" {
				t.Fatalf("evidence does not resolve to native metadata: %+v", entry)
			}
			if preset == "basic" {
				if entry.Content.State != "omitted" || entry.Content.Reason != "capture_policy" || entry.Content.Ref != "" || entry.RawContent.State != "omitted" || entry.RawContent.Ref != "" {
					t.Fatalf("basic retained configuration body: %+v", entry)
				}
				if r.ID != detailed.ID || !reflect.DeepEqual(r.From, detailed.From) || !reflect.DeepEqual(r.To, detailed.To) || r.Kind != detailed.Kind || ev.SourceID != detailed.Evidence[0].SourceID || ev.Basis != detailed.Evidence[0].Basis || ev.RecordedAt != detailed.Evidence[0].RecordedAt {
					t.Fatalf("capture presets changed the relationship: basic=%+v detailed=%+v", r, detailed)
				}
			} else {
				if entry.Content.State != "stored" || entry.RawContent.State != "stored" {
					t.Fatalf("detailed did not retain bodies: %+v", entry)
				}
				detailed = r
			}
		})
	}
}
