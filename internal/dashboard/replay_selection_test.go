package dashboard

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func selectionDecisions(p *replaySelectionPlan) map[string]replayRecordDecision {
	result := map[string]replayRecordDecision{}
	for _, r := range p.Records {
		result[r.ID] = r
	}
	return result
}

func TestReplaySelectionSessionMembership(t *testing.T) {
	paths, db, objects := artifactStore(t)
	svc := agentcontext.Service{DB: db, Paths: paths}
	addSessionGraphFixture(t, svc)
	const run = "ui-session-graph"
	// Equal paths and PIDs are deliberately shared by unrelated sessions.
	inside := putArtifact(t, objects, run, "workspace_file/shared.txt", map[string]any{"content": "worker-only"})
	outside := putArtifact(t, objects, run, "workspace_file/shared.txt", map[string]any{"content": "other-version"})
	if _, err := db.Exec(`INSERT INTO graph_edges(id,run_id,from_id,to_id,edge_type,created_at)
		VALUES ('selected-file',?,'runtime_event/fixture-codex-worker',?,'runtime_event_file','2026-10-18T00:00:00Z')`, run, inside.Hash); err != nil {
		t.Fatal(err)
	}
	snapshot, err := (Server{DB: db}).freezeReplaySource(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	frozen := Server{DB: snapshot.DB}
	p, err := frozen.resolveReplaySelection(context.Background(), ReplaySelection{RunID: run, Scope: "session", Harness: "codex", SessionID: "worker"})
	if err != nil {
		t.Fatal(err)
	}
	var entries, tools, events, files int
	for _, r := range p.Records {
		if !r.Included {
			continue
		}
		switch r.Category {
		case "tools":
			if strings.HasPrefix(r.ID, "2/") {
				tools++
			} else {
				entries++
			}
		case "messages":
			entries++
		case "runtime":
			events++
			if r.ID != "3/fixture-codex-worker" {
				t.Fatalf("wrong event: %+v", r)
			}
		case "files":
			files++
			if r.Node != inside.Hash {
				t.Fatalf("wrong file version: %+v", r)
			}
		}
		if e, ok := p.Entries[strings.TrimPrefix(r.ID, "entry/")]; ok && (e.Source.Harness != "codex" || e.Source.SessionID != "worker") {
			t.Fatalf("mixed native session identity: %+v", e.Source)
		}
	}
	if entries != 6 || tools != 1 || events != 1 || files != 1 {
		t.Fatalf("membership: entries=%d tools=%d events=%d files=%d", entries, tools, events, files)
	}
	for _, id := range []string{"runtime_event/fixture-unassigned", "runtime_event/fixture-claude-root", outside.Hash} {
		if p.DeniedNodes[id] != "outside_scope" {
			t.Fatalf("outside reader not denied: %s", id)
		}
	}
	quiet, err := frozen.resolveReplaySelection(context.Background(), ReplaySelection{RunID: run, Scope: "session", Harness: "codex", SessionID: "quiet"})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range quiet.Records {
		if r.Included && r.Category != "messages" {
			t.Fatalf("empty graph expanded to run: %+v", r)
		}
	}
	whole, err := frozen.resolveReplaySelection(context.Background(), ReplaySelection{RunID: run, Scope: "whole_run"})
	if err != nil {
		t.Fatal(err)
	}
	if !selectionDecisions(whole)["3/fixture-unassigned"].Included {
		t.Fatal("whole run lost unassigned evidence")
	}
	for _, r := range whole.Records {
		if !r.Included {
			t.Fatalf("whole-run record excluded: %+v", r)
		}
	}
	if len(whole.DeniedNodes) != 0 || len(whole.WithheldContent) != 0 {
		t.Fatal("whole-run readers changed")
	}
}

func TestReplaySelectionExcludesInvocationAliasesNotRuntimeEffects(t *testing.T) {
	paths, db, objects := artifactStore(t)
	svc := agentcontext.Service{DB: db, Paths: paths}
	addSessionGraphFixture(t, svc)
	const run = "ui-session-graph"
	scope, err := svc.SessionGraphScope(context.Background(), run, "codex", "worker")
	if err != nil {
		t.Fatal(err)
	}
	tool := scope.ToolIDs[0]
	alias, err := objects.PutExternalObject(provenance.ExternalObjectInput{Type: "tool_call", RunID: run, SourceID: tool, Payload: map[string]any{"command": "cat shared.txt"}})
	if err != nil {
		t.Fatal(err)
	}
	eventAlias, err := objects.PutExternalObject(provenance.ExternalObjectInput{Type: "event", RunID: run, SourceID: "fixture-codex-worker", Payload: map[string]any{"path": "/fixture/shared.txt"}})
	if err != nil {
		t.Fatal(err)
	}
	server := Server{DB: db}
	base, err := server.resolveReplaySelection(context.Background(), ReplaySelection{RunID: run, Scope: "whole_run"})
	if err != nil {
		t.Fatal(err)
	}
	var call string
	for _, r := range base.Records {
		e := base.Entries[strings.TrimPrefix(r.ID, "entry/")]
		if e.Source.Harness == "codex" && e.Source.SessionID == "worker" && e.Kind == "tool_call" {
			call = r.ID
			break
		}
	}
	if call == "" {
		t.Fatal("missing fixture call")
	}
	for _, exclude := range []string{call, "2/" + tool} {
		t.Run(exclude, func(t *testing.T) {
			p, err := server.resolveReplaySelection(context.Background(), ReplaySelection{RunID: run, Scope: "whole_run", ExcludeRecords: []string{exclude}})
			if err != nil {
				t.Fatal(err)
			}
			var omitted int
			for _, r := range p.Records {
				if !r.Included {
					omitted++
					if r.Category != "tools" {
						t.Fatalf("exclusion spread into unrelated evidence: %+v", r)
					}
				}
			}
			// Two channels each store the call/result; both project one tool.
			if omitted != 5 {
				t.Fatalf("invocation aliases: got %d, want 5", omitted)
			}
			if p.DeniedNodes[tool] == "" || p.DeniedNodes[alias.Hash] == "" {
				t.Fatal("tool/CAS reader bypass")
			}
			if p.DeniedNodes[eventAlias.Hash] != "" || !selectionDecisions(p)["3/fixture-codex-worker"].Included {
				t.Fatal("tool exclusion silently removed independent runtime effect")
			}
		})
	}
	p, err := server.resolveReplaySelection(context.Background(), ReplaySelection{RunID: run, Scope: "whole_run", ExcludeRecords: []string{"3/fixture-codex-worker"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.DeniedNodes[eventAlias.Hash] == "" || p.DeniedNodes["runtime_event/fixture-codex-worker"] == "" {
		t.Fatal("event envelope bypass")
	}
	if !selectionDecisions(p)["2/"+tool].Included {
		t.Fatal("event exclusion removed its parent invocation")
	}
}

func TestReplaySelectionRevisionsRawSiblingsAndDuplicateContent(t *testing.T) {
	paths, db, _ := artifactStore(t)
	svc := agentcontext.Service{DB: db, Paths: paths}
	ctx := context.Background()
	src := agentcontext.Source{Harness: "codex", SessionID: "one", Channel: "transcript", ParserVersion: "fixture/v1", Binding: "explicit"}
	ptr := func(value string) *string { return &value }
	save := func(source agentcontext.Source, records ...agentcontext.Record) {
		t.Helper()
		if _, err := svc.Save(ctx, "revisions", source, records, agentcontext.Coverage{Status: agentcontext.OK}); err != nil {
			t.Fatal(err)
		}
	}
	save(src,
		agentcontext.Record{Key: "message", Sequence: 1, Kind: "message", Role: "user", Body: ptr("old secret"), RawBody: ptr(`{"secret":"old secret","other":"allowed"}`)},
		agentcontext.Record{Key: "sibling", Sequence: 1, SourceOrdinal: 1, Kind: "message", Role: "assistant", Body: ptr("allowed"), RawBody: ptr(`{"secret":"old secret","other":"allowed"}`)},
		agentcontext.Record{Key: "separate", Sequence: 2, Kind: "message", Body: ptr("duplicate sensitive text"), RawBody: ptr(`{"text":"independent raw"}`)},
		agentcontext.Record{Key: "message", Sequence: 3, Kind: "configuration", Body: ptr(`{"mode":"normal"}`)},
	)
	save(src, agentcontext.Record{Key: "message", Sequence: 1, Kind: "message", Role: "user", Body: ptr("duplicate sensitive text"), RawBody: ptr(`{"secret":"duplicate sensitive text","other":"allowed"}`)})
	other := src
	other.SessionID = "two"
	save(other, agentcontext.Record{Key: "message", Sequence: 1, Kind: "message", Role: "user", Body: ptr("other-session")})
	base, err := (Server{DB: db}).resolveReplaySelection(ctx, ReplaySelection{RunID: "revisions", Scope: "whole_run"})
	if err != nil {
		t.Fatal(err)
	}
	var target string
	for _, r := range base.Records {
		e := base.Entries[strings.TrimPrefix(r.ID, "entry/")]
		if e.Source.SessionID == "one" && e.SourceKey == "message" && e.Kind == "message" && r.Indexed {
			target = r.ID
		}
	}
	p, err := (Server{DB: db}).resolveReplaySelection(ctx, ReplaySelection{RunID: "revisions", Scope: "whole_run", ExcludeRecords: []string{target}})
	if err != nil {
		t.Fatal(err)
	}
	decisions := selectionDecisions(p)
	omitted := 0
	for _, r := range p.Records {
		e := p.Entries[strings.TrimPrefix(r.ID, "entry/")]
		if e.Source.SessionID == "one" && e.SourceKey == "message" && e.Kind == "message" {
			if r.Included || p.DeniedNodes[e.ObjectHash] == "" {
				t.Fatalf("revision retained: %+v", r)
			}
			omitted++
		} else if !r.Included {
			t.Fatalf("unrelated entry removed: %+v", r)
		}
		if e.Source.SessionID == "one" && e.Sequence == 1 && p.WithheldContent[e.RawContent.Ref] == "" {
			t.Fatal("shared raw source line leaked")
		}
		if e.SourceKey == "separate" && p.WithheldContent[e.RawContent.Ref] != "" {
			t.Fatal("independent raw line blocked")
		}
	}
	if omitted != 2 || p.WarningCount != 1 || len(p.Warnings) != 1 {
		t.Fatalf("revision/duplicate accounting: omitted=%d warnings=%+v", omitted, p.Warnings)
	}
	w := p.Warnings[0]
	if w.Code != "same_content_in_retained_record" || w.IncludedCount != 1 || w.ExcludedCount != 1 || !decisions[w.Included[0]].Included {
		t.Fatalf("duplicate review warning: %+v", w)
	}
	summary := p.summary()
	if summary.WarningCount != 1 || len(summary.Warnings) != 1 || summary.Excluded != omitted || summary.Included+summary.Excluded != len(p.Records) {
		t.Fatalf("preview summary differs from resolved decisions: %+v", summary)
	}
	if len(p.WithheldContent) != 4 {
		t.Fatalf("old/new raw versions and their body readers must be withheld: %+v", p.WithheldContent)
	}
}

func TestReplaySelectionCategoriesValidationAndDeterminism(t *testing.T) {
	paths, db, _ := artifactStore(t)
	addSessionGraphFixture(t, agentcontext.Service{DB: db, Paths: paths})
	server := Server{DB: db}
	ctx := context.Background()
	const run = "ui-session-graph"
	input := ReplaySelection{RunID: run, Scope: "whole_run", ExcludeCategories: []string{"runtime", "tools"}, ExcludeRecords: []string{"3/fixture-unassigned"}}
	p, err := server.resolveReplaySelection(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range p.Records {
		if r.Included == slices.Contains(input.ExcludeCategories, r.Category) {
			t.Fatalf("category decision: %+v", r)
		}
	}
	input.ExcludeCategories = []string{"tools", "runtime", "tools"}
	input.ExcludeRecords = []string{"3/fixture-unassigned", "3/fixture-unassigned"}
	for i := 0; i < 5; i++ {
		next, err := server.resolveReplaySelection(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		if next.SHA256 != p.SHA256 || !reflect.DeepEqual(next.Records, p.Records) {
			t.Fatal("selection ordering changed its identity")
		}
	}
	invalid := []ReplaySelection{
		{RunID: run}, {RunID: run, Scope: "bogus"}, {RunID: run, Scope: "session", SessionID: "root"},
		{RunID: run, Scope: "whole_run", Harness: "codex", SessionID: "root"},
		{RunID: run, Scope: "whole_run", ExcludeCategories: []string{"secrets"}},
		{RunID: run, Scope: "whole_run", ExcludeRecords: []string{"3/missing"}},
		{RunID: run, Scope: "whole_run", ExcludeRecords: []string{strings.Repeat("x", 1025)}},
		{RunID: run, Scope: "whole_run", ExcludeRecords: make([]string, 4097)},
		{RunID: run, Scope: "session", Harness: "codex", SessionID: "worker", ExcludeRecords: []string{"3/fixture-unassigned"}},
	}
	for i, input := range invalid {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if _, err := server.resolveReplaySelection(ctx, input); !errors.Is(err, agentcontext.ErrInvalidArgument) {
				t.Fatalf("invalid selection: %v", err)
			}
		})
	}
	for _, input := range []ReplaySelection{{RunID: "absent", Scope: "whole_run"}, {RunID: run, Scope: "session", Harness: "claude", SessionID: "worker"}} {
		if _, err := server.resolveReplaySelection(ctx, input); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("unknown selection: %v", err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := server.resolveReplaySelection(canceled, input); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
}

func TestReplaySelectionSnapshotFreezeAndCleanup(t *testing.T) {
	_, db, _ := artifactStore(t)
	insert := func(id string) {
		t.Helper()
		if _, err := db.Exec(`INSERT INTO events(id,run_id,source,event_type,payload,created_at) VALUES (?,'freeze','fixture','execve','{}','2026-10-18T00:00:00Z')`, id); err != nil {
			t.Fatal(err)
		}
	}
	insert("first")
	snapshot, err := (Server{DB: db}).freezeReplaySource(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	input := ReplaySelection{RunID: "freeze", Scope: "whole_run"}
	before, err := (Server{DB: snapshot.DB}).resolveReplaySelection(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	insert("later")
	after, err := (Server{DB: snapshot.DB}).resolveReplaySelection(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if before.SHA256 != after.SHA256 || len(after.Records) != 1 {
		t.Fatal("live writes changed frozen selection")
	}
	if _, err := snapshot.DB.Exec(`DELETE FROM events`); err == nil {
		t.Fatal("source snapshot is writable")
	}
	root := snapshot.root
	snapshot.Close()
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("private source remains: %v", err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("source database changed: %d %v", count, err)
	}
	if _, err := (Server{DB: snapshot.DB}).resolveReplaySelection(context.Background(), input); err == nil || errors.Is(err, sql.ErrNoRows) {
		t.Fatal("database failure was reported as empty selection")
	}
}

func TestReplaySelectionPriorHistoryDoesNotOwnCurrentInvocation(t *testing.T) {
	paths, db, _ := artifactStore(t)
	svc := agentcontext.Service{DB: db, Paths: paths}
	ctx := context.Background()
	body := "old call, retained as transcript history"
	_, err := svc.Save(ctx, "prior", agentcontext.Source{Harness: "codex", SessionID: "resumed", Channel: "transcript", ParserVersion: "fixture/v1", Binding: "explicit"},
		[]agentcontext.Record{{Key: "old", Kind: "tool_call", ToolCallID: "reused", Sequence: 1, Body: &body, ExecutionScope: agentcontext.PriorContext}},
		agentcontext.Coverage{Status: agentcontext.OK, PriorContext: &agentcontext.PriorRange{FirstLine: 1, LastLine: 1}})
	if err != nil {
		t.Fatal(err)
	}
	page, err := svc.Entries(ctx, agentcontext.PageOptions{RunID: "prior"})
	if err != nil || len(page.Entries) != 1 {
		t.Fatalf("prior entry: %+v %v", page, err)
	}
	entry := page.Entries[0]
	if _, err = db.Exec(`INSERT INTO tool_calls(id,run_id,status,command,created_at) VALUES ('current','prior','completed','current command','2026-10-18T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	// Even an old stored edge must not upgrade prior history to current execution.
	if _, err = db.Exec(`INSERT INTO graph_edges(id,run_id,from_id,to_id,edge_type,created_at) VALUES ('stale','prior',?,'current','context_tool_call','2026-10-18T00:00:00Z')`, entry.ObjectHash); err != nil {
		t.Fatal(err)
	}
	p, err := (Server{DB: db}).resolveReplaySelection(ctx, ReplaySelection{RunID: "prior", Scope: "session", Harness: "codex", SessionID: "resumed"})
	if err != nil {
		t.Fatal(err)
	}
	if !selectionDecisions(p)["entry/"+entry.ID].Included || selectionDecisions(p)["2/current"].Included {
		t.Fatal("prior history widened session execution")
	}
	p, err = (Server{DB: db}).resolveReplaySelection(ctx, ReplaySelection{RunID: "prior", Scope: "whole_run", ExcludeRecords: []string{"entry/" + entry.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if !selectionDecisions(p)["2/current"].Included {
		t.Fatal("prior-history exclusion affected current invocation")
	}
}

func TestReplaySelectionWarningLimitAndFailedFreezeCleanup(t *testing.T) {
	paths, db, _ := artifactStore(t)
	svc := agentcontext.Service{DB: db, Paths: paths}
	ctx := context.Background()
	var records []agentcontext.Record
	for i := 0; i < 101; i++ {
		body := fmt.Sprintf("independent same-content pair %03d", i)
		for _, kind := range []string{"message", "configuration"} {
			records = append(records, agentcontext.Record{Key: fmt.Sprintf("%s-%d", kind, i), Sequence: int64(len(records) + 1), Kind: kind, Body: &body})
		}
	}
	_, err := svc.Save(ctx, "warnings", agentcontext.Source{Harness: "codex", SessionID: "many", Channel: "transcript", ParserVersion: "fixture/v1", Binding: "explicit"}, records, agentcontext.Coverage{Status: agentcontext.OK})
	if err != nil {
		t.Fatal(err)
	}
	p, err := (Server{DB: db}).resolveReplaySelection(ctx, ReplaySelection{RunID: "warnings", Scope: "whole_run", ExcludeCategories: []string{"messages"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.WarningCount != 101 || len(p.Warnings) != 100 {
		t.Fatalf("warning bound: %d/%d", len(p.Warnings), p.WarningCount)
	}
	if summary := p.summary(); summary.WarningCount != 101 || len(summary.Warnings) != 100 || summary.Included != 101 || summary.Excluded != 101 {
		t.Fatalf("preview warning bound: %+v", summary)
	}
	for _, warning := range p.Warnings {
		if len(warning.Included) != 1 || len(warning.Excluded) != 1 {
			t.Fatalf("warning members: %+v", warning)
		}
	}
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := (Server{DB: db}).freezeReplaySource(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled snapshot: %v", err)
	}
	left, err := os.ReadDir(tmp)
	if err != nil || len(left) != 0 {
		t.Fatalf("failed snapshot leaked private files: %+v %v", left, err)
	}
}

func BenchmarkReplaySelectionRuntime100K(b *testing.B) {
	paths, err := store.Init(filepath.Join(b.TempDir(), "store"))
	if err != nil {
		b.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<100000)
		INSERT INTO events(id,run_id,source,event_type,payload,created_at)
		SELECT printf('event-%06d',i),'large','fixture','execve','{}','2026-10-18T00:00:00Z' FROM n`)
	if err != nil {
		b.Fatal(err)
	}
	server := Server{DB: db}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p, err := server.resolveReplaySelection(context.Background(), ReplaySelection{RunID: "large", Scope: "whole_run"})
		if err != nil || len(p.Records) != 100000 {
			b.Fatalf("large selection: %v", err)
		}
	}
}
