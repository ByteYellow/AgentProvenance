package dashboard

import (
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/hooksbridge"
	"github.com/byteyellow/agentprovenance/internal/staticdata"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

const replayManyRun = "issue4-many-sessions"

func replayManySessions(t *testing.T) (Server, string) {
	t.Helper()
	paths, db, _ := artifactStore(t)
	svc := agentcontext.Service{DB: db, Paths: paths}
	ctx := context.Background()
	for i := 0; i < 260; i++ {
		src := agentcontext.Source{Harness: "codex", Channel: "transcript", SessionID: fmt.Sprintf("session-%03d", i), ParserVersion: "issue4-fixture/v1", Binding: "explicit"}
		body := "ISSUE4-BODY-" + src.SessionID
		if _, err := svc.Save(ctx, replayManyRun, src, []agentcontext.Record{{Key: "message", Sequence: 1, Kind: "message", Role: "assistant", Body: &body}}, agentcontext.Coverage{Status: agentcontext.OK}); err != nil {
			t.Fatal(err)
		}
	}
	var tail string
	if err := db.QueryRow(`SELECT session_id FROM agent_context_reports WHERE run_id=? ORDER BY source_id DESC LIMIT 1`, replayManyRun).Scan(&tail); err != nil {
		t.Fatal(err)
	}
	src := agentcontext.Source{Harness: "codex", Channel: "transcript", SessionID: tail, ParserVersion: "issue4-fixture/v1", Binding: "explicit"}
	body, command := "ISSUE4-TAIL-SEARCH-BODY report.py", `{"cmd":"cat report.py"}`
	secret := "ISSUE4-EXCLUDED-SECRET"
	fork := fmt.Sprintf(`{"id":%q,"forked_from_id":"session-000","instructions":"ISSUE4-TAIL-FORK-CONFIG"}`, tail)
	if _, err := svc.Save(ctx, replayManyRun, src, []agentcontext.Record{
		{Key: "message", Sequence: 1, Kind: "message", Role: "assistant", Body: &body},
		{Key: "call", Sequence: 2, Kind: "tool_call", ToolName: "exec_command", ToolCallID: "tail-call", Body: &command},
		{Key: "excluded", Sequence: 3, Kind: "message", Role: "assistant", Body: &secret},
		{Key: "metadata", Sequence: 4, Kind: "configuration", Status: "session_metadata", Body: &fork},
	}, agentcontext.Coverage{Status: agentcontext.OK}); err != nil {
		t.Fatal(err)
	}
	if _, err := hooksbridge.IngestContext(ctx, db, paths, replayManyRun); err != nil {
		t.Fatal(err)
	}
	page, err := svc.Entries(ctx, agentcontext.PageOptions{RunID: replayManyRun, SessionID: tail, Kind: "tool_call"})
	if err != nil || len(page.Entries) != 1 {
		t.Fatalf("tail tool: %+v %v", page, err)
	}
	tool := agentcontext.ToolNodeID(page.Entries[0])
	if _, err := db.Exec(`INSERT INTO events(id,run_id,source,event_type,payload,created_at) VALUES ('issue4-tail-event',?,'synthetic_fixture','file_open','{"path":"/fixture/report.py"}','2026-10-19T00:00:00Z')`, replayManyRun); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO graph_edges(id,run_id,from_id,to_id,edge_type,source_event_id,created_at) VALUES ('issue4-tail-edge',?,?,'runtime_event/issue4-tail-event','agent_syscall','issue4-tail-event','2026-10-19T00:00:00Z')`, replayManyRun, tool); err != nil {
		t.Fatal(err)
	}
	return Server{DB: db}, tail
}

func TestReplayExportAllSessionsBeyondOverview(t *testing.T) {
	s, tail := replayManySessions(t)
	ctx := context.Background()
	snapshot, err := s.freezeReplaySource(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	// A live-store change after freezing must not change the session catalog or
	// any of the indexes exported from that same snapshot.
	if _, err := s.DB.Exec(`DELETE FROM agent_context_reports WHERE run_id=? AND session_id=?`, replayManyRun, tail); err != nil {
		t.Fatal(err)
	}
	frozen := Server{DB: snapshot.DB}
	overview, err := (agentcontext.Service{DB: snapshot.DB}).Overview(ctx, replayManyRun)
	if err != nil || !overview.HasMoreSources || len(overview.Coverage) != 256 {
		t.Fatalf("fixture must exceed unchanged overview cap: %d %v", len(overview.Coverage), err)
	}
	for _, c := range overview.Coverage {
		if c.Source.SessionID == tail {
			t.Fatal("tail must be outside overview")
		}
	}
	replay, err := frozen.ExportReplay(ctx, replayManyRun, &staticdata.Writer{Root: filepath.Join(t.TempDir(), "export")})
	if err != nil {
		t.Fatal(err)
	}
	if len(replay.Sessions) != 260 || len(replay.Search) != 261 {
		t.Fatalf("complete session indexes: sessions=%d want=260 search=%d want=261; omitted tail=%s", len(replay.Sessions), len(replay.Search), tail)
	}
	key := fmt.Sprintf(`["codex",%q]`, tail)
	if !slices.Equal(replay.Sessions[key].EventIDs, []string{"issue4-tail-event"}) || replay.Sessions[key].Lenses.Path == "" || replay.Sessions[key].Relations[""].Path == "" || replay.Search[key][""].Path == "" {
		t.Fatalf("tail indexes incomplete: %+v", replay.Sessions[key])
	}
	if replay.Audit == nil || replay.Audit.Rule != telemetry.AuditAssociationRule {
		t.Fatalf("audit rule not serialized: %+v", replay.Audit)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := frozen.ExportReplay(canceled, replayManyRun, &staticdata.Writer{Root: t.TempDir()}); !errors.Is(err, context.Canceled) {
		t.Fatalf("export cancellation hidden: %v", err)
	}
}

func TestReplayExportManySessionsSelectedZIP(t *testing.T) {
	s, tail := replayManySessions(t)
	ctx := context.Background()
	entries, err := (agentcontext.Service{DB: s.DB}).Entries(ctx, agentcontext.PageOptions{RunID: replayManyRun, SessionID: tail})
	if err != nil {
		t.Fatal(err)
	}
	var excluded string
	for _, e := range entries.Entries {
		if e.SourceKey == "excluded" {
			excluded = "entry/" + e.ID
		}
	}
	if excluded == "" {
		t.Fatal("missing excluded fixture record")
	}
	for _, mode := range []string{"whole", "selected"} {
		t.Run(mode, func(t *testing.T) {
			selection := ReplaySelection{RunID: replayManyRun, Scope: "whole_run"}
			want := 260
			if mode == "selected" {
				selection.Scope, selection.Harness, selection.SessionID = "session", "codex", tail
				selection.ExcludeRecords = []string{excluded}
				want = 1
			}
			prepared, err := s.PrepareSelectedOfflineReplay(ctx, selection)
			if err != nil {
				t.Fatal(err)
			}
			defer prepared.Close()
			files, all := replayZIPData(t, prepared)
			encoded := strings.TrimSuffix(strings.TrimPrefix(string(files["assets/catalog.js"]), `window.AgentProvOfflineCatalog="`), `";`)
			data, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				t.Fatal(err)
			}
			var catalog struct {
				Runs map[string]ReplayRun `json:"runs"`
			}
			if err := json.Unmarshal(data, &catalog); err != nil {
				t.Fatal(err)
			}
			replay := catalog.Runs[replayManyRun]
			if len(replay.Sessions) != want || len(replay.Search) != want+1 || prepared.Inventory.Contents.Sessions != want {
				t.Fatalf("ZIP index counts: sessions=%d search=%d inventory=%d want=%d", len(replay.Sessions), len(replay.Search), prepared.Inventory.Contents.Sessions, want)
			}
			read := func(ref staticdata.Ref, value any) {
				t.Helper()
				name := strings.TrimSuffix(ref.Path, ".json.gz") + ".js"
				if err := json.Unmarshal(files[name], value); err != nil {
					t.Fatalf("missing/invalid shard %s: %v", name, err)
				}
			}
			key := fmt.Sprintf(`["codex",%q]`, tail)
			if !slices.Equal(replay.Sessions[key].EventIDs, []string{"issue4-tail-event"}) {
				t.Fatalf("missing tail event: %+v", replay.Sessions[key])
			}
			var relations agentcontext.SessionRelationsPage
			read(replay.Sessions[key].Relations[""], &relations)
			if len(relations.Relations) != 1 || relations.Relations[0].Kind != "fork" || relations.Relations[0].From.SessionID != "session-000" || relations.Relations[0].From.Available != (mode == "whole") || relations.Relations[0].To.SessionID != tail || len(relations.Relations[0].Evidence) != 1 {
				t.Fatalf("tail typed fork boundary: %+v", relations)
			}
			for sessionKey, scope := range replay.Sessions {
				var index struct {
					Views map[string]staticdata.Ref `json:"views"`
				}
				read(scope.Lenses, &index)
				if len(index.Views) != 36 {
					t.Fatalf("incomplete graph views for %s: %d", sessionKey, len(index.Views))
				}
				for _, ref := range index.Views {
					var view map[string]any
					read(ref, &view)
				}
				if scope.Relations[""].Path == "" || replay.Search[sessionKey][""].Path == "" {
					t.Fatalf("missing indexes for %s", sessionKey)
				}
			}
			if !strings.Contains(all, "ISSUE4-TAIL-SEARCH-BODY") {
				t.Fatal("tail body missing")
			}
			if mode == "selected" {
				if strings.Contains(all, "ISSUE4-EXCLUDED-SECRET") {
					t.Fatal("excluded body leaked")
				}
				for i := 0; i < 260; i++ {
					id := fmt.Sprintf("session-%03d", i)
					if id != tail && strings.Contains(all, "ISSUE4-BODY-"+id) {
						t.Fatalf("foreign session body leaked: %s", id)
					}
				}
			}
			if root := os.Getenv("AGENTPROV_ISSUE4_OUTPUT"); root != "" {
				if err := os.MkdirAll(root, 0700); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(root, "issue4-"+mode+".zip")
				f, err := os.Create(path)
				if err != nil {
					t.Fatal(err)
				}
				err = prepared.WriteZIP(ctx, f)
				closeErr := f.Close()
				if err != nil {
					t.Fatal(err)
				}
				if closeErr != nil {
					t.Fatal(closeErr)
				}
				metadata, _ := json.MarshalIndent(map[string]any{"run": replayManyRun, "tail_session": tail, "harness": "codex", "tail_event": "issue4-tail-event", "sources": 260, "sessions": want, "search_scopes": want + 1, "tail_body": "ISSUE4-TAIL-SEARCH-BODY", "excluded_record": excluded, "audit_rule": replay.Audit.Rule, "fork_parent": "session-000", "fork_parent_available": mode == "whole"}, "", "  ")
				if err := os.WriteFile(filepath.Join(root, "issue4-"+mode+".json"), metadata, 0600); err != nil {
					t.Fatal(err)
				}
				t.Logf("offline fixture: %s tail=%s", path, tail)
			}
		})
	}
}

func TestReplaySessionIndexReconciliation(t *testing.T) {
	expected := []agentcontext.SessionIdentity{{Harness: "codex", SessionID: "tail"}}
	key := `["codex","tail"]`
	ref := staticdata.Ref{Path: "data/fixture.json.gz"}
	valid := func() ReplayRun {
		return ReplayRun{Sessions: map[string]replaySession{key: {Lenses: ref, EventIDs: []string{}, Relations: map[string]staticdata.Ref{"": ref}}}, Search: map[string]map[string]staticdata.Ref{key: {"": ref}, `["",""]`: {"": ref}}}
	}
	if err := reconcileReplaySessions(expected, valid()); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*ReplayRun){
		func(r *ReplayRun) { delete(r.Sessions, key) },
		func(r *ReplayRun) { r.Sessions[`["codex","unexpected"]`] = r.Sessions[key] },
		func(r *ReplayRun) { delete(r.Search, key) },
		func(r *ReplayRun) { delete(r.Search, `["",""]`) },
		func(r *ReplayRun) { s := r.Sessions[key]; s.Lenses = staticdata.Ref{}; r.Sessions[key] = s },
		func(r *ReplayRun) { s := r.Sessions[key]; s.EventIDs = nil; r.Sessions[key] = s },
		func(r *ReplayRun) { delete(r.Sessions[key].Relations, "") },
		func(r *ReplayRun) { delete(r.Search[key], "") },
	} {
		r := valid()
		mutate(&r)
		if err := reconcileReplaySessions(expected, r); err == nil {
			t.Fatal("incomplete index accepted")
		}
	}
}

func TestReplayAuditIndexPersistsRule(t *testing.T) {
	_, db, _ := artifactStore(t)
	// Use an audit event so the rule is checked in both catalog and shard.
	line := `type=AVC msg=audit(1792342593.757:130): apparmor="DENIED" operation="open" profile="fixture" pid=42 comm="fixture" name="/fixture/private.txt" requested_mask="r" denied_mask="r"`
	if _, err := telemetry.IngestAuditReader(context.Background(), db, telemetry.AuditIngestOptions{RunID: "audit-rule"}, strings.NewReader(line)); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	index, err := (Server{DB: db}).exportReplayAudit(context.Background(), "audit-rule", &staticdata.Writer{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	var serialized struct {
		Rule string `json:"rule"`
	}
	if err := json.Unmarshal(raw, &serialized); err != nil || serialized.Rule != telemetry.AuditAssociationRule {
		t.Fatalf("index rule: %s %v", raw, err)
	}
	if len(index.Pages) == 0 {
		t.Fatal("audit fixture produced no shard")
	}
	for _, page := range index.Pages {
		f, err := os.Open(filepath.Join(root, page.Data.Path))
		if err != nil {
			t.Fatal(err)
		}
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			t.Fatal(err)
		}
		var report telemetry.AuditAssociationReport
		err = json.NewDecoder(gz).Decode(&report)
		gz.Close()
		f.Close()
		if err != nil || report.Rule != index.Rule {
			t.Fatalf("shard rule mismatch: %q %q %v", report.Rule, index.Rule, err)
		}
	}
}

func TestReplayExportRejectsLimitedSessionRelations(t *testing.T) {
	paths, db, _ := artifactStore(t)
	svc := agentcontext.Service{DB: db, Paths: paths}
	ctx := context.Background()
	for i := 0; i < 1025; i++ {
		src := agentcontext.Source{Harness: "codex", Channel: "transcript", SessionID: fmt.Sprintf("session-%04d", i), ParserVersion: "issue4-fixture/v1", Binding: "explicit"}
		if _, err := svc.Save(ctx, "relation-budget", src, nil, agentcontext.Coverage{Status: agentcontext.OK}); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := (Server{DB: db}).freezeReplaySource(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	_, err = (Server{DB: snapshot.DB}).ExportReplay(ctx, "relation-budget", &staticdata.Writer{Root: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "session relations resource limit exceeded") {
		t.Fatalf("limited relation discovery published as complete: %v", err)
	}
}

func TestReplayComparisonResourceAndCancellation(t *testing.T) {
	entries := make([]agentcontext.Entry, 1001)
	for i := range entries {
		entries[i] = agentcontext.Entry{Kind: "configuration", Content: agentcontext.ContentRef{State: "excluded"}}
	}
	groups, err := replayComparisonGroups(context.Background(), entries[:1000])
	if err != nil || len(groups["configuration"]) != 1000 {
		t.Fatalf("exact pair budget: %d %v", len(groups["configuration"]), err)
	}
	groups, err = replayComparisonGroups(context.Background(), entries)
	if err == nil || groups != nil || !strings.Contains(err.Error(), "comparison resource limit exceeded") {
		t.Fatalf("quadratic work accepted: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if groups, err := replayComparisonGroups(ctx, entries); !errors.Is(err, context.Canceled) || groups != nil {
		t.Fatalf("canceled pair generation: %v", err)
	}
	groups, err = replayComparisonGroups(context.Background(), []agentcontext.Entry{{Kind: "message", Role: "user"}, {Kind: "message", Role: "assistant"}, {Kind: "configuration"}, {Kind: "approval"}})
	if err != nil || len(groups) != 3 || len(groups["task"]) != 1 || len(groups["configuration"]) != 1 || len(groups["approval"]) != 1 {
		t.Fatalf("comparison grouping: %+v %v", groups, err)
	}
}

func TestReplayTypedForkSelectionBoundary(t *testing.T) {
	for _, preset := range []string{"basic", "detailed"} {
		t.Run(preset, func(t *testing.T) {
			paths, db, _ := artifactStore(t)
			policy, err := agentcontext.NewCapturePolicy(preset, nil)
			if err != nil {
				t.Fatal(err)
			}
			svc := agentcontext.Service{DB: db, Paths: paths, CapturePolicy: &policy}
			ctx := context.Background()
			const run = "issue2-fork-sharing"
			for _, input := range []struct{ run, session, parent, body string }{
				{run, "root", "", "ISSUE2-SAME-RUN-PARENT-BODY"},
				{"private-parent-run", "root", "", "ISSUE2-PRIVATE-PARENT-BODY"},
				{run, "branch", "root", "ISSUE2-CHILD-CONFIG-BODY"},
			} {
				body, _ := json.Marshal(map[string]string{"id": input.session, "forked_from_id": input.parent, "instructions": input.body})
				parsed, err := agentcontext.Parse(ctx, strings.NewReader(`{"type":"session_meta","payload":`+string(body)+`}`), agentcontext.ParseOptions{Harness: "codex", Binding: "explicit"})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := svc.Save(ctx, input.run, parsed.Source, parsed.Records, parsed.Coverage); err != nil {
					t.Fatal(err)
				}
			}
			for _, mode := range []string{"whole", "session", "excluded"} {
				t.Run(mode, func(t *testing.T) {
					selection := ReplaySelection{RunID: run, Scope: "whole_run"}
					if mode != "whole" {
						selection.Scope, selection.Harness, selection.SessionID = "session", "codex", "branch"
					}
					if mode == "excluded" {
						selection.ExcludeCategories = []string{"configuration"}
					}
					prepared, err := (Server{DB: db}).PrepareSelectedOfflineReplay(ctx, selection)
					if err != nil {
						t.Fatal(err)
					}
					defer prepared.Close()
					files, all := replayZIPData(t, prepared)
					if strings.Contains(all, "ISSUE2-PRIVATE-PARENT-BODY") {
						t.Fatal("private parent body crossed bundle boundary")
					}
					if mode != "whole" && strings.Contains(all, "ISSUE2-SAME-RUN-PARENT-BODY") {
						t.Fatal("unselected same-run parent body copied by fork traversal")
					}
					if (preset == "basic" || mode == "excluded") && strings.Contains(all, "ISSUE2-CHILD-CONFIG-BODY") {
						t.Fatal("omitted or excluded configuration body reconstructed")
					}
					encoded := strings.TrimSuffix(strings.TrimPrefix(string(files["assets/catalog.js"]), `window.AgentProvOfflineCatalog="`), `";`)
					raw, err := base64.StdEncoding.DecodeString(encoded)
					if err != nil {
						t.Fatal(err)
					}
					var catalog struct {
						Runs map[string]ReplayRun `json:"runs"`
					}
					if err := json.Unmarshal(raw, &catalog); err != nil {
						t.Fatal(err)
					}
					replay := catalog.Runs[run]
					wantSessions := 1
					if mode == "whole" {
						wantSessions = 2
					}
					if len(replay.Sessions) != wantSessions {
						t.Fatalf("selection widened session indexes: %d", len(replay.Sessions))
					}
					ref := replay.Sessions[`["codex","branch"]`].Relations[""]
					var page agentcontext.SessionRelationsPage
					if err := json.Unmarshal(files[strings.TrimSuffix(ref.Path, ".json.gz")+".js"], &page); err != nil {
						t.Fatal(err)
					}
					if mode == "excluded" {
						if len(page.Relations) != 0 {
							t.Fatalf("excluded typed metadata reconstructed relation: %+v", page.Relations)
						}
						return
					}
					if len(page.Relations) != 1 || page.Limited {
						t.Fatalf("fork missing: %+v", page)
					}
					r := page.Relations[0]
					if r.Kind != "fork" || r.From.SessionID != "root" || r.To.SessionID != "branch" || r.From.Available != (mode == "whole") || len(r.From.RunIDs) != 0 || r.From.RunID == "private-parent-run" || len(r.Evidence) != 1 || r.Evidence[0].EntryID == "" {
						t.Fatalf("typed fork boundary or provenance lost: %+v", r)
					}
				})
			}
		})
	}
}
