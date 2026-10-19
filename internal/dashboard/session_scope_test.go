package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/hooksbridge"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/staticdata"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func addSessionGraphFixture(t *testing.T, svc agentcontext.Service) {
	t.Helper()
	ctx := context.Background()
	const run = "ui-session-graph"
	for _, source := range []agentcontext.Source{
		{Harness: "codex", Channel: "transcript", SessionID: "root"},
		{Harness: "codex", Channel: "transcript", SessionID: "worker", ParentSessionID: "root"},
		{Harness: "codex", Channel: "hooks", SessionID: "worker", ParentSessionID: "root"},
		{Harness: "claude", Channel: "transcript", SessionID: "root"},
		{Harness: "codex", Channel: "transcript", SessionID: "quiet"},
	} {
		source.Binding, source.ParserVersion, source.Workdir = "explicit", "synthetic-session-graph/v1", "/fixture/shared"
		body, command, result := "Synthetic session graph fixture: "+source.Harness+"/"+source.SessionID, `{"cmd":"cat shared.txt"}`, "Saved fixture result; no task was executed."
		records := []agentcontext.Record{{Key: "task", Sequence: 1, Kind: "message", Role: "user", Body: &body}}
		if source.SessionID != "quiet" {
			records = append(records, agentcontext.Record{Key: "call", Sequence: 2, Kind: "tool_call", ToolName: "exec_command", ToolCallID: "reused", Body: &command, RecordedAt: "2026-10-18T00:00:01Z"}, agentcontext.Record{Key: "result", Sequence: 3, Kind: "tool_result", ToolName: "exec_command", ToolCallID: "reused", Body: &result, RecordedAt: "2026-10-18T00:00:02Z"})
		}
		if _, err := svc.Save(ctx, run, source, records, agentcontext.Coverage{Status: agentcontext.OK}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := hooksbridge.IngestContext(ctx, svc.DB, svc.Paths, run); err != nil {
		t.Fatal(err)
	}
	page, err := svc.Entries(ctx, agentcontext.PageOptions{RunID: run, Kind: "tool_call"})
	if err != nil {
		t.Fatal(err)
	}
	tools := map[string]bool{}
	for _, e := range page.Entries {
		tool := agentcontext.ToolNodeID(e)
		if tools[tool] {
			continue
		}
		tools[tool] = true
		id := "fixture-" + e.Source.Harness + "-" + e.Source.SessionID
		_, err := svc.DB.Exec(`INSERT INTO events (id,run_id,source,event_type,payload,pid,created_at) VALUES (?,?, 'synthetic_fixture','file_open','{"path":"/fixture/shared.txt"}',9001,'2026-10-18T00:00:03Z')`, id, run)
		if err != nil {
			t.Fatal(err)
		}
		for i, edge := range [][3]string{{tool, "runtime_event/" + id, "agent_syscall"}, {"runtime_process/pid/9001", "runtime_event/" + id, "runtime_process_event"}, {"runtime_event/" + id, "workspace_file//fixture/shared.txt", "runtime_event_file"}} {
			_, err = svc.DB.Exec(`INSERT INTO graph_edges (id,run_id,from_id,to_id,edge_type,source_event_id,created_at) VALUES (?,?,?,?,?,?,'2026-10-18T00:00:03Z')`, correlation.AppProcessEdgePrefix+fmt.Sprintf("fixture-%s-%d", id, i), run, edge[0], edge[1], edge[2], id)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := svc.DB.Exec(`INSERT INTO events (id,run_id,source,event_type,payload,pid,created_at) VALUES ('fixture-unassigned',?,'synthetic_fixture','file_open','{"path":"/fixture/shared.txt"}',9001,'2026-10-18T00:00:03Z')`, run); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DB.Exec(`INSERT INTO graph_edges (id,run_id,from_id,to_id,edge_type,source_event_id,created_at) VALUES ('fixture-unassigned-process',?,'runtime_process/pid/9001','runtime_event/fixture-unassigned','runtime_process_event','fixture-unassigned','2026-10-18T00:00:03Z')`, run); err != nil {
		t.Fatal(err)
	}
}

func TestDashboardSessionScopes(t *testing.T) {
	paths, err := store.Init(filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	svc := agentcontext.Service{DB: db, Paths: paths}
	addSessionGraphFixture(t, svc)
	server := Server{DB: db}
	h := server.Handler()
	get := func(path string, want int, value any) {
		t.Helper()
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != want {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		if value != nil {
			v := reflect.ValueOf(value).Elem()
			v.Set(reflect.Zero(v.Type()))
			if err := json.Unmarshal(w.Body.Bytes(), value); err != nil {
				t.Fatal(err)
			}
		}
	}
	const base = "run=ui-session-graph&harness=codex&session=worker"
	for _, path := range []string{"/api/lens?", "/api/events?"} {
		get(path+"run=ui-session-graph&session=worker", 400, nil)
		get(path+"run=ui-session-graph&harness=claude&session=worker", 404, nil)
		get(path+"run=absent&harness=codex&session=worker", 404, nil)
	}
	scope, err := svc.SessionGraphScope(context.Background(), "ui-session-graph", "codex", "worker")
	if err != nil || len(scope.SourceIDs) != 2 || len(scope.ToolIDs) != 1 || !reflect.DeepEqual(scope.EventIDs, []string{"fixture-codex-worker"}) {
		t.Fatalf("scope: %+v %v", scope, err)
	}
	var list agentcontext.Page
	get("/api/context/entries?run=ui-session-graph&harness=codex&session=root", 200, &list)
	if len(list.Entries) != 3 {
		t.Fatalf("harness filter: %+v", list)
	}
	for _, e := range list.Entries {
		if e.Source.Harness != "codex" {
			t.Fatal("mixed harness identities")
		}
	}
	get("/api/context/entries?run=ui-session-graph&harness=codex&session=root&limit=1", 200, &list)
	get("/api/context/entries?run=ui-session-graph&harness=claude&session=root&limit=1&cursor="+url.QueryEscape(list.NextCursor), 400, nil)
	var manifest provenance.GraphLensManifest
	get("/api/lens?"+base+"&detail=raw", 200, &manifest)
	if manifest.Query.SessionScope == nil || manifest.Query.RawEventCount != 1 || manifest.Query.SessionScope.Sources != 2 {
		t.Fatalf("scoped query: %+v", manifest.Query)
	}
	for _, n := range manifest.Nodes {
		if n.Kind == "runtime_event" && n.ID != "runtime_event/fixture-codex-worker" {
			t.Fatalf("unrelated event: %s", n.ID)
		}
	}
	if len(manifest.DerivedEdges) != 1 || manifest.DerivedEdges[0].DerivationRule != correlation.AppProcessMethod || manifest.DerivedEdges[0].Confidence == nil {
		t.Fatalf("association provenance lost: %+v", manifest.DerivedEdges)
	}
	var events struct {
		Total  int
		Events []struct{ ID string }
	}
	for _, filter := range []string{"", "&focus=runtime_process/pid/9001", "&refs=runtime_event/fixture-codex-worker,runtime_event/fixture-unassigned"} {
		get("/api/events?"+base+filter, 200, &events)
		if events.Total != 1 || events.Events[0].ID != "fixture-codex-worker" {
			t.Fatalf("scope intersection: %+v", events)
		}
	}
	get("/api/events?"+base+"&refs=runtime_event/fixture-unassigned", 200, &events)
	if events.Total != 0 {
		t.Fatal("reference widened the session")
	}
	get("/api/lens?"+base+"&focus=runtime_event/fixture-unassigned", 400, nil)
	get("/api/lens?"+base+"&detail=summary", 200, &manifest)
	for _, n := range manifest.Nodes {
		if n.ID == "overview/tool_calls" && n.Data["count"] != float64(1) {
			t.Fatalf("unscoped summary: %+v", n)
		}
	}
	get("/api/lens?run=ui-session-graph&harness=codex&session=quiet&detail=raw", 200, &manifest)
	if len(manifest.Nodes) != 0 || manifest.Query.RawEventCount != 0 {
		t.Fatal("empty session widened to run")
	}
	get("/api/lens?run=ui-session-graph&detail=raw", 200, &manifest)
	if manifest.Query.RawEventCount != 4 || manifest.Query.SessionScope != nil {
		t.Fatal("whole run changed")
	}
	views, err := provenance.BuildSessionReplayLenses(db, "ui-session-graph", scope)
	if err != nil {
		t.Fatal(err)
	}
	for _, view := range views.Views {
		get("/api/lens?"+base+"&detail="+view.Manifest.Query.Detail+"&lens="+view.Manifest.Lens+"&overlay=risk&overlay=trust", 200, &manifest)
		live, _ := json.Marshal(manifest)
		replay, _ := json.Marshal(view.Manifest)
		if string(live) != string(replay) {
			t.Fatalf("session replay mismatch: %s/%s", manifest.Lens, manifest.Query.Detail)
		}
		for _, node := range view.Manifest.Nodes {
			get("/api/lens?"+base+"&detail="+view.Manifest.Query.Detail+"&lens="+view.Manifest.Lens+"&focus="+url.QueryEscape(node.ID), 200, nil)
		}
	}
	replay, err := server.ExportReplay(context.Background(), "ui-session-graph", &staticdata.Writer{Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if len(replay.Sessions) != 4 || !slices.Equal(replay.Sessions[`["codex","worker"]`].EventIDs, scope.EventIDs) {
		t.Fatalf("session export: %+v", replay.Sessions)
	}
}
