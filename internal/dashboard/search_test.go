package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/hooksbridge"
	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func allSearchSources(t *testing.T, server Server, opts SearchSourceOptions) []SearchSource {
	t.Helper()
	var result []SearchSource
	seen := map[string]bool{}
	for count := 0; count < 1000; count++ {
		page, err := server.SearchSources(context.Background(), opts)
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Sources) > searchSourceLimit {
			t.Fatal("unbounded catalog page")
		}
		for _, source := range page.Sources {
			if seen[source.ID] {
				t.Fatalf("duplicate source: %s", source.ID)
			}
			seen[source.ID] = true
			result = append(result, source)
		}
		if !page.HasMore {
			return result
		}
		if page.NextCursor == "" || opts.Cursor == page.NextCursor {
			t.Fatal("catalog did not advance")
		}
		opts.Cursor = page.NextCursor
	}
	t.Fatal("catalog did not finish")
	return nil
}

func TestSearchSourcesScopeAndPagination(t *testing.T) {
	paths, db, objects := artifactStore(t)
	db.SetMaxOpenConns(1)
	service := agentcontext.Service{DB: db, Paths: paths}
	addSessionGraphFixture(t, service)
	ctx := context.Background()
	var records []agentcontext.Record
	for n := 0; n < 103; n++ {
		body := strings.Repeat("saved-only output ", 5000) + "TAIL-SEARCH"
		records = append(records, agentcontext.Record{Key: strings.Repeat("x", n+1), Sequence: int64(n + 1), Kind: "tool_result", Body: &body})
	}
	if _, err := service.Save(ctx, "catalog", agentcontext.Source{ID: "source", Harness: "codex", SessionID: "native", Binding: "explicit", ParserVersion: "test/v1"}, records, agentcontext.Coverage{Status: agentcontext.OK}); err != nil {
		t.Fatal(err)
	}
	file := putArtifact(t, objects, "catalog", "workspace_file/report.txt", map[string]any{"path": "report.txt", "content": "FILE-ONLY"})
	putArtifact(t, objects, "different-run", "workspace_file/report.txt", map[string]any{"content": "NEVER-IN-CATALOG"})
	if _, err := db.Exec(`INSERT INTO events(id,run_id,event_type,source,payload,created_at) VALUES('e','catalog','file_open','fixture','{}','2026-10-18T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	server := Server{DB: db}
	all := allSearchSources(t, server, SearchSourceOptions{RunID: "catalog"})
	if len(all) != 105 {
		t.Fatalf("missing source pages: %d", len(all))
	}
	native := allSearchSources(t, server, SearchSourceOptions{RunID: "catalog", Harness: "codex", SessionID: "native"})
	if len(native) != 103 {
		t.Fatalf("scope included unassigned records: %d", len(native))
	}
	for _, source := range native {
		if source.Entry == nil || source.Content.Ref == "" || source.Content.State != "stored" || source.SessionID != "native" || source.Node == file.Hash {
			t.Fatalf("invalid scoped source: %+v", source)
		}
	}
	owned := putArtifact(t, objects, "ui-session-graph", "workspace_file/shared.txt", map[string]any{"content": "OWNED-BODY"})
	unassigned := putArtifact(t, objects, "ui-session-graph", "workspace_file/shared.txt", map[string]any{"content": "UNASSIGNED-BODY"})
	for _, edge := range [][2]string{{"runtime_event/fixture-codex-worker", owned.Hash}, {"workspace_file//fixture/shared.txt", unassigned.Hash}} {
		if _, err := db.Exec(`INSERT INTO graph_edges(id,run_id,from_id,to_id,edge_type,created_at) VALUES(?,'ui-session-graph',?,?,'saved_content','2026-10-18T00:00:04Z')`, "search/"+edge[1], edge[0], edge[1]); err != nil {
			t.Fatal(err)
		}
	}
	scoped := allSearchSources(t, server, SearchSourceOptions{RunID: "ui-session-graph", Harness: "codex", SessionID: "worker"})
	ownedFound, eventFound := false, false
	for _, source := range scoped {
		if source.Entry != nil && (source.Harness != "codex" || source.SessionID != "worker") {
			t.Fatalf("cross-session source: %+v", source)
		}
		if source.Category == "runtime" {
			if source.Node != "runtime_event/fixture-codex-worker" {
				t.Fatalf("unrelated runtime source included: %s", source.Node)
			}
			eventFound = true
		}
		if source.Node == unassigned.Hash {
			t.Fatal("shared file path widened the session search")
		}
		if source.Node == owned.Hash {
			ownedFound = true
		}
	}
	if !ownedFound || !eventFound {
		t.Fatalf("directly linked evidence omitted: artifact=%t event=%t", ownedFound, eventFound)
	}
	page, err := server.SearchSources(ctx, SearchSourceOptions{RunID: "catalog"})
	if err != nil || !page.HasMore {
		t.Fatalf("first page: %+v %v", page, err)
	}
	for _, opts := range []SearchSourceOptions{{RunID: "other", Cursor: page.NextCursor}, {RunID: "catalog", Harness: "codex", SessionID: "native", Cursor: page.NextCursor}, {RunID: "catalog", Cursor: "bad"}, {RunID: "catalog", SessionID: "native"}} {
		if _, err := server.SearchSources(ctx, opts); !errors.Is(err, agentcontext.ErrInvalidArgument) {
			t.Fatalf("invalid cursor/scope accepted: %+v %v", opts, err)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := server.SearchSources(cancelled, SearchSourceOptions{RunID: "catalog"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/search/sources?run=catalog", nil))
	if w.Code != 500 {
		t.Fatalf("database failure became an empty search: %d", w.Code)
	}
}

func addSearchFixture(t *testing.T, s agentcontext.Service) {
	t.Helper()
	ctx := context.Background()
	output := strings.Repeat("Synthetic bounded build output.\n", 6000) + "permission denied: /tmp/report.txt\nhttps://fixture.example/169.254.169.254\n<img src=x onerror=alert(1)>"
	command := `{"cmd":"python3 report.py"}`
	for _, source := range []agentcontext.Source{
		{ID: "search-primary", Harness: "codex", Channel: "transcript", SessionID: "search-main", AgentID: "fixture-agent"},
		{ID: "search-duplicate", Harness: "codex", Channel: "hooks", SessionID: "search-main", AgentID: "fixture-agent"},
		{ID: "search-other", Harness: "codex", Channel: "transcript", SessionID: "search-other"},
	} {
		source.Binding, source.ParserVersion = "explicit", "synthetic-search-fixture/v1"
		body := output
		if source.SessionID == "search-other" {
			body = "OTHER-SESSION-ONLY: permission denied"
		}
		raw := `{"fixture":true,"kind":"tool_result"}`
		records := []agentcontext.Record{
			{Key: "call", Sequence: 1, Kind: "tool_call", ToolCallID: "search-call", ToolName: "exec_command", Body: &command, ExecutionScope: agentcontext.CurrentExecution},
			{Key: "result", Sequence: 2, Kind: "tool_result", ToolCallID: "search-call", ToolName: "exec_command", Body: &body, RawBody: &raw, Status: "source_truncated", ExecutionScope: agentcontext.CurrentExecution},
			{Key: "omitted", Sequence: 3, Kind: "message", Role: "assistant", MissingFields: []string{"body"}},
		}
		if _, err := s.Save(ctx, "ui-search", source, records, agentcontext.Coverage{Status: agentcontext.Partial, MissingFields: []string{"approval_decision"}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := hooksbridge.IngestContext(ctx, s.DB, s.Paths, "ui-search"); err != nil {
		t.Fatal(err)
	}
	objects := provenance.ObjectStore{DB: s.DB, Paths: s.Paths}
	putArtifact(t, objects, "ui-search", "workspace_file/saved-report.txt", map[string]any{"path": "saved-report.txt", "content": "UNASSIGNED-FILE-ONLY"})
	// Materialize tool objects exactly as the ordinary capture path does.
	if _, err := objects.MaterializeRun("ui-search"); err != nil {
		t.Fatal(err)
	}
}

func TestSearchSourceHTTP(t *testing.T) {
	paths, db, _ := artifactStore(t)
	addSearchFixture(t, agentcontext.Service{DB: db, Paths: paths})
	h := Server{DB: db}.Handler()
	for _, tc := range []struct {
		query  string
		status int
	}{{"run=ui-search", 200}, {"", 400}, {"run=ui-search&session=search-main", 400}, {"run=ui-search&harness=codex&session=unknown", 404}} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/api/search/sources?"+tc.query, nil))
		if w.Code != tc.status {
			t.Fatalf("%s: %d %s", tc.query, w.Code, w.Body.String())
		}
		if tc.status == 200 {
			var page SearchSources
			if json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Sources) != 9 {
				t.Fatalf("invalid catalog: %s", w.Body.String())
			}
			for _, source := range page.Sources {
				if source.Content.State == "stored" {
					w := httptest.NewRecorder()
					h.ServeHTTP(w, httptest.NewRequest("GET", "/api/context/content?run=ui-search&ref="+url.QueryEscape(source.Content.Ref), nil))
					if w.Code != 200 {
						t.Fatalf("catalog uses invalid content ref: %s", source.ID)
					}
				}
			}
		}
	}
}
