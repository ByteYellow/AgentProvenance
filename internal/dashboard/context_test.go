package dashboard

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestRunSelectorIncludesContextOnlyRuns(t *testing.T) {
	paths, err := store.Init(filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := agentcontext.Service{DB: db, Paths: paths}
	_, err = s.Save(context.Background(), "context-only", agentcontext.Source{ID: "source", Harness: "codex", ParserVersion: "test/v1", SessionID: "session", Binding: "explicit"}, nil, agentcontext.Coverage{Status: agentcontext.Empty})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	Server{DB: db}.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/runs", nil))
	var runs []runSummary
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &runs) != nil || len(runs) != 1 || runs[0].Run != "context-only" || runs[0].Events != 0 {
		t.Fatalf("context run missing: %d %s", w.Code, w.Body.String())
	}
}
