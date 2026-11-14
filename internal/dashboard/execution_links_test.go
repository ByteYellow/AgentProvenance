package dashboard

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/handoff"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestExecutionLinksDashboardReadGuard(t *testing.T) {
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	srv := serveReal(t, Server{DB: db})
	path := "/api/execution-links?run=caller"
	resp := do(t, srv, http.MethodGet, path, "", map[string]string{"Origin": srv.URL})
	var page handoff.ExecutionLinksPage
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&page) != nil || page.SchemaVersion != handoff.ExecutionLinksSchema {
		t.Fatalf("dashboard execution read route: %d %+v", resp.StatusCode, page)
	}
	resp = do(t, srv, http.MethodGet, path, "", map[string]string{"Origin": "https://untrusted.example", "Sec-Fetch-Site": "cross-site"})
	if code := status(t, resp); code != http.StatusForbidden {
		t.Fatalf("cross-site execution read allowed: %d", code)
	}
	resp = do(t, srv, http.MethodGet, path, "untrusted.example", nil)
	if code := status(t, resp); code != http.StatusForbidden {
		t.Fatalf("rebound execution read allowed: %d", code)
	}
}
