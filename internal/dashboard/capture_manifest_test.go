package dashboard

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestCaptureManifestDashboardReadGuard(t *testing.T) {
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
	path := "/api/capture-manifest?run=historical-run"
	resp := do(t, srv, http.MethodGet, path, "", map[string]string{"Origin": srv.URL})
	var page struct {
		SchemaVersion string            `json:"schema_version"`
		RunID         string            `json:"run_id"`
		Records       []json.RawMessage `json:"records"`
		HasMore       bool              `json:"has_more"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&page) != nil ||
		page.SchemaVersion != "agentprovenance.capture_manifest/v1" || page.RunID != "historical-run" || page.Records == nil || len(page.Records) != 0 || page.HasMore {
		t.Fatalf("capture manifest read route: %d %+v", resp.StatusCode, page)
	}
	resp.Body.Close()
	for _, headers := range []map[string]string{{"Origin": "https://untrusted.example", "Sec-Fetch-Site": "cross-site"}, {"Host": "untrusted.example"}} {
		resp = do(t, srv, http.MethodGet, path, headers["Host"], headers)
		if code := status(t, resp); code != http.StatusForbidden {
			t.Fatalf("untrusted manifest read allowed: %d", code)
		}
	}
	for _, path := range []string{"/api/capture-manifest", "/api/capture-manifest?run=r&limit=0", "/api/capture-manifest?run=r&cursor=bad"} {
		if code := status(t, do(t, srv, http.MethodGet, path, "", nil)); code != http.StatusBadRequest {
			t.Fatalf("invalid manifest query %s: %d", path, code)
		}
	}
}
