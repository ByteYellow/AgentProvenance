package agentcontext

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/observability"
)

func TestReadAPIIsolationPaginationAndErrors(t *testing.T) {
	s := testService(t)
	body := "\u4e2d\u6587 result"
	_, err := s.Save(context.Background(), "run", testSource(), []Record{{Key: "a", Kind: "message", Body: &body}, {Key: "b", Sequence: 2, Kind: "tool_call", Body: &body, ToolCallID: "c"}}, Coverage{Status: OK})
	if err != nil {
		t.Fatal(err)
	}
	h := s.ReadHandler()
	get := func(path string) (int, []byte) {
		r := httptest.NewRecorder()
		h.ServeHTTP(r, httptest.NewRequest("GET", path, nil))
		return r.Code, r.Body.Bytes()
	}
	code, raw := get("/context/entries?run=run&limit=1")
	var page Page
	if json.Unmarshal(raw, &page) != nil || code != 200 || !page.HasMore || len(page.Entries) != 1 {
		t.Fatalf("page: %d %s", code, raw)
	}
	ref := page.Entries[0].Content.Ref
	for _, tc := range []struct {
		path string
		code int
	}{
		{"/context/overview?run=run", 200},
		{"/context/overview", 400},
		{"/context/overview?run=absent", 404},
		{"/context/entries?run=run&limit=201", 400},
		{"/context/entries?run=run&cursor=bad", 400},
		{"/context/entries?run=run&revisions=perhaps", 400},
		{"/context/entries?run=run&limit=1&cursor=" + page.NextCursor, 200},
		{"/context/content?run=run&ref=" + ref + "&limit=4", 200},
		{"/context/content?run=run&ref=" + ref + "&offset=1", 400},
		{"/context/content?run=run&ref=" + ref + "&offset=999", 400},
		{"/context/content?run=run&ref=sha256:" + strings.Repeat("0", 64), 404},
		{"/context/content?run=run&ref=/etc/passwd", 400},
	} {
		code, raw := get(tc.path)
		if code != tc.code {
			t.Fatalf("%s: got %d want %d: %s", tc.path, code, tc.code, raw)
		}
		if !json.Valid(raw) {
			t.Fatalf("invalid json: %s", raw)
		}
	}
	if err := s.DB.Close(); err != nil {
		t.Fatal(err)
	}
	code, raw = get("/context/overview?run=run")
	if code != 503 || !strings.Contains(string(raw), "store_unavailable") {
		t.Fatalf("closed db: %d %s", code, raw)
	}
}

func TestPublicOverviewIncludesSavedRuntimeCoverage(t *testing.T) {
	s := testService(t)
	_, err := s.Save(context.Background(), "run", testSource(), nil, Coverage{Status: Empty})
	if err != nil {
		t.Fatal(err)
	}
	read := func() map[string]any {
		t.Helper()
		w := httptest.NewRecorder()
		s.ReadHandler().ServeHTTP(w, httptest.NewRequest("GET", "/context/overview?run=run", nil))
		var value map[string]any
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &value) != nil {
			t.Fatalf("public response: %d %s", w.Code, w.Body.Bytes())
		}
		return value["runtime_coverage"].(map[string]any)
	}
	legacy := read()["capture"].(map[string]any)
	if legacy["status"] != "legacy_not_recorded" || legacy["node_counter_delta"] != nil || legacy["run_dropped_events"] != nil {
		t.Fatalf("legacy contract: %+v", legacy)
	}
	r := observability.BuildRuntimeCapture("run", "disabled", observability.CaptureSnapshot{ObservedAt: time.Now().UTC()}, observability.CaptureSnapshot{ObservedAt: time.Now().UTC()}, false)
	if err := observability.SaveRuntimeCapture(s.DB, s.Paths, &r); err != nil {
		t.Fatal(err)
	}
	capture := read()["capture"].(map[string]any)
	if capture["status"] != "disabled" || capture["kernel_state"] != "disabled" || capture["ref"] != r.Ref || capture["run_dropped_events"] != nil {
		t.Fatalf("disabled contract: %+v", capture)
	}
}
