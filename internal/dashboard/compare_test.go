package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/hooksbridge"
	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func addComparisonFixture(t *testing.T, s agentcontext.Service) {
	t.Helper()
	for _, variant := range []string{"a", "b"} {
		run := "ui-compare-" + variant
		task, command := "Summarize the synthetic fixture repository.", `{"cmd":"python3 report.py"}`
		config := `{"model":"fixture-model","network_access":false,"permissions":null,"plugins":[],"large_number":9007199254740993}`
		if variant == "b" {
			config = `{"model":"fixture-model-b","network_access":true,"plugins":[],"large_number":9007199254740993}`
		}
		src := agentcontext.Source{ID: run + "-source", Harness: "codex", SessionID: "compare-" + variant, Channel: "transcript", Binding: "explicit", ParserVersion: "synthetic-compare-fixture/v1"}
		past := `{"past_only":"not-executed-here"}`
		records := []agentcontext.Record{
			{Key: "task", Sequence: 1, Kind: "message", Role: "user", Body: &task, RecordedAt: "2026-10-18T00:00:00Z", ExecutionScope: agentcontext.CurrentExecution},
			{Key: "configuration", Sequence: 2, Kind: "configuration", Body: &config, RawBody: &config, ExecutionScope: agentcontext.CurrentExecution},
			{Key: "prior", Sequence: 3, Kind: "configuration", Body: &past, ExecutionScope: agentcontext.PriorContext},
			{Key: "tool", Sequence: 4, Kind: "tool_call", ToolCallID: run + "-call", ToolName: "exec_command", Body: &command, ExecutionScope: agentcontext.CurrentExecution},
		}
		if _, err := s.Save(context.Background(), run, src, records, agentcontext.Coverage{Status: agentcontext.OK, PriorContext: &agentcontext.PriorRange{FirstLine: 3, LastLine: 3}, MissingFields: []string{"configuration.change_history_completeness"}}); err != nil {
			t.Fatal(err)
		}
		if _, err := hooksbridge.IngestContext(context.Background(), s.DB, s.Paths, run); err != nil {
			t.Fatal(err)
		}
		objects := provenance.ObjectStore{DB: s.DB, Paths: s.Paths}
		putArtifact(t, objects, run, "workspace_file/report.txt", map[string]any{"path": "report.txt", "content": "Synthetic file " + variant + "\n<img src=x onerror=alert(1)>"})
		for _, event := range []struct{ id, kind, source, payload string }{
			{"open", "file_open", "agentprov_ebpf", `{"raw":{"path":"/fixture/report.txt","mode":"read"}}`},
			{"write", "file_write", "agentprov_ebpf", `{"path":"/fixture/report.txt","mode":"write"}`},
			{"diff", "file_write", "record_file_diff", `{"path":"report.txt","op":"record_diff","content_state":"stored"}`},
			{"net", "network_connect", "agentprov_ebpf", `{"dst_ip":"192.0.2.1","port":443}`},
			{"tls", "tls_write", "agentprov_ebpf", `{"http":{"host":"api.fixture.example","path":"/responses","method":"POST","protocol":"h2"}}`},
			{"response", "tls_read", "agentprov_ebpf", `{"http":{"status":200,"protocol":"h2"}}`},
		} {
			if _, err := s.DB.Exec(`INSERT INTO events(id,run_id,source,event_type,payload,created_at) VALUES(?,?,?,?,?,?)`, run+"-"+event.id, run, event.source, event.kind, event.payload, "2026-10-18T00:00:02Z"); err != nil {
				t.Fatal(err)
			}
		}
		if variant == "b" {
			if _, err := s.DB.Exec(`INSERT INTO events(id,run_id,source,event_type,payload,created_at) VALUES(?,?,'endpoint_capture','network_connect',?,'2026-10-18T00:00:03Z')`, run+"-extra", run, `{"host":"api.mixpanel.com","path":"/track","egress_kind":"analytics","bytes":512}`); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := objects.MaterializeRun(run); err != nil {
			t.Fatal(err)
		}
	}
}

func readComparison(t *testing.T, server Server, run string) ComparisonPage {
	t.Helper()
	result := ComparisonPage{}
	cursor := ""
	for count := 0; count < 1000; count++ {
		page, err := server.ComparisonRecords(context.Background(), run, cursor)
		if err != nil {
			t.Fatal(err)
		}
		result.Records = append(result.Records, page.Records...)
		result.Issues = append(result.Issues, page.Issues...)
		result.SourcesRead += page.SourcesRead
		if !page.HasMore {
			return result
		}
		if page.NextCursor == cursor {
			t.Fatal("cursor did not advance")
		}
		cursor = page.NextCursor
	}
	t.Fatal("pagination did not finish")
	return result
}

func TestComparisonRecordsSemanticsAndScope(t *testing.T) {
	paths, db, _ := artifactStore(t)
	addComparisonFixture(t, agentcontext.Service{DB: db, Paths: paths})
	db.SetMaxOpenConns(1)
	server := Server{DB: db}
	a, b := readComparison(t, server, "ui-compare-a"), readComparison(t, server, "ui-compare-b")
	find := func(page ComparisonPage, operation, label string) ComparisonRecord {
		t.Helper()
		for _, r := range page.Records {
			if r.Operation == operation && r.Label == label {
				return r
			}
		}
		t.Fatalf("missing %s %s", operation, label)
		return ComparisonRecord{}
	}
	config := find(a, "recorded_configuration", "codex · /network_access")
	if config.Value.Preview != "false" {
		t.Fatalf("false became absent: %+v", config)
	}
	if find(a, "recorded_configuration", "codex · /permissions").Value.Preview != "null" {
		t.Fatal("null became absent")
	}
	if find(a, "recorded_configuration", "codex · /large_number").Value.Preview != "9007199254740993" {
		t.Fatal("integer precision lost")
	}
	if find(a, "saved_file_version", "report.txt").Value.SHA256 == find(b, "saved_file_version", "report.txt").Value.SHA256 {
		t.Fatal("different file bodies compared equal")
	}
	for _, op := range []string{"file_open", "file_write"} {
		find(a, op, "/fixture/report.txt")
	}
	find(a, "recorded_file_change", "report.txt")
	find(a, "connection_attempt", "192.0.2.1:443")
	find(a, "http_request_observed", "api.fixture.example/responses")
	response := find(a, "http_response_observed", "unknown")
	if response.Value == nil || !response.Partial || !strings.Contains(response.Value.Preview, `"status":200`) || strings.Contains(response.Label, "fixture.example") {
		t.Fatal("response lost its status or borrowed a request target")
	}
	analytics := find(b, "product_analytics", "api.mixpanel.com/track")
	if !strings.Contains(analytics.Value.Preview, "payload_observed") {
		t.Fatal("captured payload lost")
	}
	for _, r := range a.Records {
		if strings.Contains(r.Label, "past_only") || strings.Contains(r.Label, "mixpanel") {
			t.Fatalf("foreign/prior data included: %+v", r)
		}
		if r.Evidence.Entry != nil && r.Evidence.Entry.RunID != "ui-compare-a" {
			t.Fatal("foreign context included")
		}
	}
	for _, query := range []string{"run=ui-compare-a&session=compare-a", "run=ui-compare-a&cursor=bad", ""} {
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/compare/records?"+query, nil))
		if w.Code != 400 {
			t.Fatalf("invalid scope accepted: %s %d", query, w.Code)
		}
	}
}

func TestComparisonPaginationFailuresAndUnknowns(t *testing.T) {
	paths, db, objects := artifactStore(t)
	s := agentcontext.Service{DB: db, Paths: paths}
	missing := agentcontext.Record{Key: "missing", Kind: "configuration", MissingReason: "not_recorded"}
	if _, err := s.Save(context.Background(), "paged", agentcontext.Source{ID: "s", Harness: "codex", SessionID: "native", Binding: "explicit", ParserVersion: "fixture"}, []agentcontext.Record{missing}, agentcontext.Coverage{Status: agentcontext.Partial}); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 107; n++ {
		if _, err := db.Exec(`INSERT INTO events(id,run_id,source,event_type,payload,created_at) VALUES(?,'paged','fixture','network_connect',?,'2026-10-18T00:00:02Z')`, fmt.Sprintf("e-%03d", n), fmt.Sprintf(`{"host":"host-%d.example","port":443}`, n)); err != nil {
			t.Fatal(err)
		}
	}
	putArtifact(t, objects, "paged", "workspace_file/empty.txt", map[string]any{"path": "empty.txt", "content": ""})
	putArtifact(t, objects, "paged", "workspace_file/missing.txt", map[string]any{"path": "missing.txt", "content_state": "omitted"})
	server := Server{DB: db}
	all := readComparison(t, server, "paged")
	connections, unknowns := 0, 0
	for _, r := range all.Records {
		if r.Operation == "connection_attempt" {
			connections++
		}
		if r.Value == nil {
			unknowns++
		}
		if r.Label == "empty.txt" && r.Value == nil {
			t.Fatal("empty file treated as missing")
		}
	}
	if connections != 107 || unknowns != 2 {
		t.Fatalf("lost paged records: connections=%d unknown=%d", connections, unknowns)
	}
	first, err := server.ComparisonRecords(context.Background(), "paged", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = server.ComparisonRecords(context.Background(), "other", first.NextCursor); err == nil {
		t.Fatal("foreign cursor accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = server.ComparisonRecords(ctx, "paged", ""); err == nil {
		t.Fatal("cancellation ignored")
	}
	db.Close()
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/compare/records?run=paged", nil))
	if w.Code != 500 {
		t.Fatalf("database error became absence: %d", w.Code)
	}
	var value any
	if decodeComparisonJSON([]byte(`{} {}`), &value) == nil {
		t.Fatal("trailing JSON accepted")
	}
	b, _ := json.Marshal(all)
	if strings.Contains(string(b), "onerror=") {
		t.Fatal("file body duplicated in comparison projection")
	}
}
