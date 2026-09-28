package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/hooksbridge"
	"github.com/byteyellow/agentprovenance/internal/provenance"
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

func TestContextDashboardLayoutAndAssets(t *testing.T) {
	h := Server{}.Handler()
	for _, lang := range []string{"en", "zh-CN"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/?lang="+lang, nil))
		body := w.Body.String()
		last := -1
		for _, id := range []string{"runoverview", "graphcard", "focusedevidence", "savedcontent", "agentcontext", "outboundcard", "compliancecard"} {
			index := strings.Index(body, `id="`+id+`"`)
			if index <= last {
				t.Errorf("%s: layout order or component missing: %s", lang, id)
			}
			last = index
		}
		if !strings.Contains(body, `<details id="context-fold">`) {
			t.Fatal("agent session must start collapsed")
		}
		for _, id := range []string{"playbtn", "lenssel", "detailsel", "evtbl", "siglist", "tl", "ptree", "egtbl", "content-dialog", "context-nav-count", "context-nav-tools", "context-nav-files", "context-nav-config", "context-nav-coverage"} {
			if !strings.Contains(body, `id="`+id+`"`) {
				t.Fatalf("existing component missing: %s", id)
			}
		}
	}
	for path, mime := range map[string]string{"/assets/context.js": "application/javascript", "/assets/context.css": "text/css"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 || w.Body.Len() < 100 || !strings.Contains(w.Header().Get("Content-Type"), mime) {
			t.Fatalf("asset: %s %d", path, w.Code)
		}
	}
}

// The optional output is a synthetic browser-test store, never a real demo.
// Normal test runs use an isolated temporary directory.
func TestContextDashboardFixture(t *testing.T) {
	root := os.Getenv("AGENTPROV_UI_FIXTURE_DIR")
	if root == "" {
		root = filepath.Join(t.TempDir(), "store")
	} else if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("browser fixture output must not already exist")
	}
	paths, err := store.Init(root)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	s := agentcontext.Service{DB: db, Paths: paths}
	body := func(text string) *string { return &text }
	records := []agentcontext.Record{
		{Key: "task", Sequence: 1, Kind: "message", Role: "user", RecordedAt: "2026-09-28T09:00:00Z", Body: body("Synthetic UI fixture: inspect a report, do not access credentials. No real agent was executed."), RawBody: body(`{"fixture":true,"type":"user"}`)},
		{Key: "config-a", Sequence: 2, Kind: "configuration", Status: "session_metadata", RecordedAt: "2026-09-28T09:00:01Z", Body: body(`{"model":"fixture-model","sandbox":"read-only","approval":"on-request","cwd":"/fixture","skills":[],"plugins":null}`)},
		{Key: "tool", Sequence: 3, Kind: "tool_call", ToolCallID: "native-call", ToolName: "exec_command", RecordedAt: "2026-09-28T09:00:02Z", Body: body(`{"cmd":"python3 report.py"}`), RawBody: body(`{"fixture":true,"type":"tool_call","arguments":{"cmd":"python3 report.py"}}`)},
		{Key: "result", Sequence: 4, Kind: "tool_result", ToolCallID: "native-call", ToolName: "exec_command", Status: "error", RecordedAt: "2026-09-28T09:00:03Z", Body: body("SAVED-OUTPUT-START\n" + strings.Repeat("bounded fixture output\n", 3300) + "SAVED-OUTPUT-TAIL"), RawBody: body(`{"fixture":true,"type":"tool_result","error":true}`)},
		{Key: "config-b", Sequence: 5, Kind: "configuration", RecordedAt: "2026-09-28T09:00:04Z", Body: body(`{"model":"fixture-model","sandbox":"workspace-write","cwd":"/fixture","skills":[]}`)},
	}
	for i := 0; i < 37; i++ {
		records = append(records, agentcontext.Record{Key: fmt.Sprintf("message-%d", i), Sequence: int64(i + 6), Kind: "message", Role: "assistant", Body: body(fmt.Sprintf("Synthetic follow-up %d. <img src=x onerror=alert(1)> is recorded text, not HTML.", i))})
	}
	records[5].Status = "source_message_event"
	for i := range records {
		records[i].ExecutionScope = agentcontext.CurrentExecution
		if records[i].Sequence <= 2 {
			records[i].ExecutionScope = agentcontext.PriorContext
		}
	}
	source := agentcontext.Source{ID: "ui-fixture-source", Harness: "codex", Channel: "transcript", SessionID: "ui-fixture-session", Binding: "explicit", ParserVersion: "synthetic-ui-fixture/v1", Workdir: "/fixture"}
	_, err = s.Save(ctx, "ui-fixture", source, records, agentcontext.Coverage{Status: agentcontext.OK,
		FirstLine: 3, LastLine: 42,
		MissingFields: []string{"approval", "approval_decision", "configuration.mcp_servers", "configuration.network_restrictions", "configuration.change_history_completeness"},
		Counts:        agentcontext.Counts{Read: agentcontext.Number(40), Parsed: agentcontext.Number(40), Matched: agentcontext.Number(1)},
		PriorContext: &agentcontext.PriorRange{FirstLine: 1, LastLine: 2, MissingFields: []string{"approval"},
			Counts: agentcontext.Counts{Read: agentcontext.Number(2), Parsed: agentcontext.Number(2)}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hooksbridge.IngestContext(ctx, db, paths, "ui-fixture"); err != nil {
		t.Fatal(err)
	}
	h := Server{DB: db}.Handler()
	for _, path := range []string{"/api/context/overview?run=ui-fixture", "/api/context/entries?run=ui-fixture&group=conversation", "/api/context/entries?run=ui-fixture&group=configuration", "/api/lens?run=ui-fixture&lens=default&detail=raw"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 || !json.Valid(w.Body.Bytes()) {
			t.Fatalf("fixture route failed: %s: %d %s", path, w.Code, w.Body.String())
		}
	}
	v, err := provenance.Verify(db, "ui-fixture")
	if err != nil || v.ErrorCount != 0 {
		t.Fatalf("fixture evidence invalid: %+v %v", v, err)
	}
	addContextProtocolFixtures(t, s)
}

func addContextProtocolFixtures(t *testing.T, s agentcontext.Service) {
	t.Helper()
	ctx := context.Background()
	for _, fixture := range []struct{ run, harness, input string }{
		{"ui-deepseek-protocol", "deepseek", `{"type":"session","version":4,"id":"synthetic-dsh"}
{"type":"assistant/message","seq":0,"time":1790548590000,"data":{"message":{"role":"assistant","content":[{"type":"tool-call","id":"proposal","name":"run_shell","arguments":"{\"command\":\"true\"}"}]}}}
{"type":"tool/ptc-dispatch-start","seq":1,"time":1790548591000,"data":{"subCallId":"sub","rootCallId":"root","parentCallId":"parent","name":"read_file","arguments":{"path":"report.py"}}}
{"type":"tool/ptc-dispatch","seq":2,"time":1790548592000,"data":{"subCallId":"sub","rootCallId":"root","parentCallId":"parent","name":"read_file","arguments":{"path":"report.py"},"isError":true,"content":[{"type":"text","text":"not found"}]}}
{"type":"tool/result","seq":3,"time":1790548593000,"surfaceOp":{"op":"replace","startSeq":2,"endSeq":2},"sourceEventSeqs":[2],"data":{"message":{"toolCallId":"sub","content":[{"type":"text","text":"compacted result"}]}}}
{"type":"tool/ptc-dispatch","seq":4,"time":1790548594000,"data":{"subCallId":"orphan","rootCallId":"root","parentCallId":"parent","name":"read_file","arguments":{"path":"notes.md"},"content":[{"type":"text","text":"notes"}]}}
`},
		{"ui-claude-compound", "claude", `{"type":"user","sessionId":"synthetic-claude","message":{"content":"COMPOUND-FIRST"}}` + "\x00" + `{"type":"assistant","sessionId":"synthetic-claude","message":{"content":"COMPOUND-SECOND"}}` + "\n"},
	} {
		parsed, err := agentcontext.Parse(ctx, strings.NewReader(fixture.input), agentcontext.ParseOptions{Harness: fixture.harness, Binding: "explicit"})
		if err != nil || parsed.Coverage.Status != agentcontext.OK {
			t.Fatalf("protocol fixture parse: %+v %v", parsed, err)
		}
		if _, err := s.Save(ctx, fixture.run, parsed.Source, parsed.Records, parsed.Coverage); err != nil {
			t.Fatal(err)
		}
		if _, err := hooksbridge.IngestContext(ctx, s.DB, s.Paths, fixture.run); err != nil {
			t.Fatal(err)
		}
		verified, err := provenance.Verify(s.DB, fixture.run)
		if err != nil || verified.ErrorCount != 0 {
			t.Fatalf("protocol fixture graph: %+v %v", verified, err)
		}
	}
}
