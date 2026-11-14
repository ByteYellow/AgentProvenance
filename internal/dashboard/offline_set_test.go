package dashboard

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
)

func replaySetFixture(t *testing.T) Server {
	t.Helper()
	paths, db, objects := artifactStore(t)
	service := agentcontext.Service{DB: db, Paths: paths}
	for _, run := range []string{"origin-run", "remote-run", "private-run"} {
		for _, session := range []string{"selected", "private"} {
			body := run + "-" + session + "-MESSAGE"
			command := `{"cmd":"cat report.py","note":"` + run + "-" + session + `-TOOL </script><script>globalThis.evidenceExecuted=true</script>"}`
			_, err := service.Save(context.Background(), run, agentcontext.Source{
				Harness: "codex", SessionID: run + "-" + session, ParserVersion: "fixture/v1", Binding: "explicit",
			}, []agentcontext.Record{
				{Key: "message", Sequence: 1, Kind: "message", Role: "user", Body: &body},
				{Key: "tool", Sequence: 2, Kind: "tool_call", ToolCallID: run + "-" + session + "-call", ToolName: "exec_command", Body: &command},
			}, agentcontext.Coverage{Status: agentcontext.OK})
			if err != nil {
				t.Fatal(err)
			}
		}
		putArtifact(t, objects, run, "workspace_file/report.py", map[string]any{"content": run + "-FILE"})
		if _, err := db.Exec(`INSERT INTO events(id,run_id,source,event_type,payload,created_at)
			VALUES (?,?,'synthetic_fixture','file_read',?,'2026-11-14T00:00:00Z')`, run+"-event", run,
			`{"path":"/fixture/report.py","note":"`+run+`-EVENT"}`); err != nil {
			t.Fatal(err)
		}
	}
	return Server{DB: db, RunLabels: map[string]string{"origin-run": "Caller", "remote-run": "Worker", "private-run": "PRIVATE-TITLE"}}
}

func TestOfflineReplaySetSelectionsAndFrozenSnapshot(t *testing.T) {
	server := replaySetFixture(t)
	ctx := context.Background()
	inputs := []ReplaySelection{
		{RunID: "origin-run", Scope: "session", Harness: "codex", SessionID: "origin-run-selected"},
		{RunID: "remote-run", Scope: "whole_run", ExcludeCategories: []string{"messages"}},
	}
	snapshot, err := server.freezeReplaySource(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	// A write after the shared freeze cannot appear in just one member of the set.
	for _, run := range []string{"origin-run", "remote-run"} {
		if _, err := server.DB.Exec(`INSERT INTO events(id,run_id,source,event_type,payload,created_at)
			VALUES (?,?,'synthetic_fixture','exec','{"note":"AFTER-FREEZE"}','2026-11-14T00:01:00Z')`, run+"-late", run); err != nil {
			t.Fatal(err)
		}
	}
	p, err := server.prepareReplaySet(ctx, snapshot, inputs)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if p.Inventory.Scope != "run_set" || p.Inventory.RunID != "origin-run" || p.Inventory.Events != 1 || p.Inventory.Signed || len(p.Inventory.Runs) != 2 || p.Inventory.SelectionSummary != nil {
		t.Fatalf("set inventory: %+v", p.Inventory)
	}
	files, all := replayZIPData(t, p)
	for _, marker := range []string{"origin-run-selected-MESSAGE", "origin-run-selected-TOOL", "remote-run-selected-TOOL", "remote-run-private-TOOL", "remote-run-FILE", "remote-run-EVENT"} {
		if !strings.Contains(all, marker) {
			t.Errorf("selected record missing: %s", marker)
		}
	}
	for _, marker := range []string{"origin-run-private-MESSAGE", "origin-run-private-TOOL", "origin-run-FILE", "origin-run-EVENT", "remote-run-selected-MESSAGE", "remote-run-private-MESSAGE", "private-run", "PRIVATE-TITLE", "AFTER-FREEZE"} {
		if strings.Contains(all, marker) {
			t.Errorf("unselected data leaked: %s", marker)
		}
	}
	var master struct {
		SchemaVersion string               `json:"schema_version"`
		Runs          []ReplayRunInventory `json:"runs"`
	}
	if err := json.Unmarshal(files[p.Inventory.Selection.Path], &master); err != nil {
		t.Fatal(err)
	}
	actual, err := json.Marshal(master.Runs)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := json.Marshal(p.Inventory.Runs)
	if err != nil {
		t.Fatal(err)
	}
	if master.SchemaVersion != "agentprovenance.replay_selection_set/v1" || string(actual) != string(expected) {
		t.Fatalf("selection set: %+v", master)
	}
	totals := ReplayContents{Sources: map[string]int{}}
	for i, item := range p.Inventory.Runs {
		var selected struct {
			Selection ReplaySelection        `json:"selection"`
			Records   []replayRecordDecision `json:"records"`
		}
		data := files[item.Selection.Path]
		if item.RunID != inputs[i].RunID || item.Scope != inputs[i].Scope || replayDigest(data) != item.Selection.SHA256 || int64(len(data)) != item.Selection.Bytes {
			t.Fatalf("per-run selection: %+v", item)
		}
		if err := json.Unmarshal(data, &selected); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(selected.Selection, inputs[i]) {
			t.Fatalf("run selection changed: %+v", selected.Selection)
		}
		included := 0
		for _, record := range selected.Records {
			if record.Included {
				included++
			}
		}
		if included != item.SelectionSummary.Included || len(selected.Records)-included != item.SelectionSummary.Excluded {
			t.Fatal("per-run counts disagree with record selection")
		}
		totals.add(item.Contents)
	}
	if !reflect.DeepEqual(totals, p.Inventory.Contents) {
		t.Fatal("aggregate content counts differ from per-run sums")
	}
	for _, lang := range []string{"en", "zh-CN"} {
		if !strings.Contains(string(files[lang+"/index.html"]), "agentprov-replay-selection") {
			t.Fatal("mixed selection must retain the partial-export reading label")
		}
	}
	writeReplaySetFixture(t, "selected.zip", p)
	// The source connection is unnecessary once the private artifact is prepared.
	if err := server.DB.Close(); err != nil {
		t.Fatal(err)
	}
	_, after := replayZIPData(t, p)
	if after != all {
		t.Fatal("download changed after source database closed")
	}
}

func TestOfflineReplaySetWholeRuns(t *testing.T) {
	server := replaySetFixture(t)
	p, err := server.PrepareOfflineReplaySet(context.Background(), []ReplaySelection{
		{RunID: "origin-run", Scope: "whole_run"}, {RunID: "remote-run", Scope: "whole_run"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	_, all := replayZIPData(t, p)
	if p.Inventory.Events != 2 || p.Inventory.Contents.Sessions != 4 || strings.Contains(all, "private-run") {
		t.Fatalf("whole-run set inventory: %+v", p.Inventory)
	}
	for _, run := range []string{"origin-run", "remote-run"} {
		for _, suffix := range []string{"-selected-MESSAGE", "-private-MESSAGE", "-selected-TOOL", "-private-TOOL", "-FILE", "-EVENT"} {
			if !strings.Contains(all, run+suffix) {
				t.Errorf("whole-run content missing: %s", run+suffix)
			}
		}
	}
	writeReplaySetFixture(t, "whole.zip", p)
}

func writeReplaySetFixture(t *testing.T, name string, p *PreparedReplay) {
	t.Helper()
	root := os.Getenv("AGENTPROV_TEST_REPLAY_SET_DIR")
	if root == "" {
		return
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(root, name))
	if err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(p.WriteZIP(context.Background(), f), f.Close()); err != nil {
		t.Fatal(err)
	}
}

func TestOfflineReplaySetRejectsInvalidSelections(t *testing.T) {
	server := replaySetFixture(t)
	exports := NewReplayExports(server)
	defer exports.Close()
	server.ReplayExports = exports
	h := server.Handler()
	one := `{"run_id":"origin-run","scope":"whole_run"}`
	for _, input := range []string{
		`{"selections":[]}`, `{"selections":null}`, `{"selections":[` + one + `,` + one + `]}`,
		`{"run":"origin-run","scope":"whole_run","selections":null}`,
		`{"selections":[` + one + `],"run":""}`, `{"selections":[` + one + `],"exclude_records":[]}`,
		`{"selections":[{"run_id":"origin-run","scope":"session"}]}`,
		`{"selections":[{"run_id":"origin-run","scope":"whole_run","extra":"ignored"}]}`,
	} {
		w := previewCall(h, "POST", "/api/replay/previews", input)
		if w.Code != http.StatusBadRequest || exports.active {
			t.Fatalf("invalid set left an active preview: %s HTTP %d %s", input, w.Code, w.Body.String())
		}
	}
	tooMany := make([]ReplaySelection, maxReplayRuns+1)
	for i := range tooMany {
		tooMany[i] = ReplaySelection{RunID: fmt.Sprintf("run-%d", i), Scope: "whole_run"}
	}
	if _, err := server.PrepareOfflineReplaySet(context.Background(), tooMany); !errors.Is(err, agentcontext.ErrInvalidArgument) {
		t.Fatalf("set resource limit: %v", err)
	}
	w := previewCall(h, "POST", "/api/replay/previews", `{"selections":[`+one+`,{"run_id":"missing","scope":"whole_run"}]}`)
	if w.Code != http.StatusNotFound || exports.active {
		t.Fatalf("incomplete set was published: HTTP %d %s", w.Code, w.Body.String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := server.PrepareOfflineReplaySet(ctx, []ReplaySelection{{RunID: "origin-run", Scope: "whole_run"}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled set preparation: %v", err)
	}
}

func TestReplayPreviewExplicitRunSet(t *testing.T) {
	server := replaySetFixture(t)
	exports := NewReplayExports(server)
	t.Cleanup(exports.Close)
	server.ReplayExports = exports
	h := server.Handler()
	w := previewCall(h, http.MethodPost, "/api/replay/previews", `{"selections":[
		{"run_id":"origin-run","scope":"session","harness":"codex","session_id":"origin-run-selected"},
		{"run_id":"remote-run","scope":"whole_run","exclude_categories":["messages"]}]}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("explicit two-run preparation: HTTP %d: %s", w.Code, w.Body.String())
	}
	if root := os.Getenv("AGENTPROV_TEST_REPLAY_SET_DIR"); root != "" {
		if err := os.MkdirAll(root, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "preview.json"), w.Body.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var preview replayPreview
	if err := json.Unmarshal(w.Body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	job := exports.acquire(preview.ID)
	if job == nil {
		t.Fatal("prepared replay missing")
	}
	defer exports.release(job)
	raw, err := os.ReadFile(filepath.Join(job.prepared.root, "assets/catalog.js"))
	if err != nil {
		t.Fatal(err)
	}
	encoded := strings.TrimSuffix(strings.TrimPrefix(string(raw), `window.AgentProvOfflineCatalog="`), `";`)
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var catalog struct {
		Summaries []runSummary         `json:"summaries"`
		Runs      map[string]ReplayRun `json:"runs"`
	}
	if err := json.Unmarshal(data, &catalog); err != nil {
		t.Fatal(err)
	}
	if len(catalog.Runs) != 2 || len(catalog.Summaries) != 2 ||
		!reflect.DeepEqual([]string{catalog.Summaries[0].Run, catalog.Summaries[1].Run}, []string{"origin-run", "remote-run"}) {
		t.Fatalf("selected catalog: %s", data)
	}
	if len(catalog.Runs["origin-run"].Sessions) != 1 || len(catalog.Runs["remote-run"].Sessions) != 2 {
		t.Fatalf("independent session scopes: %+v", catalog.Runs)
	}
	response := previewCall(h, http.MethodGet, "/api/replay/previews/"+preview.ID+"/download?inventory="+preview.InventorySHA256, "")
	if response.Code != http.StatusOK || replayDigest(response.Body.Bytes()) != preview.ZIPSHA256 {
		t.Fatalf("frozen multi-run ZIP: HTTP %d", response.Code)
	}
}
