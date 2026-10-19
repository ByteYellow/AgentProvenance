package dashboard

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/i18n"
)

func TestOfflineReplayFreezesOneRunAndSavedContent(t *testing.T) {
	paths, db, objects := artifactStore(t)
	svc := agentcontext.Service{DB: db, Paths: paths}
	ctx := context.Background()
	text := func(s string) *string { return &s }
	for _, run := range []string{"selected-run", "other-run"} {
		_, err := svc.Save(ctx, run, agentcontext.Source{ID: run + "-source", Harness: "codex", SessionID: run + "-session", ParserVersion: "fixture/v1", Binding: "explicit"}, []agentcontext.Record{
			{Key: "message", Sequence: 1, Kind: "message", Role: "user", Body: text(run + `-MESSAGE </script><script>globalThis.evidenceExecuted=true</script>`), RawBody: text(run + "-RAW")},
		}, agentcontext.Coverage{Status: agentcontext.OK})
		if err != nil {
			t.Fatal(err)
		}
		putArtifact(t, objects, run, "workspace_file/output.txt", map[string]any{"content": run + "-FILE"})
		if _, err = db.Exec(`INSERT INTO events (id,run_id,source,event_type,created_at,payload) VALUES (?,?,'fixture', 'file_read','2026-10-18T00:00:00Z',?)`, run+"-event", run, `{"path":"/saved/output.txt","note":"`+run+`-EVENT"}`); err != nil {
			t.Fatal(err)
		}
	}
	currentFile := filepath.Join(t.TempDir(), "live.txt")
	if err := os.WriteFile(currentFile, []byte("CURRENT-WORKSPACE-MUST-NOT-LEAK"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tool_calls (id,run_id,status,result_ref,created_at) VALUES ('unsaved-tool','selected-run','completed',?,'2026-10-18T00:00:01Z')`, currentFile); err != nil {
		t.Fatal(err)
	}
	p, err := (Server{DB: db, RunLabels: map[string]string{
		"selected-run": "Diagnostic repair: before", "other-run": "EXCLUDED-RUN-TITLE",
	}}).PrepareOfflineReplay(ctx, "selected-run")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if p.Inventory.RunID != "selected-run" || p.Inventory.Scope != "whole_run" || p.Inventory.Signed || p.Inventory.Events != 1 {
		t.Fatalf("inventory: %+v", p.Inventory)
	}
	// Neither later database writes nor removal of original content affects the
	// prepared artifact. No source files are needed at download time.
	if _, err = db.Exec(`INSERT INTO events (id,run_id,source,event_type,created_at,payload) VALUES ('late','selected-run','fixture','exec','2026-10-18T01:00:00Z','{"note":"LATE-EVENT-MUST-NOT-LEAK"}')`); err != nil {
		t.Fatal(err)
	}
	if err = os.RemoveAll(paths.Provenance); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err = p.WriteZIP(ctx, &output); err != nil {
		t.Fatal(err)
	}
	z, err := zip.NewReader(bytes.NewReader(output.Bytes()), int64(output.Len()))
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]ReplayFile{}
	for _, f := range p.Inventory.Files {
		expected[f.Path] = f
	}
	if len(z.File) != len(expected)+1 {
		t.Fatalf("unexpected ZIP members: %d != %d", len(z.File), len(expected)+1)
	}
	var evidence bytes.Buffer
	var selectedRecords []replayRecordDecision
	for _, f := range z.File {
		reader, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte("EXCLUDED-RUN-TITLE")) {
			t.Fatal("excluded run title leaked into replay")
		}
		if (f.Name == "en/index.html" || f.Name == "zh-CN/index.html") && !bytes.Contains(data, []byte("Diagnostic repair: before")) {
			t.Fatal("selected run title missing from replay")
		}
		if f.Name == "export-inventory.json" {
			if replayDigest(data) != p.InventorySHA256 {
				t.Fatal("inventory digest mismatch")
			}
		} else if want, ok := expected[f.Name]; !ok || want.SHA256 != replayDigest(data) || want.Bytes != int64(len(data)) {
			t.Fatalf("file differs from frozen inventory: %s", f.Name)
		}
		if f.Name == p.Inventory.Selection.Path {
			if p.Inventory.Selection.SHA256 != replayDigest(data) || p.Inventory.Selection.Bytes != int64(len(data)) {
				t.Fatal("record selection differs from inventory")
			}
			var manifest struct {
				SchemaVersion string                 `json:"schema_version"`
				Selection     ReplaySelection        `json:"selection"`
				Records       []replayRecordDecision `json:"records"`
			}
			if err := json.Unmarshal(data, &manifest); err != nil {
				t.Fatal(err)
			}
			if manifest.SchemaVersion != "agentprovenance.replay_selection/v1" || manifest.Selection.Scope != "whole_run" || manifest.Selection.RunID != "selected-run" {
				t.Fatalf("record selection: %+v", manifest)
			}
			selectedRecords = manifest.Records
			summary := p.Inventory.SelectionSummary
			if summary == nil || summary.Selection.RunID != manifest.Selection.RunID || summary.Included != len(selectedRecords) || summary.Excluded != 0 {
				t.Fatalf("selection summary differs from frozen manifest: %+v", summary)
			}
			for _, r := range selectedRecords {
				if !r.Included || strings.Contains(r.ID, "other-run") || r.ID == "3/late" {
					t.Fatalf("unexpected selected record: %+v", r)
				}
			}
		}
		if strings.HasPrefix(f.Name, "data/") {
			prefix := `window.AgentProvOffline.accept("` + strings.TrimSuffix(f.Name, ".js") + `.json.gz","`
			if !bytes.HasPrefix(data, []byte(prefix)) || !bytes.HasSuffix(data, []byte(`");`)) {
				t.Fatalf("unexpected shard wrapper: %s", f.Name)
			}
			compressed, err := base64.StdEncoding.DecodeString(string(data[len(prefix) : len(data)-3]))
			if err != nil {
				t.Fatal(err)
			}
			gz, err := gzip.NewReader(bytes.NewReader(compressed))
			if err != nil {
				t.Fatal(err)
			}
			plain, err := io.ReadAll(gz)
			gz.Close()
			if err != nil || !json.Valid(plain) {
				t.Fatalf("invalid evidence shard: %v", err)
			}
			evidence.Write(plain)
		}
		if strings.HasSuffix(f.Name, ".db") || strings.HasSuffix(f.Name, ".forensics.json.gz") || strings.HasSuffix(f.Name, ".json.gz") {
			t.Fatalf("extra source data packaged: %s", f.Name)
		}
	}
	if len(selectedRecords) != 4 {
		t.Fatalf("record manifest: got %d, want one entry, file, tool and event", len(selectedRecords))
	}
	for _, marker := range []string{"selected-run-MESSAGE", "selected-run-RAW", "selected-run-FILE", "selected-run-EVENT", "legacy_not_recorded"} {
		if !strings.Contains(evidence.String(), marker) {
			t.Errorf("saved evidence missing: %s", marker)
		}
	}
	for _, marker := range []string{"other-run-MESSAGE", "other-run-RAW", "other-run-FILE", "other-run-EVENT", "CURRENT-WORKSPACE-MUST-NOT-LEAK", "LATE-EVENT-MUST-NOT-LEAK"} {
		if strings.Contains(evidence.String(), marker) {
			t.Errorf("unselected content included: %s", marker)
		}
	}
	// The preview returned to a caller is not the download's mutable file list.
	original := p.Inventory.Files[0]
	p.Inventory.Files[0] = ReplayFile{Path: "caller-supplied-file"}
	if err = p.WriteZIP(ctx, io.Discard); err != nil {
		t.Fatalf("preview mutation altered frozen package: %v", err)
	}
	p.Inventory.Files[0] = original
	if err = os.WriteFile(filepath.Join(p.root, p.Inventory.Files[0].Path), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = p.WriteZIP(ctx, io.Discard); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("changed prepared file accepted: %v", err)
	}
}

func TestOfflineReplayRejectsUnknownRunAndCancellation(t *testing.T) {
	_, db, _ := artifactStore(t)
	server := Server{DB: db}
	if _, err := server.PrepareOfflineReplay(context.Background(), "missing"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unknown run: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := server.PrepareOfflineReplay(ctx, "run"); err == nil {
		t.Fatal("canceled preparation succeeded")
	}
}

func TestOfflineReplayHTMLUsesOnlyLocalResources(t *testing.T) {
	for _, locale := range []i18n.Locale{i18n.English, i18n.Chinese} {
		w := httptest.NewRecorder()
		Server{}.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/?lang="+string(locale), nil))
		out, err := offlineReplayHTML(w.Body.Bytes(), locale)
		if err != nil {
			t.Fatal(err)
		}
		s := string(out)
		last := -1
		for _, part := range []string{"Content-Security-Policy", "../assets/catalog.js", "../assets/offline.js", "../assets/replay.js", "../assets/i18n." + string(locale) + ".js", "window.AgentWorkspaceUI"} {
			at := strings.Index(s, part)
			if at <= last {
				t.Fatalf("missing/out-of-order resource: %s", part)
			}
			last = at
		}
		for _, forbidden := range []string{`src="/`, `href="/`, `src="https:`, `src="http:`, `href="https:`} {
			if strings.Contains(s, forbidden) {
				t.Fatalf("non-portable resource: %s", forbidden)
			}
		}
		if !strings.Contains(s, "connect-src &#39;none&#39;") || !strings.Contains(s, "export-inventory.json") {
			t.Fatal("offline boundary or inventory link missing")
		}
	}
}
