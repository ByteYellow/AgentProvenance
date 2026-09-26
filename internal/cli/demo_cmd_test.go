package cli

import (
	"bytes"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/byteyellow/agentprovenance/demo"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestAllBundledDemosVerify(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "state")
	catalog := demo.Catalog()
	seen := map[string]bool{}
	count := 0
	for _, entry := range catalog {
		if seen[entry.ID] {
			t.Fatalf("duplicate demo: %s", entry.ID)
		}
		seen[entry.ID] = true
		if _, err := demo.Files.ReadFile(path.Join(entry.Directory, "README.md")); err != nil {
			t.Fatal(err)
		}
		if entry.Run == "" {
			continue
		}
		count++
		t.Run(entry.ID, func(t *testing.T) {
			got, err := prepareDemo(dir, dataDir, entry, demo.Files)
			if err != nil {
				t.Fatal(err)
			}
			if !got.SignatureVerified || got.Graph.ErrorCount != 0 {
				t.Fatalf("verification: %+v", got)
			}
			t.Logf("%s: status=%s, warnings=%d", entry.Run, got.Graph.Status, got.Graph.WarningCount)
		})
	}
	bundles, err := fs.Glob(demo.Files, "*/*.forensics.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	if len(bundles) != count {
		t.Fatalf("catalog contains %d of %d signed bundles", count, len(bundles))
	}
	guides, err := fs.Glob(demo.Files, "*/README.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, guide := range guides {
		found := false
		for _, entry := range catalog {
			if entry.Directory == path.Dir(guide) {
				found = true
			}
		}
		if !found {
			t.Errorf("missing demo directory: %s", guide)
		}
	}
}

func TestDemoRejectsTamperingBeforeStoreCreation(t *testing.T) {
	entry := demo.Catalog()[0]
	for _, suffix := range []string{".forensics.json.gz", ".forensics.dsse.json"} {
		t.Run(suffix, func(t *testing.T) {
			files := fstest.MapFS{}
			for _, name := range []string{entry.Bundle + ".forensics.json.gz", entry.Bundle + ".forensics.dsse.json", entry.Key} {
				key := path.Join(entry.Directory, name)
				b, err := demo.Files.ReadFile(key)
				if err != nil {
					t.Fatal(err)
				}
				files[key] = &fstest.MapFile{Data: b}
			}
			files[path.Join(entry.Directory, entry.Bundle+suffix)].Data = []byte("tampered")
			dir := t.TempDir()
			state := filepath.Join(dir, "state")
			if _, err := prepareDemo(dir, state, entry, files); err == nil {
				t.Fatal("accepted corrupt signed evidence")
			}
			if _, err := os.Stat(store.ResolvePaths(state).DB); !os.IsNotExist(err) {
				t.Fatalf("store created before signature verification: %v", err)
			}
		})
	}
}

func TestDemoGalleryAndGuides(t *testing.T) {
	h := demoGallery(demo.Catalog())
	for _, p := range []string{"/demos/", "/demos/docs/llm-judge", "/demos/docs/jev-judge"} {
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest(http.MethodGet, p, nil))
		if w.Code != 200 {
			t.Fatalf("%s: %d", p, w.Code)
		}
		if p == "/demos/" && !strings.Contains(w.Body.String(), "run-double-attempt") {
			t.Fatal("missing replay link")
		}
	}
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodGet, "/demos/docs/missing", nil))
	if w.Code != 404 {
		t.Fatal("unknown guide must be 404")
	}
}

func TestDemoRejectsUnknownNamesAndSharedStores(t *testing.T) {
	for _, args := range [][]string{{"demo", "missing"}, {"--data-dir", t.TempDir(), "demo"}, {"demo", "--daemon-url", "http://localhost:1"}} {
		cmd := NewRootCommand()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil {
			t.Fatalf("expected error for %q", args)
		}
	}
}

func TestDemoGuideRendersMarkdownAndLocalAssets(t *testing.T) {
	entries := demo.Catalog()
	entry := entries[len(entries)-1]
	source, err := demo.Files.ReadFile(entry.Directory + "/README.md")
	if err != nil {
		t.Fatal(err)
	}
	html, headings, err := renderDemoGuide(entry, entries, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"<h1", "<h2", "<pre><code", "/demos/assets/jev-judge/review.png"} {
		if !strings.Contains(string(html), want) {
			t.Errorf("missing rendered content: %s", want)
		}
	}
	tableSource, err := demo.Files.ReadFile("llm-judge/README.md")
	if err != nil {
		t.Fatal(err)
	}
	tableHTML, _, err := renderDemoGuide(entries[6], entries, tableSource)
	if err != nil || !strings.Contains(string(tableHTML), "<table>") {
		t.Fatalf("GFM table missing: %v", err)
	}
	if len(headings) == 0 {
		t.Fatal("missing document outline")
	}
	for _, h := range headings {
		if !strings.Contains(string(html), `id="`+h.ID+`"`) {
			t.Errorf("broken heading anchor: %s", h.ID)
		}
	}
	h := demoGallery(entries)
	for _, asset := range []string{"review.png", "review-rules.png", "validation-2026-09-22.json"} {
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest(http.MethodGet, "/demos/assets/jev-judge/"+asset, nil))
		if w.Code != 200 {
			t.Errorf("asset %s: %d", asset, w.Code)
		}
	}
	if got := demoGuideLink(entries[3], entries, "../k8s-cross-pod-a2a#replay"); got != "/demos/docs/k8s-cross-pod-a2a#replay" {
		t.Fatalf("bad local guide link: %s", got)
	}
}

func TestDemoGuideDoesNotRenderActiveHTML(t *testing.T) {
	entry := demo.Catalog()[0]
	source := []byte("# Guide\n\n<script>alert(1)</script>\n\n[bad](javascript:alert%281%29)\n\n![bad](javascript:alert%281%29)\n\n```sh\necho '<script>'\n```\n")
	html, _, err := renderDemoGuide(entry, demo.Catalog(), source)
	if err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range []string{"<script>", "javascript:"} {
		if strings.Contains(string(html), unsafe) {
			t.Errorf("active content in rendered guide: %s", html)
		}
	}
	if !strings.Contains(string(html), "&lt;script&gt;") {
		t.Fatal("code example should remain escaped and readable")
	}
}
