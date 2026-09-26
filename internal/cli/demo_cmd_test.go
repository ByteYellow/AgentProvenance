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
