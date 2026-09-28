package dashboard

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func artifactStore(t *testing.T) (store.Paths, *sql.DB, provenance.ObjectStore) {
	t.Helper()
	paths, err := store.Init(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return paths, db, provenance.ObjectStore{DB: db, Paths: paths}
}

func artifactPage(t *testing.T, db *sql.DB, run, node string, offset int64, extra string) artifactResp {
	t.Helper()
	r := httptest.NewRequest("GET", fmt.Sprintf("/api/artifact?run=%s&node=%s&offset=%d%s", url.QueryEscape(run), url.QueryEscape(node), offset, extra), nil)
	w := httptest.NewRecorder()
	(Server{DB: db}).artifact(w, r)
	if w.Code != 200 {
		t.Fatalf("status=%d: %s", w.Code, w.Body)
	}
	var out artifactResp
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func putArtifact(t *testing.T, objects provenance.ObjectStore, run, source string, payload map[string]any) provenance.ExternalObjectResult {
	t.Helper()
	obj, err := objects.PutExternalObject(provenance.ExternalObjectInput{Type: "artifact", RunID: run, SourceID: source, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	return obj
}

func TestArtifactNeverReadsCurrentFiles(t *testing.T) {
	_, db, objects := artifactStore(t)
	path := filepath.Join(t.TempDir(), "current.txt")
	if err := os.WriteFile(path, []byte("LIVE-FILE-MUST-NOT-BE-SHOWN"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tool_calls (id,run_id,status,result_ref,created_at) VALUES ('tool','run','completed',?,'2026-09-28T00:00:00Z')`, path); err != nil {
		t.Fatal(err)
	}
	for _, run := range []string{"run", "unrelated"} {
		got := artifactPage(t, db, run, path, 0, "")
		if got.Kind != "unavailable" || got.ContentState != "legacy_not_recorded" || got.Content != "" || got.TotalBytes != nil {
			t.Fatalf("live-file substitution: %+v", got)
		}
	}
	obj := putArtifact(t, objects, "run", path, map[string]any{"path": path, "content": "HISTORICAL-BODY"})
	got := artifactPage(t, db, "run", path, 0, "")
	if got.Content != "HISTORICAL-BODY" || got.Ref != obj.Hash || got.Integrity != "object_hash_verified" {
		t.Fatalf("stored evidence: %+v", got)
	}
	if err := os.Remove(obj.Path); err != nil {
		t.Fatal(err)
	}
	got = artifactPage(t, db, "run", path, 0, "")
	if got.ContentState != "unavailable" || got.Content != "" {
		t.Fatalf("missing blob read live file: %+v", got)
	}
}

func TestArtifactHashRunAndRevisionIsolation(t *testing.T) {
	_, db, objects := artifactStore(t)
	one := putArtifact(t, objects, "run", "workspace_file/nested/main.go", map[string]any{"content": "old"})
	two := putArtifact(t, objects, "run", "workspace_file/nested/main.go", map[string]any{"content": "new"})
	got := artifactPage(t, db, "run", "workspace_file/nested/main.go", 0, "")
	if got.ContentState != "ambiguous" || len(got.Versions) != 2 || got.Content != "" {
		t.Fatalf("silently chose revision: %+v", got)
	}
	for _, tc := range []struct{ node, run, want string }{{one.Hash, "run", "old"}, {two.Hash, "run", "new"}, {one.Hash, "other", ""}, {"workspace_file/different/main.go", "run", ""}} {
		if got := artifactPage(t, db, tc.run, tc.node, 0, ""); got.Content != tc.want {
			t.Fatalf("node/run mismatch: %+v", got)
		}
	}
	if err := os.WriteFile(one.Path, []byte("TAMPERED-BYTES"), 0600); err != nil {
		t.Fatal(err)
	}
	got = artifactPage(t, db, "run", one.Hash, 0, "")
	if got.ContentState != "integrity_failure" || got.Content != "" {
		t.Fatalf("unverified bytes served: %+v", got)
	}
	// A hash-valid envelope still must belong to the run in the index.
	if _, err := db.Exec(`UPDATE provenance_objects SET run_id='other' WHERE hash=?`, two.Hash); err != nil {
		t.Fatal(err)
	}
	got = artifactPage(t, db, "other", two.Hash, 0, "")
	if got.ContentState != "integrity_failure" {
		t.Fatalf("foreign envelope: %+v", got)
	}
}

func TestArtifactMetadataEmptyAndRaw(t *testing.T) {
	_, db, objects := artifactStore(t)
	meta := putArtifact(t, objects, "run", "meta", map[string]any{"file_sha256": "known-hash", "size_bytes": 100})
	empty := putArtifact(t, objects, "run", "empty", map[string]any{"path": "empty.txt", "content": ""})
	got := artifactPage(t, db, "run", meta.Hash, 0, "")
	if got.ContentState != "legacy_not_recorded" || got.TotalBytes != nil {
		t.Fatalf("metadata claimed as body: %+v", got)
	}
	got = artifactPage(t, db, "run", meta.Hash, 0, "&mode=raw")
	if got.ContentState != "stored" || !strings.Contains(got.Content, "known-hash") || got.Mode != "raw" {
		t.Fatalf("metadata raw: %+v", got)
	}
	got = artifactPage(t, db, "run", empty.Hash, 0, "")
	if got.ContentState != "stored" || got.TotalBytes == nil || *got.TotalBytes != 0 || got.HasMore {
		t.Fatalf("empty != missing: %+v", got)
	}
}

func TestArtifactPagesMaskBeforeSlicingAndKeepUTF8(t *testing.T) {
	_, db, objects := artifactStore(t)
	body := strings.Repeat("x", artifactPreviewBytes-10) + "\nAPI_KEY=sk-1234567890abcdef1234567890abcdef\n" + strings.Repeat("界", 101) + "END"
	obj := putArtifact(t, objects, "run", "page", map[string]any{"path": "code.txt", "content": body})
	var out strings.Builder
	var last artifactResp
	for offset := int64(0); ; {
		last = artifactPage(t, db, "run", obj.Hash, offset, "&limit=65536")
		if !utf8.ValidString(last.Content) || len(last.Content) > artifactPreviewBytes {
			t.Fatal("invalid UTF-8/bound")
		}
		out.WriteString(last.Content)
		if !last.HasMore {
			break
		}
		if last.NextOffset <= offset {
			t.Fatal("no progress")
		}
		offset = last.NextOffset
	}
	if !strings.HasSuffix(out.String(), "END") || strings.Contains(out.String(), "1234567890abcdef") {
		t.Fatal("tail or redaction broken")
	}
	sum := sha256.Sum256([]byte(out.String()))
	if last.SHA256 != hex.EncodeToString(sum[:]) || last.TotalBytes == nil || *last.TotalBytes != int64(out.Len()) {
		t.Fatal("body hash/length mismatch")
	}
	unicodeObj := putArtifact(t, objects, "run", "utf8", map[string]any{"content": "界界界"})
	first := artifactPage(t, db, "run", unicodeObj.Hash, 0, "&limit=4")
	if first.Content != "界" || first.NextOffset != 3 {
		t.Fatalf("split code point: %+v", first)
	}
	for _, extra := range []string{"&offset=-1", "&offset=1", "&limit=3", "&limit=999999", "&mode=unknown", "&offset=9223372036854775807"} {
		w := httptest.NewRecorder()
		(Server{DB: db}).artifact(w, httptest.NewRequest("GET", "/api/artifact?run=run&node="+unicodeObj.Hash+extra, nil))
		if w.Code != 400 {
			t.Fatalf("accepted invalid range %s: %d", extra, w.Code)
		}
	}
}

func TestArtifactBoundedMissingAndFailedLookup(t *testing.T) {
	_, db, objects := artifactStore(t)
	obj := putArtifact(t, objects, "run", "large", map[string]any{"content": "original"})
	f, err := os.OpenFile(obj.Path, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	err = f.Truncate(artifactReadBytes + 1)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	got := artifactPage(t, db, "run", obj.Hash, 0, "")
	if got.ContentState != "read_limit" || got.Content != "" {
		t.Fatalf("unbounded legacy read: %+v", got)
	}
	missing := putArtifact(t, objects, "run", "missing-chunks", map[string]any{"content_ref": "sha256:" + strings.Repeat("f", 64)})
	got = artifactPage(t, db, "run", missing.Hash, 0, "")
	if got.ContentState != "unavailable" || got.TotalBytes != nil {
		t.Fatalf("missing chunks: %+v", got)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	(Server{DB: db}).artifact(w, httptest.NewRequest("GET", "/api/artifact?run=run&node=anything", nil))
	if w.Code != 500 {
		t.Fatalf("database error became missing evidence: %d", w.Code)
	}
}

func TestArtifactSignedOfflinePagingAcrossAllLimits(t *testing.T) {
	for _, size := range []int{(64 << 10) + 33, (4 << 20) + 33, (8 << 20) + 33} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			paths, db, objects := artifactStore(t)
			body := strings.Repeat("a", size) + "\nCAPTURED-FILE-TAIL"
			content, err := objects.PutTextContent(provenance.TextContentInput{RunID: "run", SourceID: "file/large", Text: body})
			if err != nil {
				t.Fatal(err)
			}
			obj := putArtifact(t, objects, "run", "workspace_file/large.txt", map[string]any{"path": "large.txt", "content_ref": content.Ref, "content_state": "stored"})
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key}).ExportBundle("run")
			if err != nil {
				t.Fatal(err)
			}
			if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, pub); err != nil {
				t.Fatal(err)
			}
			freshPaths, freshDB, _ := artifactStore(t)
			info, err := (forensics.Service{DB: freshDB, Paths: freshPaths}).ImportBundle(bundle.Path)
			if err != nil || info.Omitted != 0 {
				t.Fatalf("import=%+v err=%v", info, err)
			}
			if err := os.Rename(paths.Provenance, paths.Provenance+"-offline"); err != nil {
				t.Fatal(err)
			}
			var result strings.Builder
			for offset := int64(0); ; {
				page := artifactPage(t, freshDB, "run", obj.Hash, offset, "")
				if page.ContentState != "stored" || page.ContentRef != content.Ref || page.SHA256 != content.SHA256 || page.TotalBytes == nil || *page.TotalBytes != int64(len(body)) {
					t.Fatalf("offline page differs: ref=%s state=%s reason=%s", page.ContentRef, page.ContentState, page.Reason)
				}
				result.WriteString(page.Content)
				if !page.HasMore {
					break
				}
				if page.NextOffset <= offset {
					t.Fatal("page made no progress")
				}
				offset = page.NextOffset
			}
			if result.String() != body {
				t.Fatal("offline body or tail changed")
			}
		})
	}
}

// This fixture writes only synthetic evidence; it is not a captured agent run.
func TestArtifactDashboardFixture(t *testing.T) {
	root := os.Getenv("AGENTPROV_ARTIFACT_UI_FIXTURE_DIR")
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
	objects := provenance.ObjectStore{DB: db, Paths: paths}
	body := "SYNTHETIC-FILE-START\n" + strings.Repeat("saved historical line\n", 400000) + "SYNTHETIC-FILE-TAIL"
	text, err := objects.PutTextContent(provenance.TextContentInput{RunID: "artifact-ui", SourceID: "fixture/large", Text: body})
	if err != nil {
		t.Fatal(err)
	}
	putArtifact(t, objects, "artifact-ui", "workspace_file/large.txt", map[string]any{"content_ref": text.Ref, "path": "large.txt"})
	putArtifact(t, objects, "artifact-ui", "workspace_file/change.patch", map[string]any{"content": "diff --git a/report.py b/report.py\n--- a/report.py\n+++ b/report.py\n@@ -1 +1 @@\n-old\n+new\n", "path": "change.patch"})
	putArtifact(t, objects, "artifact-ui", "workspace_file/metadata.txt", map[string]any{"path": "metadata.txt", "file_sha256": "synthetic-metadata-only"})
	putArtifact(t, objects, "artifact-ui", "workspace_file/versions.txt", map[string]any{"content": "VERSION-ONE"})
	putArtifact(t, objects, "artifact-ui", "workspace_file/versions.txt", map[string]any{"content": "VERSION-TWO"})
	for i, path := range []string{"large.txt", "change.patch", "metadata.txt", "versions.txt"} {
		id := fmt.Sprintf("fixture-%d", i)
		payload, _ := json.Marshal(map[string]any{"path": path, "fixture": true})
		if _, err := db.Exec(`INSERT INTO events (id,run_id,source,event_type,payload,created_at) VALUES (?,'artifact-ui','synthetic_fixture','file_write',?,'2026-09-28T00:00:00Z')`, id, string(payload)); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO graph_edges (id,run_id,from_id,to_id,edge_type,source_event_id,created_at) VALUES (?,'artifact-ui',?,?,'runtime_event_file',?,'2026-09-28T00:00:00Z')`, "edge-"+id, "runtime_event/"+id, "workspace_file/"+path, id); err != nil {
			t.Fatal(err)
		}
	}
	got := artifactPage(t, db, "artifact-ui", "workspace_file/large.txt", 0, "")
	if got.TotalBytes == nil || *got.TotalBytes <= 8<<20 || !got.HasMore {
		t.Fatalf("large fixture: state=%s size=%d", got.ContentState, got.Size)
	}
}
