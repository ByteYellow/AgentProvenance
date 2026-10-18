package dashboard

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
)

func TestReplayFileHTTPTransport(t *testing.T) {
	data := bytes.Repeat([]byte("large-frozen-replay\n"), 400000)
	path := filepath.Join(t.TempDir(), "catalog.js")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveReplayFile(w, r, "catalog.js", path)
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 10 * time.Second
	for i := 0; i < 8; i++ {
		response, err := client.Get(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.New()
		n, readErr := io.Copy(hash, response.Body)
		response.Body.Close()
		if readErr != nil || response.StatusCode != 200 || response.ContentLength != int64(len(data)) || n != int64(len(data)) || hex.EncodeToString(hash.Sum(nil)) != replayDigest(data) {
			t.Fatalf("large response %d: status=%d bytes=%d err=%v", i, response.StatusCode, n, readErr)
		}
	}
	request, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Range", "bytes=65536-131071")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	part, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusPartialContent || !bytes.Equal(part, data[65536:131072]) {
		t.Fatalf("byte-range response: status=%d err=%v", response.StatusCode, err)
	}
}

func previewFixture(t *testing.T) (*ReplayExports, http.Handler) {
	t.Helper()
	paths, db, _ := artifactStore(t)
	body, raw := "FROZEN-CONTEXT", "FROZEN-RAW"
	_, err := (agentcontext.Service{DB: db, Paths: paths}).Save(context.Background(), "preview-run", agentcontext.Source{ID: "source", Harness: "codex", SessionID: "native-session", ParserVersion: "fixture/v1", Binding: "explicit"}, []agentcontext.Record{
		{Key: "message", Kind: "message", Role: "user", Body: &body, RawBody: &raw},
	}, agentcontext.Coverage{Status: agentcontext.OK})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO events (id,run_id,source,event_type,created_at,payload) VALUES ('first','preview-run','fixture','exec','2026-10-18T00:00:00Z','{"command":"original"}')`); err != nil {
		t.Fatal(err)
	}
	m := NewReplayExports(Server{DB: db})
	t.Cleanup(m.Close)
	return m, (Server{DB: db, ReplayExports: m}).Handler()
}

func replayRequest(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, "http://127.0.0.1:7396"+path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:45678"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-AgentProv-Export", "1")
	r.Header.Set("Origin", "http://127.0.0.1:7396")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	return r
}

func previewCall(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, replayRequest(method, path, body))
	return w
}

func preparedPreview(t *testing.T, h http.Handler) replayPreview {
	t.Helper()
	w := previewCall(h, "POST", "/api/replay/previews", `{"run":"preview-run","scope":"whole_run"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("prepare: %d %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Content-Type") != "application/json" {
		t.Fatal("JSON response type missing")
	}
	var preview replayPreview
	if err := json.Unmarshal(w.Body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	return preview
}

func TestReplayPreviewDownloadUsesFrozenInventory(t *testing.T) {
	m, h := previewFixture(t)
	p := preparedPreview(t, h)
	if p.Inventory.Scope != "whole_run" || p.Inventory.Signed || p.Inventory.Events != 1 || p.ZIPBytes <= 0 || len(p.ID) != 48 {
		t.Fatalf("bad preview: %+v", p)
	}
	c := p.Inventory.Contents
	if c.Sessions != 1 || c.ContextEntries != 1 || c.LatestEntries != 1 || c.BodyRefs != 1 || c.RawRefs != 1 || c.Sources["messages"] != 1 || c.Sources["runtime"] != 1 {
		t.Fatalf("bad counts: %+v", c)
	}
	base := "/api/replay/previews/" + p.ID
	if _, err := m.server.DB.Exec(`INSERT INTO events (id,run_id,source,event_type,created_at,payload) VALUES ('late','preview-run','fixture','exec','2026-10-18T01:00:00Z','{"command":"later"}')`); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{base, base + "/files/en/index.html", base + "/files/zh-CN/index.html", base + "/files/assets/export.js", base + "/files/export-inventory.json"} {
		w := previewCall(h, "GET", path, "")
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("frozen file %s: %d %s", path, w.Code, w.Body.String())
		}
	}
	for _, file := range []string{"prepared-replay.zip", "snapshot.db", "not-listed", "%2e%2e%2fsecret", "assets/../../snapshot.db"} {
		w := previewCall(h, "GET", base+"/files/"+file, "")
		if w.Code == 200 {
			t.Fatalf("unlisted file served: %s", file)
		}
	}
	if w := previewCall(h, "GET", base+"/download", ""); w.Code != 409 {
		t.Fatal("download skipped inventory confirmation")
	}
	w := previewCall(h, "GET", base+"/download?inventory="+p.InventorySHA256, "")
	if w.Code != 200 || int64(w.Body.Len()) != p.ZIPBytes || replayDigest(w.Body.Bytes()) != p.ZIPSHA256 || w.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("ZIP mismatch: %d", w.Code)
	}
	z, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if len(z.File) != len(p.Inventory.Files)+1 {
		t.Fatal("archive includes unlisted files")
	}
	for _, f := range z.File {
		if f.Name == "export-inventory.json" {
			r, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(r)
			r.Close()
			if err != nil {
				t.Fatal(err)
			}
			if replayDigest(data) != p.InventorySHA256 {
				t.Fatal("downloaded inventory differs")
			}
		}
	}
	if again := previewCall(h, "POST", "/api/replay/previews", `{"run":"preview-run","scope":"whole_run"}`); again.Code != 409 {
		t.Fatal("concurrent preview admitted")
	}
	j := m.acquire(p.ID)
	if j == nil {
		t.Fatal("missing preview")
	}
	root := j.prepared.root
	if deleted := previewCall(h, "DELETE", base, ""); deleted.Code != 204 {
		t.Fatal("cancel failed")
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatal("active reader lost its files")
	}
	m.release(j)
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("canceled preview was not cleaned")
	}
	if expired := previewCall(h, "GET", base, ""); expired.Code != 410 {
		t.Fatal("canceled preview still accessible")
	}
}

func TestReplayPreviewRequestBoundary(t *testing.T) {
	_, h := previewFixture(t)
	for _, body := range []string{`{}`, `{"run":"preview-run"}`, `{"run":"preview-run","scope":"session"}`, `{"run":"preview-run","scope":"whole_run","exclude":["secret"]}`, `{"run":"preview-run","scope":"whole_run"}{}`, `{"run":"` + strings.Repeat("x", 5000) + `","scope":"whole_run"}`} {
		if w := previewCall(h, "POST", "/api/replay/previews", body); w.Code != 400 {
			t.Fatalf("invalid request accepted: %d", w.Code)
		}
	}
	for _, change := range []func(*http.Request){
		func(r *http.Request) { r.Host = "rebind.example:7396" },
		func(r *http.Request) { r.RemoteAddr = "192.168.1.2:1234" },
		func(r *http.Request) { r.Header.Set("Origin", "https://attacker.example") },
		func(r *http.Request) { r.Header.Set("Origin", "null") },
		func(r *http.Request) { r.Header.Set("Origin", "http://127.0.0.1:7397") },
		func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
		func(r *http.Request) { r.Header.Del("X-AgentProv-Export") },
	} {
		r := replayRequest("POST", "/api/replay/previews", `{"run":"preview-run","scope":"whole_run"}`)
		change(r)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("request boundary: %d", w.Code)
		}
	}
	r := replayRequest("POST", "/api/replay/previews", `{}`)
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 415 {
		t.Fatal("non-JSON accepted")
	}
	w = previewCall(Server{}.Handler(), "POST", "/api/replay/previews", `{}`)
	if w.Code != 503 {
		t.Fatal("export enabled without private lifecycle owner")
	}
}

func TestReplayPreviewExpiryAndClose(t *testing.T) {
	m, h := previewFixture(t)
	p := preparedPreview(t, h)
	j := m.acquire(p.ID)
	root := j.prepared.root
	m.release(j)
	m.retire(j)
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("retired files remain")
	}
	// Exercise actual timer cleanup as well as explicit expiry and cancellation.
	m.ttl = time.Millisecond
	_ = preparedPreview(t, h)
	deadline := time.Now().Add(time.Second)
	for {
		m.mu.Lock()
		active := m.active
		m.mu.Unlock()
		if !active {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("expiry did not release storage")
		}
		time.Sleep(time.Millisecond)
	}
	m.Close()
	if w := previewCall(h, "POST", "/api/replay/previews", `{"run":"preview-run","scope":"whole_run"}`); w.Code != 409 {
		t.Fatal("closed manager accepted a preparation")
	}
}

func TestReplayPreviewFailedPreparationReleasesSlot(t *testing.T) {
	m, h := previewFixture(t)
	for _, run := range []string{"missing", "preview-run"} {
		ctx, cancel := context.WithCancel(context.Background())
		if run == "preview-run" {
			cancel()
		}
		r := replayRequest("POST", "/api/replay/previews", `{"run":"`+run+`","scope":"whole_run"}`).WithContext(ctx)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		cancel()
		m.mu.Lock()
		active := m.active
		m.mu.Unlock()
		if active {
			t.Fatal("failed prepare leaked its slot")
		}
	}
	_ = preparedPreview(t, h)
}
