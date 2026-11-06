package daemon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// csrfFixture builds an open (no token) server whose ingest allow directory is
// a temp dir containing one valid task YAML.
func csrfFixture(t *testing.T) (Server, *httptest.Server, string) {
	t.Helper()
	s := testServer(t)
	allow := t.TempDir()
	s.IngestAllowDir = allow
	task := filepath.Join(allow, "task.yaml")
	if err := os.WriteFile(task, []byte("run_id: csrf-run\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return s, srv, allow
}

// doWrite posts a JSON body to srv with the given extra headers.
func doWrite(t *testing.T, srvURL, path, contentType string, headers map[string]string, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srvURL+path, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestCSRFGuardRejectsCrossSiteWrites covers the H1 fix: browser cross-site
// markers on a write route are rejected with 403, while plain JSON API calls
// (no Origin/Sec-Fetch headers) keep working.
func TestCSRFGuardRejectsCrossSiteWrites(t *testing.T) {
	_, srv, allow := csrfFixture(t)
	task := filepath.Join(allow, "task.yaml")
	body := fmt.Sprintf(`{"task":%q}`, task)
	host := strings.TrimPrefix(srv.URL, "http://")

	cases := []struct {
		name    string
		ct      string
		headers map[string]string
		want    int
	}{
		{"plain JSON POST no Origin", "application/json", nil, http.StatusOK},
		{"JSON charset param", "application/json; charset=utf-8", nil, http.StatusOK},
		{"body without Content-Type header", "", nil, http.StatusForbidden},
		{"cross-site Origin", "application/json", map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
		{"text/plain drive-by", "text/plain", map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "no-cors"}, http.StatusForbidden},
		{"form-urlencoded no-cors", "application/x-www-form-urlencoded", nil, http.StatusForbidden},
		{"Sec-Fetch cross-site only", "application/json", map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"Origin null sandbox", "application/json", map[string]string{"Origin": "null"}, http.StatusForbidden},
		{"same-origin Origin", "application/json", map[string]string{"Origin": "http://" + host}, http.StatusOK},
		{"Sec-Fetch none", "application/json", map[string]string{"Sec-Fetch-Site": "none"}, http.StatusOK},
	}
	for _, tc := range cases {
		resp := doWrite(t, srv.URL, "/v1/leases", tc.ct, tc.headers, body)
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Fatalf("%s: status = %d, want %d", tc.name, resp.StatusCode, tc.want)
		}
	}

	// Health endpoints stay exempt even with hostile headers.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/health", nil)
	req.Header.Set("Origin", "https://evil.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health with hostile Origin status = %d, want 200", resp.StatusCode)
	}
}

// TestIngestFalcoConfinedToAllowDir covers the H2 fix: sync and async ingest
// both refuse paths outside the allow directory (including symlink escapes),
// and async spool copies are written 0600.
func TestIngestFalcoConfinedToAllowDir(t *testing.T) {
	_, srv, allow := csrfFixture(t)

	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("api_token: super-secret-42\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, mode := range []bool{false, true} {
		resp := doWrite(t, srv.URL, "/v1/telemetry/ingest-falco", "application/json", nil,
			fmt.Sprintf(`{"file":%q,"run_id":"h2-fix","async":%v}`, outside, mode))
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("async=%v outside path status = %d, want 400", mode, resp.StatusCode)
		}
		if msg, _ := body["error"].(string); !strings.Contains(msg, "outside the ingest allow directory") {
			t.Fatalf("async=%v unexpected error %v", mode, body["error"])
		}
	}

	// Symlink inside the allow directory pointing outside must be rejected too.
	link := filepath.Join(allow, "escape.jsonl")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	resp := doWrite(t, srv.URL, "/v1/telemetry/ingest-falco", "application/json", nil,
		fmt.Sprintf(`{"file":%q,"run_id":"h2-fix"}`, link))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("symlink escape status = %d, want 400", resp.StatusCode)
	}

	// A real falco JSONL inside the allow dir works in both modes, and the
	// async spool copy is 0600.
	falco := filepath.Join(allow, "events.jsonl")
	line := `{"time":"2026-01-01T00:00:00Z","rule":"Canary test","priority":"Warning","output":"test","evt.type":"execve","output_fields":{}}`
	if err := os.WriteFile(falco, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resp = doWrite(t, srv.URL, "/v1/telemetry/ingest-falco", "application/json", nil,
		fmt.Sprintf(`{"file":%q,"run_id":"h2-fix-sync"}`, falco))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sync inside status = %d, want 200", resp.StatusCode)
	}
	resp = doWrite(t, srv.URL, "/v1/telemetry/ingest-falco", "application/json", nil,
		fmt.Sprintf(`{"file":%q,"run_id":"h2-fix-async","async":true}`, falco))
	var asyncBody struct {
		SpoolBatch struct {
			SpoolPath string `json:"spool_path"`
		} `json:"spool_batch"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&asyncBody)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || asyncBody.SpoolBatch.SpoolPath == "" {
		t.Fatalf("async inside status = %d body=%s", resp.StatusCode, asyncBody.SpoolBatch.SpoolPath)
	}
	info, err := os.Stat(asyncBody.SpoolBatch.SpoolPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("spool file mode = %o, want 600", info.Mode().Perm())
	}
}

// TestLeaseTaskConfinedToAllowDir covers the M7 fix: /v1/leases only accepts
// task paths inside the allow directory and never echoes file content back,
// neither via storage errors nor via YAML parse errors.
func TestLeaseTaskConfinedToAllowDir(t *testing.T) {
	s, srv, allow := csrfFixture(t)
	_ = s

	// Secret file outside the allow directory.
	outside := filepath.Join(t.TempDir(), "canary.yaml")
	if err := os.WriteFile(outside, []byte("api_token: super-secret-42\nrun_id: canary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resp := doWrite(t, srv.URL, "/v1/leases", "application/json", nil, fmt.Sprintf(`{"task":%q}`, outside))
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("outside task status = %d, want 400", resp.StatusCode)
	}
	if msg, _ := body["error"].(string); strings.Contains(msg, "super-secret") || strings.Contains(msg, string(outside)) {
		t.Fatalf("error leaks file content or path: %v", body["error"])
	}

	// Invalid YAML inside the allow dir: fixed error message, no content echo.
	invalid := filepath.Join(allow, "broken.yaml")
	if err := os.WriteFile(invalid, []byte("api_token: leaked-fragment-77\nrun_id: [unclosed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resp = doWrite(t, srv.URL, "/v1/leases", "application/json", nil, fmt.Sprintf(`{"task":%q}`, invalid))
	var broken map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&broken)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid task status = %d, want 400", resp.StatusCode)
	}
	if msg, _ := broken["error"].(string); strings.Contains(msg, "leaked-fragment") || strings.Contains(msg, "yaml") {
		t.Fatalf("YAML error echoes file content: %v", broken["error"])
	}

	// Valid task inside the allow dir still creates a lease.
	resp = doWrite(t, srv.URL, "/v1/leases", "application/json", nil, `{"task":"task.yaml"}`)
	var ok struct {
		LeaseID string `json:"lease_id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&ok)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || ok.LeaseID == "" {
		t.Fatalf("valid task status = %d lease=%q, want 200 + lease_id", resp.StatusCode, ok.LeaseID)
	}
}

// TestResolveWithinIngestAllowDir pins the containment helper semantics.
func TestResolveWithinIngestAllowDir(t *testing.T) {
	s := testServer(t)
	allow := s.Paths.Root
	s.IngestAllowDir = filepath.Join(allow, "ingest")
	if err := os.MkdirAll(s.IngestAllowDir, 0o700); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(s.IngestAllowDir, "a.jsonl")
	if err := os.WriteFile(inside, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, ok := range []string{inside, filepath.Join(s.IngestAllowDir, "missing.jsonl")} {
		if _, err := s.resolveWithinIngestAllowDir(ok); err != nil {
			t.Fatalf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"/etc/passwd",
		filepath.Join(allow, "sibling.jsonl"),
		filepath.Join(s.IngestAllowDir, "..", "agentprov.db"),
		s.IngestAllowDir,
		"",
	} {
		if _, err := s.resolveWithinIngestAllowDir(bad); err == nil {
			t.Fatalf("%q accepted, want reject", bad)
		}
	}

	// Symlink planted inside pointing outside.
	outside := filepath.Join(t.TempDir(), "target.txt")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(s.IngestAllowDir, "link.jsonl")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := s.resolveWithinIngestAllowDir(link); err == nil {
		t.Fatal("symlink escape accepted")
	}
}

// TestAuthTokenHelpers covers token generation, 0600 persistence and the
// client-side precedence (explicit env > token file).
func TestAuthTokenHelpers(t *testing.T) {
	token, err := GenerateAuthToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 64 {
		t.Fatalf("token length = %d, want 64 hex chars", len(token))
	}
	dir := t.TempDir()
	if err := WriteAuthTokenFile(dir, token); err != nil {
		t.Fatal(err)
	}
	if got := ReadAuthToken(dir); got != token {
		t.Fatalf("round trip = %q, want %q", got, token)
	}
	info, err := os.Stat(TokenPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode = %o, want 600", info.Mode().Perm())
	}
	// Pre-existing weak mode is tightened.
	if err := os.Chmod(TokenPath(dir), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteAuthTokenFile(dir, token); err != nil {
		t.Fatal(err)
	}
	if info, err = os.Stat(TokenPath(dir)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("weak mode not tightened: %v %v", err, info.Mode().Perm())
	}
	// Missing file -> empty token.
	if got := ReadAuthToken(filepath.Join(dir, "nope")); got != "" {
		t.Fatalf("missing file token = %q", got)
	}
	// Client token precedence: env wins over file; file used without env.
	t.Setenv("AGENTPROV_DAEMON_TOKEN", "env-token")
	if got := resolveClientToken(dir); got != "env-token" {
		t.Fatalf("env precedence lost: %q", got)
	}
	t.Setenv("AGENTPROV_DAEMON_TOKEN", "")
	if got := resolveClientToken(dir); got != token {
		t.Fatalf("token file fallback lost: %q", got)
	}
}
