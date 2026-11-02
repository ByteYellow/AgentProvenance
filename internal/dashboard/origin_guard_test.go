package dashboard

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// serveReal opens the dashboard handler on a live loopback listener so requests
// traverse real network connections (no httptest.ResponseRecorder, which the
// same-origin guard exempts for offline rendering).
func serveReal(t *testing.T, s Server) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv
}

// do sends a request to srv with a spoofed Host header, as a rebinding browser
// or curl -H would.
func do(t *testing.T, srv *httptest.Server, method, path, host string, headers map[string]string) *http.Response {
	t.Helper()
	var body io.Reader
	if method != http.MethodGet && method != http.MethodHead && method != http.MethodDelete {
		body = strings.NewReader("{}")
	}
	req, err := http.NewRequest(method, srv.URL+path, body)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if host != "" {
		req.Host = host
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s (Host %q): %v", method, path, host, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func status(t *testing.T, resp *http.Response) int {
	t.Helper()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode
}

func TestGuardRejectsRebindingHostOnDataRoutes(t *testing.T) {
	db := newDashboardTestDB(t)
	insertDashboardEvent(t, db, "guard-evt", "execve", `{}`)
	srv := serveReal(t, Server{DB: db})

	for _, path := range []string{"/", "/api/runs", "/api/events?run=run-dash", "/api/overview", "/api/graph", "/api/context/overview", "/assets/theme.css"} {
		resp := do(t, srv, http.MethodGet, path, "evil.example", nil)
		if code := status(t, resp); code != http.StatusForbidden {
			t.Errorf("GET %s with Host evil.example: got %d, want 403", path, code)
		}
	}
}

func TestGuardAllowsLocalHostOnDataRoutes(t *testing.T) {
	db := newDashboardTestDB(t)
	insertDashboardEvent(t, db, "guard-evt", "execve", `{}`)
	srv := serveReal(t, Server{DB: db})
	local := strings.TrimPrefix(srv.URL, "http://") // 127.0.0.1:port

	for _, host := range []string{local, "localhost", "127.0.0.1", "[::1]"} {
		resp := do(t, srv, http.MethodGet, "/api/runs", host, nil)
		if code := status(t, resp); code != http.StatusOK {
			t.Errorf("GET /api/runs with Host %q: got %d, want 200", host, code)
		}
	}
	// Bare IP Hosts cannot be rebound through DNS, so a LAN-addressed host is fine.
	if code := status(t, do(t, srv, http.MethodGet, "/api/runs", "192.168.1.10:7396", nil)); code != http.StatusOK {
		t.Errorf("GET /api/runs with literal-IP Host: got %d, want 200", code)
	}
}

func TestGuardRejectsCrossSiteOrigin(t *testing.T) {
	db := newDashboardTestDB(t)
	insertDashboardEvent(t, db, "guard-evt", "execve", `{}`)
	srv := serveReal(t, Server{DB: db})
	local := strings.TrimPrefix(srv.URL, "http://")

	if code := status(t, do(t, srv, http.MethodGet, "/api/runs", local, map[string]string{"Origin": "http://evil.example"})); code != http.StatusForbidden {
		t.Errorf("cross-site Origin: got %d, want 403", code)
	}
	if code := status(t, do(t, srv, http.MethodGet, "/api/runs", local, map[string]string{"Origin": "null"})); code != http.StatusForbidden {
		t.Errorf("Origin null: got %d, want 403", code)
	}
	if code := status(t, do(t, srv, http.MethodGet, "/api/runs", local, map[string]string{"Origin": srv.URL})); code != http.StatusOK {
		t.Errorf("same-origin Origin: got %d, want 200", code)
	}
}

func TestGuardRejectsCrossSiteFetchOnWrites(t *testing.T) {
	stub := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	srv := httptest.NewServer((Server{}).sameOriginGuard(stub))
	t.Cleanup(srv.Close)
	local := strings.TrimPrefix(srv.URL, "http://")

	if code := status(t, do(t, srv, http.MethodPost, "/api/write", local, map[string]string{"Sec-Fetch-Site": "cross-site"})); code != http.StatusForbidden {
		t.Errorf("POST with Sec-Fetch-Site cross-site: got %d, want 403", code)
	}
	if code := status(t, do(t, srv, http.MethodPost, "/api/write", local, map[string]string{"Sec-Fetch-Site": "same-origin"})); code != http.StatusOK {
		t.Errorf("POST with Sec-Fetch-Site same-origin: got %d, want 200", code)
	}
	// Pure curl writes carry neither Origin nor Sec-Fetch-Site and must pass.
	if code := status(t, do(t, srv, http.MethodPost, "/api/write", local, nil)); code != http.StatusOK {
		t.Errorf("POST without fetch headers: got %d, want 200", code)
	}
	// Cross-site GET navigations stay allowed: reads are Host/Origin guarded and
	// a navigation response is not readable by the foreign page.
	if code := status(t, do(t, srv, http.MethodGet, "/x", local, map[string]string{"Sec-Fetch-Site": "cross-site"})); code != http.StatusOK {
		t.Errorf("GET with Sec-Fetch-Site cross-site: got %d, want 200", code)
	}
}

func TestReplayRoutesKeepStricterGuard(t *testing.T) {
	srv := serveReal(t, Server{ReplayExports: NewReplayExports(Server{})})

	// The rebinding Host still gets a 403 from the replay guard, with its
	// established message (not the generic dashboard one).
	resp := do(t, srv, http.MethodPost, "/api/replay/previews", "127.0.0.1:7396", nil)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "Replay export requires a same-origin local connection.") {
		t.Errorf("replay route with non-loopback Host: got %d %q, want 403 with strict guard message", resp.StatusCode, string(body))
	}

	// A loopback Host passes the replay guard and reaches the route itself
	// (unknown preview id → 410 Gone), proving the exemption wiring works.
	if code := status(t, do(t, srv, http.MethodGet, "/api/replay/previews/no-such-id", "127.0.0.1:7396", nil)); code != http.StatusGone {
		t.Errorf("replay route with loopback Host: got %d, want 410", code)
	}
}

func TestListenAddrRestrictsAllowedHosts(t *testing.T) {
	listen := "dashboard.internal:7396"
	r := httptest.NewRequest(http.MethodGet, "http://dashboard.internal:7396/api/runs", nil)
	if !localDashboardRequest(r, listen) {
		t.Error("Host matching ListenAddr must be accepted")
	}
	// The explicitly configured host is accepted, but other domain names never
	// are — even when ListenAddr is set. Literal IPs stay rebinding-safe.
	r = httptest.NewRequest(http.MethodGet, "http://other.internal:7396/api/runs", nil)
	if localDashboardRequest(r, listen) {
		t.Error("an unrelated domain Host must be rejected even with ListenAddr set")
	}
	r = httptest.NewRequest(http.MethodGet, "http://dashboard.internal.evil:7396/api/runs", nil)
	if localDashboardRequest(r, listen) {
		t.Error("a lookalike domain must be rejected")
	}
	r = httptest.NewRequest(http.MethodGet, "http://localhost:7396/api/runs", nil)
	if !localDashboardRequest(r, listen) {
		t.Error("localhost must stay accepted with ListenAddr set")
	}
}

func TestLocalDashboardRequestEdgeCases(t *testing.T) {
	cases := []struct {
		name   string
		host   string
		origin string
		method string
		fetch  string
		want   bool
		listen string
	}{
		{"curl loopback", "127.0.0.1:7396", "", "GET", "", true, ""},
		{"curl localhost no port", "localhost", "", "GET", "", true, ""},
		{"curl ipv6", "[::1]:8080", "", "GET", "", true, ""},
		{"localhost trailing dot", "localhost.:7396", "", "GET", "", true, ""},
		{"rebind domain", "evil.example", "", "GET", "", false, ""},
		{"rebind subdomain", "agentprov.evil.example:80", "", "GET", "", false, ""},
		{"lookalike localhost", "localhost.evil.com", "", "GET", "", false, ""},
		{"empty host", "", "", "GET", "", false, ""},
		{"cross origin", "127.0.0.1:7396", "http://evil.example", "GET", "", false, ""},
		{"same origin", "127.0.0.1:7396", "http://127.0.0.1:7396", "GET", "", true, ""},
		{"null origin", "127.0.0.1:7396", "null", "GET", "", false, ""},
		{"write cross-site fetch", "127.0.0.1:7396", "", "POST", "cross-site", false, ""},
		{"write same-site fetch", "127.0.0.1:7396", "", "PUT", "same-origin", true, ""},
		{"delete none fetch", "127.0.0.1:7396", "", "DELETE", "none", true, ""},
		{"listen host match", "10.0.0.5:8080", "", "GET", "", true, "10.0.0.5:8080"},
	}
	for _, tc := range cases {
		r := httptest.NewRequest(tc.method, "http://"+tc.host+"/api/runs", nil)
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		if tc.fetch != "" {
			r.Header.Set("Sec-Fetch-Site", tc.fetch)
		}
		if got := localDashboardRequest(r, tc.listen); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
