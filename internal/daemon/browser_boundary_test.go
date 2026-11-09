package daemon

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDaemonBrowserBoundaryControls(t *testing.T) {
	for _, tc := range []struct {
		name, host, configured, auth, token, method, body, ct, origin string
		want                                                          int
	}{
		{name: "localhost", host: "LOCALHOST.:8574", want: 204},
		{name: "IPv4", host: "127.0.0.1:8574", want: 204},
		{name: "IPv6", host: "[::1]:8574", want: 204},
		{name: "LAN IP", host: "192.0.2.10:8574", want: 204},
		{name: "configured host", host: "LAB.EXAMPLE:8574", configured: "lab.example:8574", want: 204},
		{name: "hostname suffix", host: "lab.example.evil:8574", configured: "lab.example:8574", want: 403},
		{name: "wildcard listen", host: "evil.example:8574", configured: "0.0.0.0:8574", want: 403},
		{name: "authenticated DNS client", host: "api.example:8574", auth: "fixture-token", token: "fixture-token", want: 204},
		{name: "missing token", host: "api.example:8574", auth: "fixture-token", want: 401},
		{name: "wrong token", host: "api.example:8574", auth: "fixture-token", token: "wrong", want: 401},
		{name: "empty DELETE", host: "localhost", method: "DELETE", want: 204},
		{name: "empty POST", host: "localhost", method: "POST", want: 204},
		{name: "JSON body", host: "localhost", method: "POST", body: `{"example":1}`, ct: "application/json; charset=utf-8", want: 204},
		{name: "missing JSON type", host: "localhost", method: "POST", body: `{}`, want: 403},
		{name: "malformed type", host: "localhost", method: "POST", body: `{}`, ct: "application/json;broken", want: 403},
		{name: "authenticated hostile origin", host: "api.example:8574", auth: "fixture-token", token: "fixture-token", origin: "http://other.example", want: 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := Server{AuthToken: tc.auth, ListenAddr: tc.configured}
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != tc.body {
					t.Errorf("body changed: %q err=%v", body, err)
				}
				w.WriteHeader(http.StatusNoContent)
			})
			srv := httptest.NewServer(s.withAuth(s.csrfGuard(next)))
			defer srv.Close()
			method := tc.method
			if method == "" {
				method = http.MethodGet
			}
			req, _ := http.NewRequest(method, srv.URL+"/v1/probe", strings.NewReader(tc.body))
			req.Host = tc.host
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			if tc.ct != "" {
				req.Header.Set("Content-Type", tc.ct)
			}
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("status=%d want=%d", resp.StatusCode, tc.want)
			}
		})
	}
}

func TestDaemonOriginCanonicalization(t *testing.T) {
	for _, tc := range []struct {
		host, origin string
		tls, want    bool
	}{
		{"LOCALHOST", "http://localhost:80", false, true},
		{"localhost:80", "http://LOCALHOST", false, true},
		{"[::1]:443", "https://[::1]", true, true},
		{"localhost", "https://localhost", true, true},
		{"localhost", "http://localhost:81", false, false},
		{"localhost", "http://localhost/", false, false},
		{"localhost", "http://localhost?", false, false},
		{"localhost", "http://localhost#", false, false},
		{"localhost", "null", false, false},
		{"localhost", "http://localhost:70000", false, false},
		{"localhost", "http://localhost", true, false},
	} {
		req := httptest.NewRequest("POST", "http://localhost/v1/probe", nil)
		req.Host = tc.host
		req.Header.Set("Origin", tc.origin)
		if tc.tls {
			req.TLS = &tls.ConnectionState{}
		}
		if got := sameOriginRequest(req); got != tc.want {
			t.Errorf("%+v: got %v", tc, got)
		}
	}
}

func TestDaemonClientEmptyAndStreamingWrites(t *testing.T) {
	s := Server{AuthToken: "fixture-token"}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/sessions/example/exec":
			if !strings.Contains(r.Header.Get("Content-Type"), "application/json") {
				t.Error("missing JSON")
			}
			body, _ := io.ReadAll(r.Body)
			if !bytes.Contains(body, []byte(`"command"`)) {
				t.Errorf("lost stream request body: %s", body)
			}
			w.Write([]byte("first\n"))
			w.(http.Flusher).Flush()
			w.Write([]byte("second\n"))
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	})
	srv := httptest.NewServer(s.withAuth(s.csrfGuard(next)))
	defer srv.Close()
	c := Client{BaseURL: srv.URL, HTTP: srv.Client(), Token: s.AuthToken}
	if err := c.RemoveSession("example"); err != nil {
		t.Fatal(err)
	}
	if err := c.StopSession("example"); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if _, err := c.Exec("example", []string{"printf", "sample"}, true, &output); err != nil {
		t.Fatal(err)
	}
	if output.String() != "first\nsecond\n" {
		t.Fatalf("stream changed: %q", output.String())
	}
}

func TestDaemonManifestClientUsesExplicitWrite(t *testing.T) {
	for _, auth := range []string{"", "fixture-token"} {
		s := testServer(t)
		s.AuthToken = auth
		srv := httptest.NewServer(s.Handler())
		client := Client{BaseURL: srv.URL, HTTP: srv.Client(), Token: auth}
		result, err := client.EvidenceManifest("example", true)
		if err != nil || result.ObjectHash == "" {
			t.Fatalf("materialize auth=%t: %+v %v", auth != "", result, err)
		}
		if _, err := client.EvidenceManifest("example", false); err != nil {
			t.Fatal(err)
		}
		// Token-authenticated legacy GET remains available for older clients.
		if auth != "" {
			req, _ := http.NewRequest("GET", srv.URL+"/v1/evidence/manifest?run=example&materialize=true", nil)
			req.Header.Set("Authorization", "Bearer "+auth)
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatalf("legacy authenticated GET status=%d", resp.StatusCode)
			}
		}
		srv.Close()
	}
}

func TestOpenDaemonRejectsRebindingHosts(t *testing.T) {
	s, srv, _ := csrfFixture(t)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, auth := range []string{"", "Bearer forged-token"} {
			path, body := "/v1/sessions", ""
			if method == http.MethodPost {
				path, body = "/v1/leases", `{"task":"task.yaml"}`
			}
			req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
			req.Host = "rebind.example:8574"
			req.Header.Set("Authorization", auth)
			if method == http.MethodPost {
				req.Header.Set("Origin", "http://"+req.Host)
				req.Header.Set("Sec-Fetch-Site", "same-origin")
				req.Header.Set("Content-Type", "application/json")
			}
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s auth=%q: status=%d, want 403", method, auth, resp.StatusCode)
			}
		}
	}
	var count int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM leases`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rebound writes reached storage: count=%d err=%v", count, err)
	}
}

func TestDaemonRejectsMalformedOriginsAndWriteMetadata(t *testing.T) {
	_, srv, _ := csrfFixture(t)
	host := strings.TrimPrefix(srv.URL, "http://")
	for name, headers := range map[string]map[string]string{
		"scheme":       {"Origin": "https://" + host},
		"userinfo":     {"Origin": "http://user@" + host},
		"path":         {"Origin": srv.URL + "/path"},
		"query":        {"Origin": srv.URL + "?x=1"},
		"fragment":     {"Origin": srv.URL + "#part"},
		"same-site":    {"Sec-Fetch-Site": "same-site"},
		"unknown site": {"Sec-Fetch-Site": "unexpected"},
	} {
		t.Run(name, func(t *testing.T) {
			resp := doWrite(t, srv.URL, "/v1/leases", "application/json", headers, `{"task":"task.yaml"}`)
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status=%d, want 403", resp.StatusCode)
			}
		})
	}
}

func TestDaemonBodyWithoutContentTypeIsNotAnEmptyWrite(t *testing.T) {
	_, srv, _ := csrfFixture(t)
	for _, chunked := range []bool{false, true} {
		var body io.Reader = strings.NewReader(`{"task":"task.yaml"}`)
		if chunked {
			body = struct{ io.Reader }{body}
		}
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/leases", body)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("chunked=%v: status=%d, want 403", chunked, resp.StatusCode)
		}
	}
}

func TestOpenDaemonManifestGETDoesNotWrite(t *testing.T) {
	s := testServer(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	for _, site := range []string{"", "cross-site"} {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/evidence/manifest?run=demo&materialize=1", nil)
		req.Header.Set("Sec-Fetch-Site", site)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("site=%q: status=%d, want blocked materialization", site, resp.StatusCode)
		}
	}
	var count int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM provenance_objects`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("GET created objects: count=%d err=%v", count, err)
	}
}
