package daemon

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// TokenFileName is the file (inside the data directory) that holds the daemon
// bearer token generated at serve startup.
const TokenFileName = "auth-token"

// TokenPath returns the path of the persisted daemon auth token inside dataDir.
func TokenPath(dataDir string) string {
	return filepath.Join(dataDir, TokenFileName)
}

// ReadAuthToken reads the daemon bearer token persisted by `daemon serve`.
// It returns "" when the file is missing or unreadable; callers treat that as
// "no token configured".
func ReadAuthToken(dataDir string) string {
	raw, err := os.ReadFile(TokenPath(dataDir))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// GenerateAuthToken returns a 256-bit random token, hex encoded.
func GenerateAuthToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// WriteAuthTokenFile persists the daemon bearer token with 0600 permissions.
// An existing file is tightened to 0600 as well (os.WriteFile keeps the old
// mode when the file already exists).
func WriteAuthTokenFile(dataDir, token string) error {
	path := TokenPath(dataDir)
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// resolveClientToken picks the bearer token for an API client: the process
// environment wins (explicit operator choice), then the token file the daemon
// persists in its data directory.
func resolveClientToken(dataDir string) string {
	if v := os.Getenv("AGENTPROV_DAEMON_TOKEN"); v != "" {
		return v
	}
	if dataDir == "" {
		dataDir = ".agentprov" // store.DefaultDataDir
	}
	return ReadAuthToken(dataDir)
}

// csrfGuard runs after withAuth. Authenticated API clients may use arbitrary
// DNS names; open mode trusts only literal addresses and the configured host.
func (s Server) csrfGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if publicHealthRequest(r) {
			next.ServeHTTP(w, r)
			return
		}
		write := r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions
		write = write || (r.URL.Path == "/v1/evidence/manifest" && manifestMaterializationRequested(r))
		if (s.AuthToken == "" && !trustedOpenHost(r.Host, s.ListenAddr)) || !sameOriginRequest(r) ||
			(write && (!sameSiteMetadata(r) || !jsonContentType(r))) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": "untrusted host, cross-origin request, or non-JSON write rejected",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func publicHealthRequest(r *http.Request) bool {
	return r.Method == http.MethodGet && (r.URL.Path == "/v1/health" || r.URL.Path == "/v1/ready" || r.URL.Path == "/v1/live")
}

func trustedOpenHost(authority, listen string) bool {
	host, _, ok := originAuthority(authority, "http")
	if !ok {
		return false
	}
	host = strings.TrimSuffix(host, ".")
	if strings.EqualFold(host, "localhost") || net.ParseIP(host) != nil {
		return true
	}
	configured, _, ok := originAuthority(listen, "http")
	return ok && strings.EqualFold(host, strings.TrimSuffix(configured, "."))
}

func sameSiteMetadata(r *http.Request) bool {
	values := r.Header.Values("Sec-Fetch-Site")
	return len(values) == 0 || (len(values) == 1 && (values[0] == "same-origin" || values[0] == "none"))
}

// sameOriginRequest reports whether a request that carries an Origin header is
// same-origin. Requests without an Origin header (curl, the CLI) pass.
func sameOriginRequest(r *http.Request) bool {
	values := r.Header.Values("Origin")
	if len(values) == 0 {
		return true
	}
	if len(values) != 1 {
		return false
	}
	u, err := url.Parse(values[0])
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if err != nil || u.Scheme != scheme || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(values[0], "#") {
		return false
	}
	fromHost, fromPort, fromOK := originAuthority(u.Host, scheme)
	toHost, toPort, toOK := originAuthority(r.Host, scheme)
	return fromOK && toOK && strings.EqualFold(fromHost, toHost) && fromPort == toPort
}

// originAuthority validates a host/port without resolving DNS. Default ports
// compare equally to their explicit form, as they do in a browser origin.
func originAuthority(authority, scheme string) (string, string, bool) {
	u, err := url.Parse(scheme + "://" + authority)
	if err != nil || u.Host == "" || u.Host != authority || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", "", false
	}
	host, port := u.Hostname(), u.Port()
	if host == "" {
		return "", "", false
	}
	if port == "" {
		port = "80"
		if scheme == "https" {
			port = "443"
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", "", false
	}
	return host, strconv.Itoa(n), true
}

// Only truly empty writes may omit Content-Type, including chunked empty bodies.
func jsonContentType(r *http.Request) bool {
	values := r.Header.Values("Content-Type")
	if len(values) == 0 {
		if r.Body == nil || r.Body == http.NoBody {
			return true
		}
		if r.ContentLength > 0 {
			return false
		}
		var first [1]byte
		n, err := io.ReadFull(r.Body, first[:])
		if n > 0 {
			r.Body = struct {
				io.Reader
				io.Closer
			}{io.MultiReader(bytes.NewReader(first[:n]), r.Body), r.Body}
		}
		return n == 0 && err == io.EOF
	}
	if len(values) != 1 {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(values[0])
	if err != nil {
		return false
	}
	return mediaType == "application/json"
}
