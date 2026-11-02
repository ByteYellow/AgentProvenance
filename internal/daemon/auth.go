package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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

// csrfGuard rejects browser-initiated cross-site write requests (drive-by
// no-cors POST, form POST, DNS-rebinding pages). Rules for every non-GET
// request: a cross-origin Origin header is rejected, Sec-Fetch-Site: cross-site
// is rejected, and a non-application/json Content-Type is rejected. Plain API
// clients (curl, the CLI) send neither Origin nor Sec-Fetch headers and post
// JSON, so they are unaffected. GET/HEAD/OPTIONS stay exempt.
func csrfGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		if !sameOriginRequest(r) || r.Header.Get("Sec-Fetch-Site") == "cross-site" || !jsonContentType(r) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": "cross-site or non-JSON write requests are rejected by this daemon",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sameOriginRequest reports whether a request that carries an Origin header is
// same-origin. Requests without an Origin header (curl, the CLI) pass.
func sameOriginRequest(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.Host != r.Host {
		return false
	}
	return true
}

// jsonContentType reports whether the request's Content-Type is
// application/json (parameters such as charset are ignored). A missing
// Content-Type header passes: the daemon's own clients always set JSON, and
// bodyless writes (e.g. DELETE) legitimately omit it. Browsers always attach a
// Content-Type to POSTs, so cross-site text/plain / form-urlencoded drive-by
// requests are rejected.
func jsonContentType(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return true
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mediaType == "application/json"
}
