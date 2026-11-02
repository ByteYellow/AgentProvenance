package daemon_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/daemon"
)

// TestNewClientResolvesTokenFromDataDir verifies that the daemon client
// resolves its bearer token from the data directory passed to NewClient, so
// CLI commands keep working when `daemon serve` runs with a custom --data-dir.
func TestNewClientResolvesTokenFromDataDir(t *testing.T) {
	t.Setenv("AGENTPROV_DAEMON_TOKEN", "") // the token file, not the environment, must win here

	const token = "datadir-token"
	dataDir := t.TempDir()
	if err := daemon.WriteAuthTokenFile(dataDir, token); err != nil {
		t.Fatal(err)
	}
	wrongDir := t.TempDir()
	if err := daemon.WriteAuthTokenFile(wrongDir, "wrong-token"); err != nil {
		t.Fatal(err)
	}

	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if gotAuth != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sessions":[]}`))
	}))
	defer server.Close()

	client := daemon.NewClient(server.URL, dataDir)
	if _, err := client.ListSessions(); err != nil {
		t.Fatalf("token from custom data dir must authenticate: %v", err)
	}
	if gotAuth != "Bearer "+token {
		t.Fatalf("authorization header=%q", gotAuth)
	}

	// A client pointed at an unrelated data directory reads that directory's
	// token and is rejected by the daemon.
	misdirected := daemon.NewClient(server.URL, wrongDir)
	if _, err := misdirected.ListSessions(); err == nil {
		t.Fatal("token from wrong data dir must be rejected")
	}
	if gotAuth != "Bearer wrong-token" {
		t.Fatalf("wrong data dir token not used: header=%q", gotAuth)
	}

	// An empty data dir falls back to the default ".agentprov" directory,
	// which holds no matching token here, so the request stays unauthorized.
	defaulted := daemon.NewClient(server.URL, "")
	if _, err := defaulted.ListSessions(); err == nil {
		t.Fatal("default data dir without matching token must be rejected")
	}
}
