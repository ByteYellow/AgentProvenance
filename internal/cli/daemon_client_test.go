package cli

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/daemon"
	"github.com/spf13/cobra"
)

func TestDaemonClientUsesCommandDataDir(t *testing.T) {
	t.Setenv("AGENTPROV_DAEMON_TOKEN", "")
	for _, args := range [][]string{{"session", "list"}, {"session", "create", "--lease", "test-lease"}} {
		t.Run(args[1], func(t *testing.T) {
			commands := make([]*cobra.Command, 0, 2)
			for _, token := range []string{"first-test-token", "second-test-token"} {
				dir := t.TempDir()
				if err := daemon.WriteAuthTokenFile(dir, token); err != nil {
					t.Fatal(err)
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Authorization") != "Bearer "+token {
						http.Error(w, "wrong data directory credentials", http.StatusUnauthorized)
						return
					}
					if r.URL.Path != "/v1/sessions" {
						http.NotFound(w, r)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, `{"sessions":[],"session_id":"test-session"}`)
				}))
				t.Cleanup(server.Close)
				cmd := NewRootCommand()
				cmd.SetOut(io.Discard)
				cmd.SetErr(io.Discard)
				cmd.SetArgs(append([]string{"--data-dir", dir, "--daemon-url", server.URL}, args...))
				commands = append(commands, cmd)
			}
			// Construct both roots before executing either: each must retain its own flags.
			for i, cmd := range commands {
				if err := cmd.Execute(); err != nil {
					t.Fatalf("command %d: %v", i+1, err)
				}
			}
		})
	}
}

func TestDaemonClientHelperUsesExplicitDataDir(t *testing.T) {
	t.Setenv("AGENTPROV_DAEMON_TOKEN", "")
	dir := t.TempDir()
	if err := daemon.WriteAuthTokenFile(dir, "helper-test-token"); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer helper-test-token" {
			http.Error(w, "wrong data directory credentials", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"sessions":[]}`)
	}))
	defer server.Close()
	NewRootCommand()
	if _, err := listSessions(dir, server.URL); err != nil {
		t.Fatal(err)
	}
}
