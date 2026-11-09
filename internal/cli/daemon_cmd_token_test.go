package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/daemon"
)

// tokenFileSnapshot captures the bytes and mtime of the persisted auth-token
// file so tests can assert "nothing was rotated".
type tokenFileSnapshot struct {
	data    []byte
	modTime int64
}

func snapTokenFile(t *testing.T, dataDir string) tokenFileSnapshot {
	t.Helper()
	raw, err := os.ReadFile(daemon.TokenPath(dataDir))
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}
	info, err := os.Stat(daemon.TokenPath(dataDir))
	if err != nil {
		t.Fatalf("stat token file: %v", err)
	}
	return tokenFileSnapshot{data: raw, modTime: info.ModTime().UnixNano()}
}

// TestResolveServeTokenMatrix pins the serve token decision order:
// explicit flag/env wins (never persisted) > --insecure-open (no token) >
// reuse the persisted token (no rotation) > generate+persist (first start).
func TestResolveServeTokenMatrix(t *testing.T) {
	const persisted = "persisted-token-t1"

	writeToken := func(t *testing.T, dir, token string) {
		t.Helper()
		if err := os.WriteFile(daemon.TokenPath(dir), []byte(token+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("existing token file is reused, never rotated", func(t *testing.T) {
		dir := t.TempDir()
		writeToken(t, dir, persisted)
		before := snapTokenFile(t, dir)

		var stdout, stderr bytes.Buffer
		got, err := resolveServeToken(dir, "", false, "127.0.0.1:8574", &stdout, &stderr)
		if err != nil {
			t.Fatal(err)
		}
		if got != persisted {
			t.Fatalf("token = %q, want reused %q", got, persisted)
		}
		after := snapTokenFile(t, dir)
		if !bytes.Equal(before.data, after.data) || before.modTime != after.modTime {
			t.Fatalf("token file was rewritten: before=%q@%d after=%q@%d", before.data, before.modTime, after.data, after.modTime)
		}
		if out := stdout.String(); out != "" {
			t.Fatalf("stdout must not print the reused token, got %q", out)
		}
		if msg := stderr.String(); !strings.Contains(msg, "reusing existing auth token from") || strings.Contains(msg, persisted) {
			t.Fatalf("stderr should name the token file but not the token, got %q", msg)
		}
	})

	t.Run("explicit flag token wins and is not persisted", func(t *testing.T) {
		dir := t.TempDir()
		writeToken(t, dir, persisted)
		before := snapTokenFile(t, dir)

		var stdout, stderr bytes.Buffer
		got, err := resolveServeToken(dir, "explicit-t2", false, "127.0.0.1:8574", &stdout, &stderr)
		if err != nil {
			t.Fatal(err)
		}
		if got != "explicit-t2" {
			t.Fatalf("token = %q, want explicit %q", got, "explicit-t2")
		}
		after := snapTokenFile(t, dir)
		if !bytes.Equal(before.data, after.data) || before.modTime != after.modTime {
			t.Fatalf("explicit token must not touch the token file")
		}
		if stdout.Len() != 0 || stderr.Len() != 0 {
			t.Fatalf("explicit path must be silent, stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
	})

	t.Run("env token wins over file", func(t *testing.T) {
		dir := t.TempDir()
		writeToken(t, dir, persisted)
		t.Setenv("AGENTPROV_DAEMON_TOKEN", "env-t3")
		var stdout, stderr bytes.Buffer
		got, err := resolveServeToken(dir, "", false, "127.0.0.1:8574", &stdout, &stderr)
		if err != nil {
			t.Fatal(err)
		}
		if got != "env-t3" {
			t.Fatalf("token = %q, want env %q", got, "env-t3")
		}
		if after := snapTokenFile(t, dir); !bytes.Equal(after.data, []byte(persisted+"\n")) {
			t.Fatalf("env token must not rewrite the token file, got %q", after.data)
		}
	})

	t.Run("insecure-open runs without token and warns", func(t *testing.T) {
		dir := t.TempDir()
		var stdout, stderr bytes.Buffer
		got, err := resolveServeToken(dir, "", true, "127.0.0.1:8574", &stdout, &stderr)
		if err != nil {
			t.Fatal(err)
		}
		if got != "" {
			t.Fatalf("token = %q, want empty under --insecure-open", got)
		}
		if _, err := os.Stat(daemon.TokenPath(dir)); !os.IsNotExist(err) {
			t.Fatalf("insecure-open must not create a token file, stat err = %v", err)
		}
		if msg := stderr.String(); !strings.Contains(msg, "WARNING: --insecure-open") {
			t.Fatalf("missing insecure-open warning, got %q", msg)
		}
	})

	t.Run("first start generates, persists 0600 and prints once", func(t *testing.T) {
		dir := t.TempDir()
		var stdout, stderr bytes.Buffer
		got, err := resolveServeToken(dir, "", false, "127.0.0.1:8574", &stdout, &stderr)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 64 {
			t.Fatalf("generated token = %q, want 64 hex chars", got)
		}
		raw, err := os.ReadFile(daemon.TokenPath(dir))
		if err != nil || string(raw) != got+"\n" {
			t.Fatalf("token file = %q (err %v), want generated token", raw, err)
		}
		if info, err := os.Stat(daemon.TokenPath(dir)); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("token file mode = %v (err %v), want 0600", info, err)
		}
		if out := stdout.String(); !strings.Contains(out, "daemon auth token generated") || !strings.Contains(out, got) {
			t.Fatalf("first-start stdout format changed, got %q", out)
		}
		if stderr.Len() != 0 {
			t.Fatalf("generation must stay on stdout, stderr = %q", stderr.String())
		}
	})
}

// TestServeSecondInstanceKeepsTokenAndFails is the P1 regression: a second
// `daemon serve` on an already-owned data dir must exit with an error BEFORE
// reading, rotating or rewriting the auth token, so the running daemon and its
// clients keep matching credentials.
func TestServeSecondInstanceKeepsTokenAndFails(t *testing.T) {
	const firstToken = "first-daemon-token-t1"
	dataDir := t.TempDir()
	if err := daemon.WriteAuthTokenFile(dataDir, firstToken); err != nil {
		t.Fatal(err)
	}
	before := snapTokenFile(t, dataDir)

	// Occupy the instance lock with a live foreign process (same trick as
	// internal/daemon/lock_test.go): serve must see ActiveLock and refuse.
	child := exec.Command("sleep", "30")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _, _ = child.Process.Wait() })
	lockPath := filepath.Join(dataDir, ".daemon.lock")
	raw, _ := json.Marshal(daemon.LockInfo{PID: child.Process.Pid, Addr: "127.0.0.1:8574"})
	if err := os.WriteFile(lockPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	dataDirPtr := dataDir
	root := daemonCmd(&dataDirPtr)
	serveCmd, _, err := root.Find([]string{"serve"})
	if err != nil {
		t.Fatal(err)
	}
	execErr := serveCmd.RunE(serveCmd, []string{})
	if execErr == nil {
		t.Fatal("second serve against a live daemon must fail")
	}
	if msg := execErr.Error(); !strings.Contains(msg, "already owns data dir") || !strings.Contains(msg, "pid") {
		t.Fatalf("unexpected error %q, want an already-running-daemon refusal", msg)
	}

	// Core assertion: the failed startup did not touch the live credentials.
	after := snapTokenFile(t, dataDir)
	if !bytes.Equal(before.data, after.data) || before.modTime != after.modTime {
		t.Fatalf("failed startup rotated the token: before=%q@%d after=%q@%d", before.data, before.modTime, after.data, after.modTime)
	}
	if got := daemon.ReadAuthToken(dataDir); got != firstToken {
		t.Fatalf("ReadAuthToken = %q, want %q", got, firstToken)
	}

	// The lock must still belong to the first daemon, not to this process.
	var info daemon.LockInfo
	lockRaw, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(lockRaw, &info); err != nil {
		t.Fatal(err)
	}
	if info.PID != child.Process.Pid {
		t.Fatalf("lock pid = %d, want first daemon pid %d (second serve must not take the lock)", info.PID, child.Process.Pid)
	}
}
