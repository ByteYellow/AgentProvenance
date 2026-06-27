package daemon

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDaemonLockLifecycle(t *testing.T) {
	dir := t.TempDir()

	// No lock yet -> no warning, not active.
	var buf bytes.Buffer
	WarnIfDaemonActive(dir, &buf)
	if buf.Len() != 0 {
		t.Fatalf("expected no warning with no lock, got %q", buf.String())
	}
	if _, ok := ActiveLock(dir); ok {
		t.Fatal("expected no active lock")
	}

	// A live OTHER process owns the data dir.
	child := exec.Command("sleep", "30")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _, _ = child.Process.Wait() }()
	path, err := lockPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(LockInfo{PID: child.Process.Pid, Addr: "127.0.0.1:8574"})
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	info, ok := ActiveLock(dir)
	if !ok || info.PID != child.Process.Pid {
		t.Fatalf("expected active lock for child pid %d, got %+v ok=%v", child.Process.Pid, info, ok)
	}
	buf.Reset()
	WarnIfDaemonActive(dir, &buf)
	if !strings.Contains(buf.String(), "owns this data dir") {
		t.Fatalf("expected two-writer warning, got %q", buf.String())
	}

	// Stale lock (dead pid) -> not active.
	_ = child.Process.Kill()
	_, _ = child.Process.Wait()
	if _, ok := ActiveLock(dir); ok {
		t.Fatal("expected stale lock (dead pid) to be inactive")
	}

	// AcquireLock writes our own lock; release removes it.
	release, err := AcquireLock(dir, "127.0.0.1:9000")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), ".daemon.lock")); err != nil {
		t.Fatalf("expected lock file written: %v", err)
	}
	release()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected lock removed after release, stat err=%v", err)
	}
}
