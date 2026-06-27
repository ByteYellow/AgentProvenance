package daemon

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/byteyellow/agentprovenance/internal/store"
)

// LockInfo records which process owns a data dir as the control daemon.
type LockInfo struct {
	PID       int    `json:"pid"`
	Addr      string `json:"addr"`
	StartedAt string `json:"started_at"`
}

func lockPath(dataDir string) (string, error) {
	paths, err := store.Init(dataDir)
	if err != nil {
		return "", err
	}
	return filepath.Join(paths.Root, ".daemon.lock"), nil
}

// AcquireLock records that this process owns dataDir as the control daemon and
// returns a release func to remove the lock on shutdown. A stale lock (its pid
// is gone) is overwritten. The lock is advisory: it powers WarnIfDaemonActive so
// direct CLI writes can surface the two-writer hazard, not a hard mutex.
func AcquireLock(dataDir, addr string) (func(), error) {
	path, err := lockPath(dataDir)
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(LockInfo{
		PID:       os.Getpid(),
		Addr:      addr,
		StartedAt: time.Now().UTC().Format(time.RFC3339),
	})
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return nil, err
	}
	return func() { _ = os.Remove(path) }, nil
}

// ActiveLock returns the lock info if a live daemon currently owns dataDir.
func ActiveLock(dataDir string) (LockInfo, bool) {
	path, err := lockPath(dataDir)
	if err != nil {
		return LockInfo{}, false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return LockInfo{}, false
	}
	var info LockInfo
	if json.Unmarshal(raw, &info) != nil || info.PID <= 0 {
		return LockInfo{}, false
	}
	if info.PID == os.Getpid() || !processAlive(info.PID) {
		return LockInfo{}, false
	}
	return info, true
}

// WarnIfDaemonActive prints a stderr warning when a live daemon owns dataDir, so
// a direct CLI write knows it may diverge from the daemon's in-memory state.
// It never blocks the command (WAL keeps the file safe; the risk is logical).
func WarnIfDaemonActive(dataDir string, w io.Writer) {
	if info, ok := ActiveLock(dataDir); ok {
		fmt.Fprintf(w, "warning: a daemon (pid %d, %s) owns this data dir; a direct CLI write can diverge from daemon state. Route writes through --daemon-url http://%s instead.\n", info.PID, info.Addr, info.Addr)
	}
}

func processAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}
