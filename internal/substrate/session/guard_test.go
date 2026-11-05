package session

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func newGuardDB(t *testing.T) *sql.DB {
	t.Helper()
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func insertLease(t *testing.T, db *sql.DB, id, status string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(`INSERT INTO leases (id, run_id, task_path, task_yaml, status, created_at, updated_at)
		VALUES (?, 'run-guard', '', '', ?, ?, ?)`, id, status, now, now); err != nil {
		t.Fatal(err)
	}
}

func insertSession(t *testing.T, db *sql.DB, id, leaseID, containerID, status string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(`INSERT INTO sessions (id, lease_id, run_id, container_id, workspace_host_path, runtime, status, startup_cold_ms, created_at, updated_at)
		VALUES (?, ?, 'run-guard', ?, '/tmp/ws-guard', 'docker', ?, 0, ?, ?)`, id, leaseID, containerID, status, now, now); err != nil {
		t.Fatal(err)
	}
}

func TestGuardExecAllowsRunningSessionWithActiveLease(t *testing.T) {
	db := newGuardDB(t)
	insertLease(t, db, "lease-ok", "allocated")
	insertSession(t, db, "sbx-ok", "lease-ok", "ctr-ok", "running")

	if err := GuardExec(db, "sbx-ok"); err != nil {
		t.Fatalf("GuardExec returned %v, want nil", err)
	}
}

func TestGuardExecRejectsUnknownSessionWithoutExistenceOracle(t *testing.T) {
	db := newGuardDB(t)
	err := GuardExec(db, "sbx-missing")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("err = %v, want ErrSessionNotFound", err)
	}
	if strings.Contains(err.Error(), "sql: no rows") || strings.Contains(err.Error(), "no rows in result set") {
		t.Fatalf("error leaks driver detail: %v", err)
	}
}

func TestGuardExecRejectsStoppedAndRemovedSessions(t *testing.T) {
	db := newGuardDB(t)
	insertLease(t, db, "lease-a", "allocated")
	insertLease(t, db, "lease-b", "allocated")
	insertSession(t, db, "sbx-stopped", "lease-a", "ctr-a", "stopped")
	insertSession(t, db, "sbx-removed", "lease-b", "", "removed")

	for _, id := range []string{"sbx-stopped", "sbx-removed"} {
		err := GuardExec(db, id)
		if !errors.Is(err, ErrSessionNotRunning) {
			t.Fatalf("GuardExec(%s) = %v, want ErrSessionNotRunning", id, err)
		}
	}
}

func TestGuardExecRejectsRunningSessionWithoutContainer(t *testing.T) {
	db := newGuardDB(t)
	insertLease(t, db, "lease-c", "allocated")
	insertSession(t, db, "sbx-noctr", "lease-c", "", "running")

	if err := GuardExec(db, "sbx-noctr"); !errors.Is(err, ErrSessionNotRunning) {
		t.Fatalf("err = %v, want ErrSessionNotRunning", err)
	}
}

func TestGuardExecRejectsInactiveLease(t *testing.T) {
	db := newGuardDB(t)
	insertLease(t, db, "lease-stopped", "stopped")
	insertLease(t, db, "lease-revoked", "revoked")
	insertSession(t, db, "sbx-lease-stopped", "lease-stopped", "ctr-s", "running")
	insertSession(t, db, "sbx-lease-revoked", "lease-revoked", "ctr-r", "running")

	for _, id := range []string{"sbx-lease-stopped", "sbx-lease-revoked"} {
		err := GuardExec(db, id)
		if !errors.Is(err, ErrLeaseInactive) {
			t.Fatalf("GuardExec(%s) = %v, want ErrLeaseInactive", id, err)
		}
	}
}

func TestGuardExecRejectsMissingLeaseRow(t *testing.T) {
	db := newGuardDB(t)
	// store.Open 的 DSN 对所有连接开了 foreign_keys：借单条连接临时关掉 FK，
	// 插入 lease 行缺失的会话，覆盖 guard 的 lease 不存在分支。
	conn, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := conn.ExecContext(t.Context(), `PRAGMA foreign_keys = OFF`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(t.Context(), `INSERT INTO sessions (id, lease_id, run_id, container_id, workspace_host_path, runtime, status, startup_cold_ms, created_at, updated_at)
		VALUES ('sbx-orphan', 'lease-ghost', 'run-guard', 'ctr-o', '/tmp/ws-guard', 'docker', 'running', 0, ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	if err := GuardExec(db, "sbx-orphan"); !errors.Is(err, ErrLeaseInactive) {
		t.Fatalf("err = %v, want ErrLeaseInactive", err)
	}
}

func TestGuardExecRequiresDB(t *testing.T) {
	if err := GuardExec(nil, "sbx-x"); err == nil {
		t.Fatalf("GuardExec(nil) must fail")
	}
}
