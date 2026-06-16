package provenance

import (
	"bytes"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestTraceRunFiltersSnapshotPlansToRun(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".acf"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	insertTraceSnapshot(t, db, "snap-run1", "ready", now)
	insertTraceSnapshot(t, db, "snap-run2", "ready", now)
	_, err = db.Exec(`INSERT INTO rollouts (id, run_id, base_snapshot_id, status, fanout, created_at, updated_at)
		VALUES ('rollout-run1', 'run-1', 'snap-run1', 'completed', 1, ?, ?)`, now, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO rollouts (id, run_id, base_snapshot_id, status, fanout, created_at, updated_at)
		VALUES ('rollout-run2', 'run-2', 'snap-run2', 'completed', 1, ?, ?)`, now, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO fork_attempts (id, rollout_id, snapshot_id, workspace_path, fork_ms, status, created_at)
		VALUES ('attempt-run1', 'rollout-run1', 'snap-run1', ?, 1, 'completed', ?)`, filepath.Join(root, "attempt-run1"), now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO fork_attempts (id, rollout_id, snapshot_id, workspace_path, fork_ms, status, created_at)
		VALUES ('attempt-run2', 'rollout-run2', 'snap-run2', ?, 1, 'completed', ?)`, filepath.Join(root, "attempt-run2"), now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO snapshot_edges (id, parent_id, child_id, edge_type, plan, plan_reason, planner_score, created_at)
		VALUES ('edge-run1', 'snap-run1', 'attempt-run1', 'fork', 'copy', 'policy=smallest-delta delta_added=1', 1000, ?)`, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO snapshot_edges (id, parent_id, child_id, edge_type, plan, plan_reason, planner_score, created_at)
		VALUES ('edge-run2', 'snap-run2', 'attempt-run2', 'fork', 'copy', 'policy=latest-ready delta_added=99', 1000, ?)`, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO snapshot_edges (id, parent_id, child_id, edge_type, plan, plan_reason, planner_score, created_at)
		VALUES ('edge-same-parent-other-attempt', 'snap-run1', 'attempt-not-in-run', 'fork', 'copy', 'policy=local unrelated_attempt=true', 1000, ?)`, now)
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := TraceRun(db, "run-1", &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "snapshot_plans:") || !strings.Contains(got, "policy=smallest-delta") {
		t.Fatalf("trace did not include run-1 planner explanation:\n%s", got)
	}
	if strings.Contains(got, "snap-run2") ||
		strings.Contains(got, "policy=latest-ready delta_added=99") ||
		strings.Contains(got, "attempt-not-in-run") ||
		strings.Contains(got, "unrelated_attempt=true") {
		t.Fatalf("trace leaked run-2 snapshot data:\n%s", got)
	}
}

func insertTraceSnapshot(t *testing.T, db *sql.DB, id, name, createdAt string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO snapshots (id, name, kind, source, path, manifest_hash, file_count, bytes, status, created_at)
		VALUES (?, ?, 'ready', 'test', ?, 'hash', 1, 1, 'ready', ?)`, id, name, filepath.Join(t.TempDir(), id), createdAt)
	if err != nil {
		t.Fatal(err)
	}
}
