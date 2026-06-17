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

func TestTraceArtifactShowsReverseProvenance(t *testing.T) {
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
	artifactRef := filepath.Join(paths.Artifacts, "attempt-1-result.txt")
	insertTraceSnapshot(t, db, "snap-1", "ready", now)
	_, err = db.Exec(`INSERT INTO rollouts (id, run_id, base_snapshot_id, status, fanout, winner_attempt_id, cost_estimate, risk_status, created_at, updated_at)
		VALUES ('rollout-1', 'run-1', 'snap-1', 'completed', 1, 'attempt-1', 0.001, 'clean', ?, ?)`, now, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO fork_attempts
		(id, rollout_id, tool_call_id, snapshot_id, workspace_path, fork_ms, strategy, status, score, cost_estimate, is_winner, artifact_result, created_at)
		VALUES ('attempt-1', 'rollout-1', 'tool-1', 'snap-1', ?, 1, 'artifact', 'passed', 7, 0.001, 1, ?, ?)`,
		filepath.Join(root, "attempt-1"), artifactRef, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO tool_calls
		(id, run_id, rollout_id, attempt_id, command, status, exit_code, wall_ms, result_ref, created_at)
		VALUES ('tool-1', 'run-1', 'rollout-1', 'attempt-1', 'echo artifact', 'passed', 0, 10, ?, ?)`, artifactRef, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO graph_edges (id, run_id, rollout_id, from_id, to_id, edge_type, source_event_id, created_at)
		VALUES ('edge-attempt-artifact', 'run-1', 'rollout-1', 'attempt-1', ?, 'attempt_artifact', 'evidence-1', ?)`, artifactRef, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO graph_edges (id, run_id, rollout_id, from_id, to_id, edge_type, source_event_id, created_at)
		VALUES ('edge-tool-artifact', 'run-1', 'rollout-1', 'tool-1', ?, 'tool_call_artifact', 'evidence-1', ?)`, artifactRef, now)
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := TraceArtifact(db, artifactRef, &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{
		"artifact=" + artifactRef,
		"type=attempt_artifact",
		"type=tool_call_artifact",
		"attempt=attempt-1",
		"tool_call=tool-1",
		"rollout=rollout-1",
		"winner=true",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("artifact trace missing %q:\n%s", want, got)
		}
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
