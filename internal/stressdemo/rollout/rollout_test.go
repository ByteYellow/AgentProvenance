package rollout

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/substrate/state"
)

func TestStartWritesExplainableAttemptEvidence(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	taskPath := filepath.Join(root, "task.yaml")
	if err := writeFile(taskPath, "run_id: run-test\nimage: alpine:3.20\n"); err != nil {
		t.Fatal(err)
	}
	stack, err := state.Service{DB: db, Paths: paths}.CreateStack(taskPath)
	if err != nil {
		t.Fatal(err)
	}

	_, _, winner, _, err := Service{DB: db, Paths: paths}.Start(StartRequest{
		RunID:     "run-test",
		TaskPath:  taskPath,
		Snapshot:  stack.ReadySnapshotID,
		Fanout:    2,
		TopK:      2,
		EarlyStop: true,
		Runtime:   "local",
		Strategies: []string{
			"low-probe::echo SHOULD_NOT_RUN::probe=echo 1::score=number",
			"high-probe::echo winner::probe=echo 10::score=number",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if winner.Strategy != "high-probe" {
		t.Fatalf("winner = %+v, want high-probe", winner)
	}

	payloads := readEvidencePayloads(t, db)
	joined := strings.Join(payloads, "\n")
	for _, want := range []string{
		`"winner":true`,
		`"selection_reason":"winner_selected_by_risk_budget_score_cost"`,
		`"strategy":"high-probe"`,
		`"strategy":"low-probe"`,
		`early_stop_after_winner`,
		`"status":"pruned"`,
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("evidence payloads missing %q:\n%s", want, joined)
		}
	}
}

func TestPromotionBarrierRejectsTaintedAttempt(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	insertRolloutPromotionFixture(t, db, "run-taint", "rollout-taint", "snap-taint", "attempt-taint", "tool-taint", now)
	_, err = db.Exec(`UPDATE fork_attempts SET status = 'quarantined', risk_status = 'tainted' WHERE id = 'attempt-taint'`)
	if err != nil {
		t.Fatal(err)
	}

	promotion, err := (Service{DB: db, Paths: paths}).promoteWithBarrier("rollout-taint", "snap-taint", "attempt-taint")
	if err != nil {
		t.Fatal(err)
	}
	if promotion.Status != "rejected" || promotion.RiskStatus != "tainted" || !strings.Contains(promotion.Reason, "attempt is quarantined or tainted") {
		t.Fatalf("promotion = %+v, want rejected tainted attempt", promotion)
	}
	var promoted int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE event_type = 'winner_promoted' AND json_extract(payload, '$.attempt_id') = 'attempt-taint'`).Scan(&promoted); err != nil {
		t.Fatal(err)
	}
	if promoted != 0 {
		t.Fatalf("winner_promoted events = %d, want 0", promoted)
	}
}

func TestPromotionBarrierRecordsDrainWatermark(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	insertRolloutPromotionFixture(t, db, "run-drain", "rollout-drain", "snap-drain", "attempt-drain", "tool-drain", now)
	svc := Service{DB: db, Paths: paths}
	if err := svc.appendEvidence("run-drain", "rollout-drain", "attempt-drain", "session-drain", "tool-drain", "snap-drain", "attempt_finished", "normal", `{"status":"passed"}`); err != nil {
		t.Fatal(err)
	}

	promotion, err := svc.promoteWithBarrier("rollout-drain", "snap-drain", "attempt-drain")
	if err != nil {
		t.Fatal(err)
	}
	if promotion.Status != "promoted" || promotion.RiskStatus != "clean" {
		t.Fatalf("promotion = %+v, want promoted clean", promotion)
	}
	if promotion.TelemetryWatermark == "" || promotion.DrainStartedAt == "" || promotion.DrainCompletedAt == "" {
		t.Fatalf("promotion missing drain timestamps: %+v", promotion)
	}
	if promotion.DrainQueuedBefore != 1 || promotion.DrainProcessed != 1 || promotion.DrainPendingAfter != 0 {
		t.Fatalf("promotion drain stats = queued_before=%d processed=%d pending_after=%d, want 1/1/0", promotion.DrainQueuedBefore, promotion.DrainProcessed, promotion.DrainPendingAfter)
	}
	var queued int
	if err := db.QueryRow(`SELECT COUNT(*) FROM evidence_events WHERE attempt_id = 'attempt-drain' AND status = 'queued'`).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if queued != 0 {
		t.Fatalf("queued evidence after promotion = %d, want 0", queued)
	}
}

func TestTaintAttemptPropagatesSnapshotDescendants(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	insertRolloutPromotionFixture(t, db, "run-prop", "rollout-prop", "snap-parent", "attempt-prop", "tool-prop", now)
	insertTestSnapshot(t, db, "snap-child", "child", now)
	if _, err := db.Exec(`INSERT INTO snapshot_edges (id, parent_id, child_id, edge_type, plan, created_at)
		VALUES ('edge-prop', 'snap-parent', 'snap-child', 'fork', 'copy', ?)`, now); err != nil {
		t.Fatal(err)
	}

	if err := (Service{DB: db, Paths: paths}).TaintAttempt("attempt-prop", "test taint propagation"); err != nil {
		t.Fatal(err)
	}
	for _, snapshotID := range []string{"snap-parent", "snap-child"} {
		var status string
		var tainted int
		if err := db.QueryRow(`SELECT status, COALESCE(tainted, 0) FROM snapshots WHERE id = ?`, snapshotID).Scan(&status, &tainted); err != nil {
			t.Fatal(err)
		}
		if status != "tainted" || tainted != 1 {
			t.Fatalf("snapshot %s status=%s tainted=%d, want tainted/1", snapshotID, status, tainted)
		}
	}
	var eventCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE event_type IN ('snapshot_tainted', 'snapshot_taint_propagated', 'attempt_quarantined')`).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if eventCount < 3 {
		t.Fatalf("taint event count = %d, want >= 3", eventCount)
	}
}

func writeFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func readEvidencePayloads(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT payload FROM evidence_events ORDER BY created_at`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var payloads []string
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			t.Fatal(err)
		}
		payloads = append(payloads, payload)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return payloads
}

func insertRolloutPromotionFixture(t *testing.T, db *sql.DB, runID, rolloutID, snapshotID, attemptID, toolCallID, now string) {
	t.Helper()
	insertTestSnapshot(t, db, snapshotID, "ready", now)
	if _, err := db.Exec(`INSERT INTO rollouts (id, run_id, base_snapshot_id, status, fanout, winner_attempt_id, risk_status, created_at, updated_at)
		VALUES (?, ?, ?, 'running', 1, ?, 'pending', ?, ?)`, rolloutID, runID, snapshotID, attemptID, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO fork_attempts
		(id, rollout_id, tool_call_id, snapshot_id, workspace_path, fork_ms, strategy, command, status, risk_status, score, is_winner, created_at)
		VALUES (?, ?, ?, ?, ?, 1, 'test', 'echo test', 'passed', 'clean', 1, 1, ?)`,
		attemptID, rolloutID, toolCallID, snapshotID, filepath.Join(t.TempDir(), attemptID), now); err != nil {
		t.Fatal(err)
	}
}

func insertTestSnapshot(t *testing.T, db *sql.DB, snapshotID, name, now string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO snapshots (id, name, kind, source, path, manifest_hash, file_count, bytes, status, created_at)
		VALUES (?, ?, 'ready', 'test', ?, 'hash', 1, 1, 'ready', ?)`, snapshotID, name, filepath.Join(t.TempDir(), snapshotID), now); err != nil {
		t.Fatal(err)
	}
}
