package rollout

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/state"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestStartWritesExplainableAttemptEvidence(t *testing.T) {
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
