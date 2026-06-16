package attempt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/state"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestBestOfSelectsPassingWinner(t *testing.T) {
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
	if err := os.WriteFile(taskPath, []byte("run_id: run-test\nimage: alpine:3.20\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stack, err := state.Service{DB: db, Paths: paths}.CreateStack(taskPath)
	if err != nil {
		t.Fatal(err)
	}

	results, winner, err := Service{DB: db, State: state.Service{DB: db, Paths: paths}}.BestOf(stack.ReadySnapshotID, []string{
		"bad::exit 7",
		"good::test -f task.yaml && echo ok",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2", len(results))
	}
	if winner.Strategy != "good" || !winner.IsWinner || winner.ExitCode != 0 {
		t.Fatalf("winner = %+v, want passing good strategy", winner)
	}

	var winnerCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM fork_attempts WHERE is_winner = 1`).Scan(&winnerCount); err != nil {
		t.Fatal(err)
	}
	if winnerCount != 1 {
		t.Fatalf("winner count = %d, want 1", winnerCount)
	}
}

func TestBestOfPenalizesBudgetExceededAttempts(t *testing.T) {
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
	if err := os.WriteFile(taskPath, []byte("run_id: run-test\nimage: alpine:3.20\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stack, err := state.Service{DB: db, Paths: paths}.CreateStack(taskPath)
	if err != nil {
		t.Fatal(err)
	}

	results, winner, err := Service{DB: db, State: state.Service{DB: db, Paths: paths}}.BestOf(stack.ReadySnapshotID, []string{
		"slow::sleep 2; echo slow::budget=1::score=contains:slow",
		"fast::echo fast::budget=1::score=contains:fast",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2", len(results))
	}
	if winner.Strategy != "fast" || winner.BudgetExceeded {
		t.Fatalf("winner = %+v, want fast within-budget attempt", winner)
	}
	var exceeded int
	if err := db.QueryRow(`SELECT COUNT(*) FROM fork_attempts WHERE budget_exceeded = 1`).Scan(&exceeded); err != nil {
		t.Fatal(err)
	}
	if exceeded != 1 {
		t.Fatalf("budget_exceeded count = %d, want 1", exceeded)
	}
}

func TestBestOfProbeTopKPrunesBeforeFullCommand(t *testing.T) {
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
	if err := os.WriteFile(taskPath, []byte("run_id: run-test\nimage: alpine:3.20\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stack, err := state.Service{DB: db, Paths: paths}.CreateStack(taskPath)
	if err != nil {
		t.Fatal(err)
	}

	results, winner, err := Service{DB: db, State: state.Service{DB: db, Paths: paths}}.BestOfWithOptions(stack.ReadySnapshotID, []string{
		"strong-probe::echo selected::probe=echo 10::score=number::artifact=selected.txt",
		"weak-probe::echo 9999::probe=echo 1::score=number::artifact=pruned.txt",
	}, Options{MaxFanout: 2, TopK: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2", len(results))
	}
	if winner.Strategy != "strong-probe" || !winner.IsWinner {
		t.Fatalf("winner = %+v, want strong-probe", winner)
	}
	var pruned Result
	for _, result := range results {
		if result.Strategy == "weak-probe" {
			pruned = result
		}
	}
	if pruned.Status != "pruned" || !strings.Contains(pruned.OutputSummary, "pruned_before_full_command") {
		t.Fatalf("weak strategy result = %+v, want pruned before full command", pruned)
	}
	var prunedCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM fork_attempts WHERE status = 'pruned'`).Scan(&prunedCount); err != nil {
		t.Fatal(err)
	}
	if prunedCount != 1 {
		t.Fatalf("pruned count = %d, want 1", prunedCount)
	}
}

func TestBestOfEarlyStopRunsFullCommandsByProbeRank(t *testing.T) {
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
	if err := os.WriteFile(taskPath, []byte("run_id: run-test\nimage: alpine:3.20\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stack, err := state.Service{DB: db, Paths: paths}.CreateStack(taskPath)
	if err != nil {
		t.Fatal(err)
	}

	results, winner, err := Service{DB: db, State: state.Service{DB: db, Paths: paths}}.BestOfWithOptions(stack.ReadySnapshotID, []string{
		"low-probe::echo SHOULD_NOT_RUN::probe=echo 1::score=number",
		"high-probe::echo winner::probe=echo 10::score=number",
	}, Options{MaxFanout: 2, TopK: 2, EarlyStop: true})
	if err != nil {
		t.Fatal(err)
	}
	if winner.Strategy != "high-probe" {
		t.Fatalf("winner = %+v, want high-probe", winner)
	}
	var low Result
	for _, result := range results {
		if result.Strategy == "low-probe" {
			low = result
		}
	}
	if low.Status != "pruned" || !strings.Contains(low.OutputSummary, "early_stop_after_winner") {
		t.Fatalf("low-probe result = %+v, want early-stop pruned", low)
	}
	if strings.Contains(low.OutputSummary, "SHOULD_NOT_RUN") {
		t.Fatalf("low-probe full command ran before high-probe winner: %+v", low)
	}
}

func TestBestOfCapturesDeclaredArtifact(t *testing.T) {
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
	if err := os.WriteFile(taskPath, []byte("run_id: run-test\nimage: alpine:3.20\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stack, err := state.Service{DB: db, Paths: paths}.CreateStack(taskPath)
	if err != nil {
		t.Fatal(err)
	}

	results, winner, err := Service{DB: db, State: state.Service{DB: db, Paths: paths}}.BestOfWithOptions(stack.ReadySnapshotID, []string{
		"artifact::printf artifact-body > result.txt; echo 7::score=number::artifact=result.txt",
	}, Options{MaxFanout: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("results=%d, want 1", len(results))
	}
	if winner.ArtifactResult == "" || !strings.Contains(winner.ArtifactResult, paths.Artifacts) {
		t.Fatalf("artifact result = %q, want artifact path under %s", winner.ArtifactResult, paths.Artifacts)
	}
	body, err := os.ReadFile(winner.ArtifactResult)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "artifact-body" {
		t.Fatalf("artifact body = %q, want artifact-body", string(body))
	}
	var stored string
	if err := db.QueryRow(`SELECT artifact_result FROM fork_attempts WHERE id = ?`, winner.AttemptID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != winner.ArtifactResult {
		t.Fatalf("stored artifact = %q, want %q", stored, winner.ArtifactResult)
	}
}
