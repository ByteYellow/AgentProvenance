package attempt

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/substrate/state"
)

func TestBestOfSelectsPassingWinner(t *testing.T) {
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

func TestBestOfLocalAttemptRecordsProcessTrace(t *testing.T) {
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
	if err := os.WriteFile(taskPath, []byte("run_id: run-local-process\nimage: alpine:3.20\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stack, err := state.Service{DB: db, Paths: paths}.CreateStack(taskPath)
	if err != nil {
		t.Fatal(err)
	}

	results, winner, err := Service{DB: db, State: state.Service{DB: db, Paths: paths}}.BestOfWithOptions(stack.ReadySnapshotID, []string{
		"artifact::printf trace-body > result.txt; echo 17::score=number::artifact=result.txt",
	}, Options{MaxFanout: 1, RunID: "run-local-process", Runtime: "local", TaskPath: taskPath, BaseSnapshotID: stack.ReadySnapshotID, Paths: paths})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("results=%d, want 1", len(results))
	}
	if winner.ProcessID == "" || winner.SessionID == "" || winner.ToolCallID == "" {
		t.Fatalf("winner missing execution ids: %+v", winner)
	}

	var processToolCallID, processSessionID, processStatus string
	if err := db.QueryRow(`SELECT tool_call_id, session_id, status FROM processes WHERE id = ?`, winner.ProcessID).Scan(&processToolCallID, &processSessionID, &processStatus); err != nil {
		t.Fatal(err)
	}
	if processToolCallID != winner.ToolCallID || processSessionID != winner.SessionID || processStatus != "exited" {
		t.Fatalf("process row = tool:%s session:%s status:%s, want tool:%s session:%s exited", processToolCallID, processSessionID, processStatus, winner.ToolCallID, winner.SessionID)
	}

	var eventCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE process_id = ? AND tool_call_id = ? AND event_type IN ('exec_start', 'exec_end', 'burst_reserve', 'burst_release')`, winner.ProcessID, winner.ToolCallID).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if eventCount < 4 {
		t.Fatalf("event count = %d, want at least 4 process-linked rollout events", eventCount)
	}
	var runningLocalSessions int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE runtime = 'local' AND status = 'running'`).Scan(&runningLocalSessions); err != nil {
		t.Fatal(err)
	}
	if runningLocalSessions != 0 {
		t.Fatalf("running local sessions = %d, want 0 after rollout attempt completion", runningLocalSessions)
	}

	var out bytes.Buffer
	if err := provenance.TraceProcess(db, winner.ProcessID, &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{
		"process=" + winner.ProcessID,
		"session=" + winner.SessionID,
		"tool_call=" + winner.ToolCallID,
		"attempt=" + winner.AttemptID,
		"artifact=" + winner.ArtifactResult,
		"exec_start",
		"exec_end",
		"winner=true",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("process trace missing %q:\n%s", want, got)
		}
	}
}
