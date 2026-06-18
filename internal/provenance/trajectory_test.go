package provenance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/effects"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestTrajectoriesRunJSONEmitsPerAttemptEvidence(t *testing.T) {
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

	base := filepath.Join(root, "base")
	workspace := filepath.Join(root, "attempt-1")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "calculator.py"), []byte("def add(a, b):\n    return a - b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "old.txt"), []byte("remove me\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "calculator.py"), []byte("def add(a, b):\n    return a + b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "new.txt"), []byte("created\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(paths.Artifacts, "fix.patch")
	if err := os.MkdirAll(filepath.Dir(artifact), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifact, []byte("patch"), 0o644); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(`INSERT INTO snapshots (id, name, kind, source, path, manifest_hash, file_count, bytes, status, created_at)
		VALUES ('snap-1', 'ready', 'ready', 'test', ?, 'hash', 2, 64, 'ready', ?)`, base, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO rollouts
		(id, run_id, base_snapshot_id, status, fanout, winner_attempt_id, promotion_id, risk_status, created_at, updated_at)
		VALUES ('rollout-1', 'run-1', 'snap-1', 'completed', 1, 'attempt-1', 'promo-1', 'clean', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO fork_attempts
		(id, rollout_id, tool_call_id, snapshot_id, workspace_path, fork_ms, strategy, command, status, risk_status, is_winner, artifact_result, score, cost_estimate, created_at)
		VALUES ('attempt-1', 'rollout-1', 'tool-1', 'snap-1', ?, 1, 'fix', 'pytest -q', 'passed', 'clean', 1, ?, 7, 0.001, ?)`, workspace, artifact, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO leases
		(id, run_id, task_path, task_yaml, status, created_at, updated_at)
		VALUES ('lease-1', 'run-1', 'task.yaml', '{}', 'allocated', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO sessions
		(id, lease_id, run_id, workspace_host_path, status, created_at, updated_at)
		VALUES ('session-1', 'lease-1', 'run-1', ?, 'stopped', ?, ?)`, workspace, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tool_calls
		(id, run_id, rollout_id, attempt_id, session_id, command, status, exit_code, result_ref, created_at, started_at, ended_at)
		VALUES ('tool-1', 'run-1', 'rollout-1', 'attempt-1', 'session-1', 'pytest -q', 'passed', 0, ?, ?, ?, ?)`, artifact, now, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO processes
		(id, session_id, tool_call_id, command, status, exit_code, started_at, ended_at)
		VALUES ('process-1', 'session-1', 'tool-1', 'pytest -q', 'exited', 0, ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO events
		(id, run_id, session_id, tool_call_id, process_id, source, event_type, payload, created_at, correlation_method, correlation_confidence)
		VALUES ('evt-1', 'run-1', 'session-1', 'tool-1', 'process-1', 'tetragon_jsonl', 'execve', '{"attempt_id":"attempt-1"}', ?, 'cgroup_time_window:cgroup_id+time', 0.98)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := effects.RecordEffect(db, effects.CreateInput{
		RunID:      "run-1",
		AttemptID:  "attempt-1",
		SessionID:  "session-1",
		ToolCallID: "tool-1",
		ProcessID:  "process-1",
		EffectType: "api_call",
		Target:     "api.example.com",
		Mode:       "dry-run",
		Decision:   "audit",
	}); err != nil {
		t.Fatal(err)
	}

	manifest, err := BuildTrajectoriesRun(db, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var decoded TrajectoryManifest
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SchemaVersion != "agentprovenance.trajectories/v1" || decoded.DecisionOwner != "external_evaluator" {
		t.Fatalf("unexpected manifest header: %+v", decoded)
	}
	if len(decoded.Trajectories) != 1 {
		t.Fatalf("trajectories = %d, want 1", len(decoded.Trajectories))
	}
	trajectory := decoded.Trajectories[0]
	if !trajectory.LocalCandidateEligible || trajectory.ToolCall == nil || len(trajectory.Processes) != 1 || len(trajectory.RuntimeEvents) != 1 || len(trajectory.ExternalEffects) != 1 {
		t.Fatalf("missing trajectory evidence: %+v", trajectory)
	}
	changes := map[string]string{}
	for _, change := range trajectory.FileChanges {
		changes[change.Path] = change.ChangeType
	}
	if changes["calculator.py"] != "modified" || changes["new.txt"] != "created" || changes["old.txt"] != "deleted" {
		t.Fatalf("unexpected file changes: %+v", changes)
	}
}
