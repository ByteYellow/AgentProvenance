package provenance

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestDiffAndBlameFileAcrossAttempts(t *testing.T) {
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
	base := filepath.Join(root, "base")
	attempt1 := filepath.Join(root, "attempt-1")
	attempt2 := filepath.Join(root, "attempt-2")
	for _, dir := range []string{base, attempt1, attempt2} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(base, "calculator.py"), []byte("def add(a, b):\n    return a - b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "old.txt"), []byte("remove me\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(attempt1, "calculator.py"), []byte("def add(a, b):\n    return a - b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(attempt1, "old.txt"), []byte("remove me\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(attempt2, "calculator.py"), []byte("def add(a, b):\n    return a + b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(attempt2, "new.txt"), []byte("created\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	insertDiffSnapshot(t, db, "snap-1", base, now)
	_, err = db.Exec(`INSERT INTO rollouts (id, run_id, base_snapshot_id, status, fanout, winner_attempt_id, created_at, updated_at)
		VALUES ('rollout-1', 'run-1', 'snap-1', 'completed', 2, 'attempt-2', ?, ?)`, now, now)
	if err != nil {
		t.Fatal(err)
	}
	insertDiffAttempt(t, db, "attempt-1", "tool-1", attempt1, "noop", "cat calculator.py", 0, now)
	insertDiffAttempt(t, db, "attempt-2", "tool-2", attempt2, "correct-add", "sed fix", 1, now)

	var diffOut bytes.Buffer
	if err := DiffFile(db, "run-1", "calculator.py", &diffOut); err != nil {
		t.Fatal(err)
	}
	diff := diffOut.String()
	for _, want := range []string{
		"attempt=attempt-1",
		"changed=false",
		"attempt=attempt-2",
		"winner=true",
		"changed=true",
		"-    return a - b",
		"+    return a + b",
	} {
		if !strings.Contains(diff, want) {
			t.Fatalf("diff missing %q:\n%s", want, diff)
		}
	}

	var blameOut bytes.Buffer
	if err := BlameFile(db, "run-1", "calculator.py", &blameOut); err != nil {
		t.Fatal(err)
	}
	blame := blameOut.String()
	for _, want := range []string{
		"reason=unchanged_from_base",
		"reason=modified_by_attempt",
		"tool_call=tool-2",
		"strategy=correct-add",
		"command=\"sed fix\"",
	} {
		if !strings.Contains(blame, want) {
			t.Fatalf("blame missing %q:\n%s", want, blame)
		}
	}
}

func TestDiffAndBlameJSON(t *testing.T) {
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
	base := filepath.Join(root, "base")
	attempt1 := filepath.Join(root, "attempt-1")
	attempt2 := filepath.Join(root, "attempt-2")
	for _, dir := range []string{base, attempt1, attempt2} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(base, "calculator.py"), []byte("def add(a, b):\n    return a - b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "old.txt"), []byte("remove me\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(attempt1, "calculator.py"), []byte("def add(a, b):\n    return a - b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(attempt1, "old.txt"), []byte("remove me\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(attempt2, "calculator.py"), []byte("def add(a, b):\n    return a + b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(attempt2, "new.txt"), []byte("created\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	insertDiffSnapshot(t, db, "snap-1", base, now)
	if _, err := db.Exec(`INSERT INTO rollouts (id, run_id, base_snapshot_id, status, fanout, winner_attempt_id, created_at, updated_at)
		VALUES ('rollout-1', 'run-1', 'snap-1', 'completed', 2, 'attempt-2', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	insertDiffAttempt(t, db, "attempt-1", "tool-1", attempt1, "noop", "cat calculator.py", 0, now)
	insertDiffAttempt(t, db, "attempt-2", "tool-2", attempt2, "correct-add", "sed fix", 1, now)

	var diffOut bytes.Buffer
	if err := DiffFileJSON(db, "run-1", "calculator.py", &diffOut); err != nil {
		t.Fatal(err)
	}
	var diffManifest FileDiffManifest
	if err := json.Unmarshal(diffOut.Bytes(), &diffManifest); err != nil {
		t.Fatalf("invalid diff json: %v\n%s", err, diffOut.String())
	}
	if diffManifest.SchemaVersion != "agentprovenance.diff/v1" || len(diffManifest.Attempts) != 2 {
		t.Fatalf("unexpected diff manifest: %+v", diffManifest)
	}
	if diffManifest.Attempts[0].Changed || !diffManifest.Attempts[1].Changed || !diffManifest.Attempts[1].IsWinner {
		t.Fatalf("unexpected diff attempts: %+v", diffManifest.Attempts)
	}
	if len(diffManifest.Attempts[1].UnifiedDiff) == 0 {
		t.Fatalf("expected unified diff lines: %+v", diffManifest.Attempts[1])
	}

	var blameOut bytes.Buffer
	if err := BlameFileJSON(db, "run-1", "calculator.py", &blameOut); err != nil {
		t.Fatal(err)
	}
	var blameManifest FileBlameManifest
	if err := json.Unmarshal(blameOut.Bytes(), &blameManifest); err != nil {
		t.Fatalf("invalid blame json: %v\n%s", err, blameOut.String())
	}
	if blameManifest.SchemaVersion != "agentprovenance.blame/v1" || len(blameManifest.Entries) != 2 {
		t.Fatalf("unexpected blame manifest: %+v", blameManifest)
	}
	if blameManifest.Entries[1].Reason != "modified_by_attempt" || blameManifest.Entries[1].ToolCallID != "tool-2" {
		t.Fatalf("unexpected blame entry: %+v", blameManifest.Entries[1])
	}

	var createdOut bytes.Buffer
	if err := BlameFileJSON(db, "run-1", "new.txt", &createdOut); err != nil {
		t.Fatal(err)
	}
	var createdManifest FileBlameManifest
	if err := json.Unmarshal(createdOut.Bytes(), &createdManifest); err != nil {
		t.Fatalf("invalid created blame json: %v\n%s", err, createdOut.String())
	}
	if createdManifest.Entries[0].Changed || createdManifest.Entries[0].Reason != "unchanged_from_base" {
		t.Fatalf("missing file in base and attempt should be unchanged: %+v", createdManifest.Entries[0])
	}
	if !createdManifest.Entries[1].Changed || createdManifest.Entries[1].Reason != "created_by_attempt" {
		t.Fatalf("expected created_by_attempt: %+v", createdManifest.Entries[1])
	}

	var createdDiffOut bytes.Buffer
	if err := DiffFileJSON(db, "run-1", "new.txt", &createdDiffOut); err != nil {
		t.Fatal(err)
	}
	var createdDiff FileDiffManifest
	if err := json.Unmarshal(createdDiffOut.Bytes(), &createdDiff); err != nil {
		t.Fatalf("invalid created diff json: %v\n%s", err, createdDiffOut.String())
	}
	if createdDiff.Attempts[0].Changed || !createdDiff.Attempts[1].Changed {
		t.Fatalf("unexpected created diff attempts: %+v", createdDiff.Attempts)
	}

	var deletedOut bytes.Buffer
	if err := BlameFileJSON(db, "run-1", "old.txt", &deletedOut); err != nil {
		t.Fatal(err)
	}
	var deletedManifest FileBlameManifest
	if err := json.Unmarshal(deletedOut.Bytes(), &deletedManifest); err != nil {
		t.Fatalf("invalid deleted blame json: %v\n%s", err, deletedOut.String())
	}
	if deletedManifest.Entries[1].Reason != "deleted_by_attempt" || !deletedManifest.Entries[1].Changed {
		t.Fatalf("expected deleted_by_attempt: %+v", deletedManifest.Entries[1])
	}
}

func insertDiffSnapshot(t *testing.T, db *sql.DB, id, path, createdAt string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO snapshots (id, name, kind, source, path, manifest_hash, file_count, bytes, status, created_at)
		VALUES (?, 'ready', 'ready', 'test', ?, 'hash', 1, 1, 'ready', ?)`, id, path, createdAt)
	if err != nil {
		t.Fatal(err)
	}
}

func insertDiffAttempt(t *testing.T, db *sql.DB, id, toolCallID, workspace, strategy, command string, winner int, createdAt string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO fork_attempts
		(id, rollout_id, tool_call_id, snapshot_id, workspace_path, fork_ms, strategy, command, status, is_winner, created_at)
		VALUES (?, 'rollout-1', ?, 'snap-1', ?, 1, ?, ?, 'passed', ?, ?)`,
		id, toolCallID, workspace, strategy, command, winner, createdAt)
	if err != nil {
		t.Fatal(err)
	}
}
