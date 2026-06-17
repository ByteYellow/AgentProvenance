package evidence

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestProcessEvidenceCreatesArtifactGraphEdges(t *testing.T) {
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
	artifactRef := filepath.Join(paths.Artifacts, "attempt-1-result.txt")
	_, err = db.Exec(`INSERT INTO evidence_events
		(id, run_id, rollout_id, attempt_id, tool_call_id, snapshot_id, event_type, priority, payload, status, created_at)
		VALUES ('evidence-1', 'run-1', 'rollout-1', 'attempt-1', 'tool-1', 'snap-1', 'attempt_finished', 'normal', ?, 'queued', ?)`,
		`{"artifact_result":"`+artifactRef+`","status":"passed"}`, now)
	if err != nil {
		t.Fatal(err)
	}

	result, err := Service{DB: db, Paths: paths}.ProcessEvidence(10)
	if err != nil {
		t.Fatal(err)
	}
	if result.Processed != 1 {
		t.Fatalf("processed=%d, want 1", result.Processed)
	}
	for _, edgeType := range []string{"attempt_artifact", "tool_call_artifact"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE edge_type = ? AND to_id = ?`, edgeType, artifactRef).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("edge %s count=%d, want 1", edgeType, count)
		}
	}
}
