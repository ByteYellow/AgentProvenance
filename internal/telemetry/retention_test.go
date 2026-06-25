package telemetry

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestPruneRawEventsDeletesOnlyUnreferencedOldEvents(t *testing.T) {
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

	old := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano)
	recent := time.Now().UTC().Format(time.RFC3339Nano)
	insertEvent := func(id, createdAt string) {
		t.Helper()
		if _, err := db.Exec(`INSERT INTO events
			(id, run_id, source, event_type, payload, created_at)
			VALUES (?, 'run-retention', 'filtered_telemetry', 'execve', '{"argv":["true"]}', ?)`, id, createdAt); err != nil {
			t.Fatal(err)
		}
	}
	insertEvent("evt-old-free", old)
	insertEvent("evt-old-policy", old)
	insertEvent("evt-old-batch", old)
	insertEvent("evt-old-graph", old)
	insertEvent("evt-recent-free", recent)
	if _, err := db.Exec(`INSERT INTO policy_decisions
		(id, event_id, run_id, session_id, rule_id, decision, reason, created_at)
		VALUES ('pol-retention', 'evt-old-policy', 'run-retention', '', 'rule', 'audit', 'keep', ?)`, old); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO telemetry_batches
		(id, run_id, format, path, file_sha256, read_count, ingested_count, event_ids_json, event_ids_sha256, created_at)
		VALUES ('batch-retention', 'run-retention', 'falco', 'input.jsonl', 'sha256:input', 1, 1, '["evt-old-batch"]', 'sha256:events', ?)`, old); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO graph_edges
		(id, run_id, from_id, to_id, edge_type, source_event_id, created_at)
		VALUES ('edge-retention', 'run-retention', 'runtime_event/evt-old-graph', 'process-1', 'runtime_process_event', 'evt-old-graph', ?)`, old); err != nil {
		t.Fatal(err)
	}

	result, err := PruneRawEvents(db, RetentionOptions{RunID: "run-retention", OlderThan: time.Hour, MaxDelete: 10})
	if err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion != "agentprovenance.telemetry_retention/v1" || result.Deleted != 1 || result.Protected != 3 {
		t.Fatalf("unexpected retention result: %+v", result)
	}
	if len(result.DeletedIDs) != 1 || result.DeletedIDs[0] != "evt-old-free" {
		t.Fatalf("deleted ids = %+v, want evt-old-free", result.DeletedIDs)
	}
	for _, id := range []string{"evt-old-policy", "evt-old-batch", "evt-old-graph", "evt-recent-free"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE id = ?`, id).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("event %s count=%d, want protected", id, count)
		}
	}
}
