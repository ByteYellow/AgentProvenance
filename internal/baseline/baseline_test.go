package baseline

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestCheckPersistsBaselineDeviations(t *testing.T) {
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
	if _, err := db.Exec(`INSERT INTO baseline_profiles
		(id, template_name, exec_count, network_event_count, policy_block_count, active_cpu_seconds, status, created_at)
		VALUES ('base-test', 'coding-agent', 1, 0, 0, 1.0, 'ready', ?)`, now); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if _, err := db.Exec(`INSERT INTO events (id, run_id, source, event_type, payload, created_at)
			VALUES (?, 'run-anomalous', 'test', 'network_connect', '{"dst":"api.example.com"}', ?)`, fmt.Sprintf("evt-net-%c", 'a'+i), now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO policy_decisions
		(id, event_id, run_id, session_id, decision, reason, created_at)
		VALUES ('dec-test', 'evt-net-a', 'run-anomalous', '', 'deny', 'test deny', ?)`, now); err != nil {
		t.Fatal(err)
	}

	status, deviations, err := Check(db, "coding-agent", "run-anomalous")
	if err != nil {
		t.Fatal(err)
	}
	if status != "anomalous" || len(deviations) != 2 {
		t.Fatalf("status=%s deviations=%+v, want anomalous with two deviations", status, deviations)
	}
	records, err := ListDeviations(db, "run-anomalous")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("deviation records = %d, want 2: %+v", len(records), records)
	}
	seen := map[string]bool{}
	for _, record := range records {
		seen[record.DeviationType] = true
		if record.Status != "anomalous" || record.RecommendedAction != "audit" || record.ProfileID != "base-test" {
			t.Fatalf("unexpected deviation record: %+v", record)
		}
	}
	if !seen["network_event_count"] || !seen["policy_block_count"] {
		t.Fatalf("missing expected deviation types: %+v", records)
	}
}
