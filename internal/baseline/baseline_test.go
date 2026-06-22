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
	if status != "anomalous" || len(deviations) != 3 {
		t.Fatalf("status=%s deviations=%+v, want anomalous with three deviations", status, deviations)
	}
	records, err := ListDeviations(db, "run-anomalous")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("deviation records = %d, want 3: %+v", len(records), records)
	}
	seen := map[string]bool{}
	for _, record := range records {
		seen[record.DeviationType] = true
		if record.Status != "anomalous" || record.ProfileID != "base-test" {
			t.Fatalf("unexpected deviation record: %+v", record)
		}
		highRiskDeviation := record.DeviationType == "suspicious_runtime_count" || record.DeviationType == "policy_block_count"
		if highRiskDeviation && record.RecommendedAction != "review" {
			t.Fatalf("%s action = %s, want review", record.DeviationType, record.RecommendedAction)
		}
		if !highRiskDeviation && record.RecommendedAction != "audit" {
			t.Fatalf("%s action = %s, want audit", record.DeviationType, record.RecommendedAction)
		}
	}
	if !seen["network_event_count"] || !seen["policy_block_count"] || !seen["suspicious_runtime_count"] {
		t.Fatalf("missing expected deviation types: %+v", records)
	}
	var riskCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM risk_signals WHERE run_id = 'run-anomalous' AND signal_type = 'baseline_deviation'`).Scan(&riskCount); err != nil {
		t.Fatal(err)
	}
	if riskCount != 3 {
		t.Fatalf("baseline risk signals = %d, want 3", riskCount)
	}
}

func TestLearnStoresRuntimeFeatureVector(t *testing.T) {
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
	for _, eventType := range []string{"execve", "metadata_ip", "private_cidr", "secret_path", "file_write"} {
		if _, err := db.Exec(`INSERT INTO events (id, run_id, source, event_type, payload, created_at)
			VALUES (?, 'run-learn', 'test', ?, '{}', ?)`, "evt-"+eventType, eventType, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO events (id, run_id, source, event_type, payload, created_at)
		VALUES ('evt-observed', 'run-learn', 'record_process_sample', 'process_observed', '{"outlived_root":true}', ?)`, now); err != nil {
		t.Fatal(err)
	}
	profile, err := Learn(db, "coding-agent", "run-learn")
	if err != nil {
		t.Fatal(err)
	}
	if profile.Features.ExecCount != 1 ||
		profile.Features.MetadataIPCount != 1 ||
		profile.Features.PrivateCIDRCount != 1 ||
		profile.Features.SecretPathCount != 1 ||
		profile.Features.FileWriteCount != 1 ||
		profile.Features.OutlivedRootCount != 1 ||
		profile.Payload == "" || profile.Payload == "{}" {
		t.Fatalf("unexpected learned feature vector: %+v payload=%s", profile.Features, profile.Payload)
	}
}
