package security

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestEvaluateMetadataIPQuarantines(t *testing.T) {
	decision := DefaultEngine().Evaluate(Event{
		EventType: "network_connect",
		DstIP:     "169.254.169.254",
	})
	if decision.Decision != "quarantine" {
		t.Fatalf("decision = %s, want quarantine", decision.Decision)
	}
}

func TestEvaluatePrivateCIDRDenies(t *testing.T) {
	decision := DefaultEngine().Evaluate(Event{
		EventType: "network_connect",
		DstIP:     "10.0.0.5",
	})
	if decision.Decision != "deny" {
		t.Fatalf("decision = %s, want deny", decision.Decision)
	}
}

func TestEvaluateSecretPathKills(t *testing.T) {
	decision := DefaultEngine().Evaluate(Event{
		EventType: "file_open",
		Path:      "/workspace/.env",
	})
	if decision.Decision != "kill" {
		t.Fatalf("decision = %s, want kill", decision.Decision)
	}
}

func TestEvaluateJSONLWithStatePersistsAndQuarantines(t *testing.T) {
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
	insertPolicySession(t, db)

	eventsPath := filepath.Join(root, "events.jsonl")
	if err := os.WriteFile(eventsPath, []byte(`{"source":"egress_proxy","event_type":"network_connect","run_id":"run-test","session_id":"sbx-test","dst_ip":"169.254.169.254"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := EvaluateJSONLWithState(db, eventsPath, os.Stdout); err != nil {
		t.Fatal(err)
	}

	var sessionStatus string
	if err := db.QueryRow(`SELECT status FROM sessions WHERE id = 'sbx-test'`).Scan(&sessionStatus); err != nil {
		t.Fatal(err)
	}
	if sessionStatus != "quarantined" {
		t.Fatalf("session status = %s, want quarantined", sessionStatus)
	}
	var decisionCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM policy_decisions WHERE run_id = 'run-test' AND decision = 'quarantine'`).Scan(&decisionCount); err != nil {
		t.Fatal(err)
	}
	if decisionCount != 1 {
		t.Fatalf("decision count = %d, want 1", decisionCount)
	}
	var eventID, decisionID string
	if err := db.QueryRow(`SELECT id, event_id FROM policy_decisions WHERE run_id = 'run-test' AND decision = 'quarantine'`).Scan(&decisionID, &eventID); err != nil {
		t.Fatal(err)
	}
	var policyEdgeCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM graph_edges
		WHERE run_id = 'run-test'
		  AND from_id = ?
		  AND to_id = ?
		  AND edge_type = 'runtime_event_policy_decision'`, "runtime_event/"+eventID, "policy_decision/"+decisionID).Scan(&policyEdgeCount); err != nil {
		t.Fatal(err)
	}
	if policyEdgeCount != 1 {
		t.Fatalf("policy edge count = %d, want 1", policyEdgeCount)
	}
	var sessionEdgeCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM graph_edges
		WHERE run_id = 'run-test'
		  AND from_id = ?
		  AND to_id = 'sbx-test'
		  AND edge_type = 'policy_decision_session'`, "policy_decision/"+decisionID).Scan(&sessionEdgeCount); err != nil {
		t.Fatal(err)
	}
	if sessionEdgeCount != 1 {
		t.Fatalf("policy session edge count = %d, want 1", sessionEdgeCount)
	}
	var quarantineCount int
	if err := db.QueryRow(`SELECT COALESCE(SUM(quarantine_count), 0) FROM cost_samples WHERE run_id = 'run-test'`).Scan(&quarantineCount); err != nil {
		t.Fatal(err)
	}
	if quarantineCount != 1 {
		t.Fatalf("quarantine count = %d, want 1", quarantineCount)
	}
	risks, err := ListRiskSignals(db, "run-test")
	if err != nil {
		t.Fatal(err)
	}
	if len(risks) != 1 {
		t.Fatalf("risk signals = %d, want 1", len(risks))
	}
	if risks[0].PolicyDecisionID != decisionID || risks[0].SignalType != "policy_violation" || risks[0].Severity != "high" || risks[0].RecommendedAction != "quarantine" {
		t.Fatalf("unexpected risk signal: %+v", risks[0])
	}
	responses, err := ListResponseActions(db, "run-test")
	if err != nil {
		t.Fatal(err)
	}
	if len(responses) != 1 {
		t.Fatalf("response actions = %d, want 1", len(responses))
	}
	if responses[0].RiskSignalID != risks[0].ID || responses[0].PolicyDecisionID != decisionID || responses[0].ActionType != "quarantine" || responses[0].TargetType != "session" || responses[0].TargetID != "sbx-test" {
		t.Fatalf("unexpected response action: %+v", responses[0])
	}
}

func insertPolicySession(t *testing.T, db *sql.DB) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := db.Exec(`INSERT INTO leases (id, run_id, task_path, task_yaml, status, created_at, updated_at)
		VALUES ('lease-test', 'run-test', 'task.yaml', '{}', 'allocated', ?, ?)`, now, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO sessions (id, lease_id, run_id, container_id, workspace_host_path, status, created_at, updated_at)
		VALUES ('sbx-test', 'lease-test', 'run-test', 'container-test', '/tmp/workspace', 'running', ?, ?)`, now, now)
	if err != nil {
		t.Fatal(err)
	}
}
