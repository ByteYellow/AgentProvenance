package evidence

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestBuildManifestAggregatesRunEvidence(t *testing.T) {
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

	workdir := filepath.Join(root, "workspace")
	if err := os.MkdirAll(workdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workdir, "app.py"), []byte("print('old')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := (record.Service{DB: db, Paths: paths}).Run(record.Request{
		RunID:   "run-evidence-manifest",
		Name:    "evidence-manifest",
		Workdir: workdir,
		Command: []string{"sh", "-c", "printf \"print('new')\\n\" > app.py"},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	eventID := ""
	if err := db.QueryRow(`SELECT id FROM events WHERE run_id = ? AND event_type = 'file_write' LIMIT 1`, result.RunID).Scan(&eventID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO policy_decisions
		(id, event_id, run_id, session_id, rule_id, decision, reason, created_at)
		VALUES ('policy-evidence-manifest', ?, ?, ?, 'test-rule', 'audit', 'test decision', ?)`,
		eventID, result.RunID, result.SessionID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO risk_signals
		(id, run_id, session_id, tool_call_id, process_id, snapshot_id, event_id, policy_decision_id, signal_type, severity, reason, recommended_action, payload, created_at)
		VALUES ('risk-evidence-manifest', ?, ?, ?, ?, ?, ?, 'policy-evidence-manifest', 'runtime_policy', 'medium', 'test risk', 'audit', '{}', ?)`,
		result.RunID, result.SessionID, result.ToolCallID, result.ProcessID, result.BaseSnapshotID, eventID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO response_actions
		(id, run_id, session_id, process_id, snapshot_id, risk_signal_id, policy_decision_id, action_type, target_type, target_id, status, created_at)
		VALUES ('action-evidence-manifest', ?, ?, ?, ?, 'risk-evidence-manifest', 'policy-evidence-manifest', 'audit', 'event', ?, 'recorded', ?)`,
		result.RunID, result.SessionID, result.ProcessID, result.BaseSnapshotID, eventID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := (provenance.ObjectStore{DB: db, Paths: paths}).MaterializeRun(result.RunID); err != nil {
		t.Fatal(err)
	}

	manifest, err := BuildManifest(db, ManifestOptions{RunID: result.RunID, ObjectLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != ManifestSchemaVersion || manifest.RunID != result.RunID {
		t.Fatalf("unexpected manifest header: %+v", manifest)
	}
	if manifest.ResultSetID == "" || manifest.PageHash == "" {
		t.Fatalf("missing manifest integrity hashes: result_set_id=%q page_hash=%q", manifest.ResultSetID, manifest.PageHash)
	}
	if manifest.Summary.EventCount == 0 || manifest.Timeline.EventCount == 0 {
		t.Fatalf("manifest missing timeline/summary counts: %+v", manifest)
	}
	if manifest.Security.RiskCount != 1 || manifest.Security.ResponseCount != 1 {
		t.Fatalf("unexpected security counts: %+v", manifest.Security)
	}
	if manifest.Objects.ObjectCount == 0 || manifest.Objects.ResultSetID == "" || manifest.Objects.PageHash == "" {
		t.Fatalf("missing object summary: %+v", manifest.Objects)
	}
	if manifest.Objects.ByType["record_manifest"] == 0 {
		t.Fatalf("manifest missing record object type: %+v", manifest.Objects.ByType)
	}
	if !hasView(manifest.RecommendedViews, "graph verify --run "+result.RunID+" --json") {
		t.Fatalf("manifest missing verification view: %+v", manifest.RecommendedViews)
	}
}

func hasView(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
