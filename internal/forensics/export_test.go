package forensics

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/correlation"
	securitymodel "github.com/byteyellow/agentprovenance/internal/security"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestExportBundleIncludesRiskResponseEvidence(t *testing.T) {
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
	if _, err := correlation.RecordBinding(db, correlation.Binding{
		RunID:         "run-forensics-test",
		SessionID:     "session-forensics-test",
		AttemptID:     "attempt-forensics-test",
		ToolCallID:    "tool-forensics-test",
		ProcessID:     "process-forensics-test",
		ContainerID:   "container-forensics-test",
		PID:           4242,
		RootPID:       4242,
		StartedAt:     now,
		BindingSource: "external_telemetry",
		Confidence:    0.95,
	}); err != nil {
		t.Fatal(err)
	}
	eventID, err := telemetry.IngestFiltered(db, telemetry.IngestEvent{
		RawEventID:  "raw-forensics-risk",
		ContainerID: "container-forensics-test",
		PID:         4242,
		TGID:        4242,
		PPID:        4000,
		Timestamp:   now,
		Source:      "falco_jsonl",
		EventType:   "metadata_ip",
		Payload:     `{"dst":"169.254.169.254"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, persisted, err := securitymodel.EvaluateRuntimeEvent(db, eventID); err != nil {
		t.Fatal(err)
	} else if !persisted {
		t.Fatal("expected risk policy decision to persist")
	}

	info, err := (Service{DB: db, Paths: paths}).ExportBundle("run-forensics-test")
	if err != nil {
		t.Fatal(err)
	}
	if info.SchemaVersion != "agentprovenance.forensics_export/v1" || info.ID == "" || info.Path == "" || info.SHA256 == "" || info.SizeBytes == 0 {
		t.Fatalf("unexpected bundle info: %+v", info)
	}
	raw, err := os.ReadFile(info.Path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != info.SHA256 {
		t.Fatalf("bundle hash mismatch")
	}
	var bundle struct {
		SchemaVersion    string           `json:"schema_version"`
		RunID            string           `json:"run_id"`
		Events           []map[string]any `json:"events"`
		PolicyDecisions  []map[string]any `json:"policy_decisions"`
		RiskSignals      []map[string]any `json:"risk_signals"`
		ResponseActions  []map[string]any `json:"response_actions"`
		GraphEdges       []map[string]any `json:"graph_edges"`
		EvidenceManifest struct {
			SchemaVersion string `json:"schema_version"`
			Security      struct {
				RiskCount     int `json:"risk_count"`
				ResponseCount int `json:"response_count"`
			} `json:"security"`
		} `json:"evidence_manifest"`
	}
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.SchemaVersion != "agentprovenance.forensics_bundle/v1" || bundle.RunID != "run-forensics-test" {
		t.Fatalf("unexpected bundle header: %+v", bundle)
	}
	if len(bundle.Events) != 1 || len(bundle.PolicyDecisions) != 1 || len(bundle.RiskSignals) != 1 || len(bundle.ResponseActions) != 1 || len(bundle.GraphEdges) == 0 {
		t.Fatalf("bundle missing risk evidence: %+v", bundle)
	}
	if bundle.EvidenceManifest.SchemaVersion != "agentprovenance.evidence_manifest/v1" ||
		bundle.EvidenceManifest.Security.RiskCount != 1 ||
		bundle.EvidenceManifest.Security.ResponseCount != 1 {
		t.Fatalf("bundle missing evidence manifest security summary: %+v", bundle.EvidenceManifest)
	}
}

func TestImportBundleRejectsUnknownColumns(t *testing.T) {
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

	bundlePath := filepath.Join(root, "bundle.json")
	raw := []byte(`{
	  "schema_version":"agentprovenance.forensics_bundle/v1",
	  "run_id":"run-bad-import",
	  "leases":[{"id":"lease-bad","run_id":"run-bad-import","task_path":"task.yaml","task_yaml":"{}","status":"allocated","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","id) VALUES ('x'); DROP TABLE leases; --":"boom"}]
	}`)
	if err := os.WriteFile(bundlePath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = (Service{DB: db, Paths: paths}).ImportBundle(bundlePath)
	if err == nil {
		t.Fatal("expected malicious/unknown import column to be rejected")
	}
	var count int
	if qerr := db.QueryRow(`SELECT COUNT(*) FROM leases`).Scan(&count); qerr != nil {
		t.Fatalf("leases table should still exist: %v", qerr)
	}
}
