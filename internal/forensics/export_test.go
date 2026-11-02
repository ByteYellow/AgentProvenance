package forensics

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/evidence"
	observability "github.com/byteyellow/agentprovenance/internal/observability"
	securitymodel "github.com/byteyellow/agentprovenance/internal/security"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestRequiredObjectOverLimitFailsExport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large-object.json")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxInlineObjectBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	blobs, omitted, err := embedObjectBlobs([]map[string]any{{"hash": "sha256:large", "path": path}})
	if err == nil || !strings.Contains(err.Error(), "required object sha256:large exceeds") {
		t.Fatalf("expected explicit size failure, got %v", err)
	}
	if len(blobs) != 0 || len(omitted) != 0 {
		t.Fatal("required object must not become an optional omission")
	}
}

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

// TestRedactBundleTextsMasksFreeTextColumns 断言导出 backstop 覆盖事件 payload、
// 录制的 command 列（tool_calls/processes/fork_attempts）、lease task_yaml 与
// evidence manifest 摘要——这些列都引用捕获原文，等价于 H4 的 bundle 泄漏向量；
// provenance_objects 保持原样（内容寻址，materialize 时已掩码，此处重掩码会破坏哈希）。
func TestRedactBundleTextsMasksFreeTextColumns(t *testing.T) {
	truncatedPEM := "-----BEGIN OPENSSH PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7X9qFAKE"
	bundle := map[string]any{
		"tool_calls":         []map[string]any{{"id": "tc1", "command": `["echo","github_pat_11ABcdEF0aBcDeFgHiJkLmNoPqRsTuVwxYz"]`}},
		"processes":          []map[string]any{{"id": "p1", "command": `["id"]`}},
		"fork_attempts":      []map[string]any{{"id": "f1", "command": truncatedPEM}},
		"leases":             []map[string]any{{"id": "l1", "task_yaml": "token: super-secret-token-42"}},
		"events":             []map[string]any{{"id": "e1", "payload": `{"argv":["echo","https://admin:SuperSecret9@github.com/acme/x.git"]}`}},
		"sessions":           []map[string]any{{"id": "s1", "container_id": "c1"}},
		"provenance_objects": []map[string]any{{"hash": "sha256:abc", "payload": "token: super-secret-token-42"}},
	}
	manifest := evidence.Manifest{Summary: observability.Summary{
		TopEvidenceRefs: []observability.EvidenceSummary{{Ref: "ref1", Type: "exec", Summary: "ran echo sk-abcdefghijklmnop123456"}},
	}}
	redactBundleTexts(bundle, &manifest)

	assertMasked := func(name string, got any, secret string) {
		s, _ := got.(string)
		if strings.Contains(s, secret) {
			t.Fatalf("%s: secret %q leaked: %q", name, secret, s)
		}
		if !strings.Contains(s, "***REDACTED***") {
			t.Fatalf("%s: expected mask, got %q", name, s)
		}
	}
	tc := bundle["tool_calls"].([]map[string]any)[0]
	assertMasked("tool_calls.command", tc["command"], "github_pat_11ABcdEF0aBcDeFgHiJkLmNoPqRsTuVwxYz")
	fa := bundle["fork_attempts"].([]map[string]any)[0]
	assertMasked("fork_attempts.command", fa["command"], "MIIEpAIBAAKCAQEA7X9qFAKE")
	le := bundle["leases"].([]map[string]any)[0]
	assertMasked("leases.task_yaml", le["task_yaml"], "super-secret-token-42")
	ev := bundle["events"].([]map[string]any)[0]
	assertMasked("events.payload", ev["payload"], "SuperSecret9")
	// 无机密内容保持原样（掩码按内容触发，不碰路径/ID/普通值）。
	p := bundle["processes"].([]map[string]any)[0]
	if p["command"] != `["id"]` {
		t.Fatalf("clean command must stay verbatim, got %q", p["command"])
	}
	if s := bundle["sessions"].([]map[string]any)[0]["container_id"]; s != "c1" {
		t.Fatalf("unrelated columns must stay verbatim, got %v", s)
	}
	// provenance_objects 不动（materialize 时已掩码，此处重掩码会破坏内容寻址哈希）。
	po := bundle["provenance_objects"].([]map[string]any)[0]
	if po["payload"] != "token: super-secret-token-42" {
		t.Fatalf("provenance_objects must be left untouched, got %v", po["payload"])
	}
	assertMasked("evidence_manifest.summary", manifest.Summary.TopEvidenceRefs[0].Summary, "sk-abcdefghijklmnop123456")
}
