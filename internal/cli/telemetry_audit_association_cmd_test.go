package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestAuditAssociationCommandReadsSavedEvidence(t *testing.T) {
	dir, daemonURL := t.TempDir(), ""
	if _, err := auditCLI(t, dir, auditCLIRecord); err != nil {
		t.Fatal(err)
	}
	cmd := telemetryAuditAssociationsCmd(&dir, &daemonURL)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--run", "run-audit", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var report telemetry.AuditAssociationReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil || len(report.Items) != 1 || report.Items[0].Process.Status != "unassociated" {
		t.Fatalf("audit without lifetime was guessed: %+v %v", report, err)
	}
	for _, args := range [][]string{{}, {"--run", "run", "--limit", "0"}, {"--run", "run", "--limit", "501"}, {"--run", "run", "--cursor", "bad"}} {
		cmd := telemetryAuditAssociationsCmd(&dir, &daemonURL)
		cmd.SilenceErrors, cmd.SilenceUsage = true, true
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil {
			t.Fatalf("invalid options accepted: %v", args)
		}
	}
}

func TestAuditAssociationCommandUsesDaemon(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "must-not-initialize")
	t.Setenv("AGENTPROV_DAEMON_TOKEN", "cli-test-token")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/telemetry/audit-associations" || r.URL.Query().Get("run") != "remote run" || r.Header.Get("Authorization") != "Bearer cli-test-token" {
			t.Errorf("unexpected request: %s", r.URL)
		}
		_ = json.NewEncoder(w).Encode(telemetry.AuditAssociationReport{RunID: "remote run", Status: "complete", Items: []telemetry.AuditAssociationItem{}})
	}))
	defer server.Close()
	remote := server.URL
	cmd := telemetryAuditAssociationsCmd(&dir, &remote)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--run", "remote run", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var report telemetry.AuditAssociationReport
	if json.Unmarshal(out.Bytes(), &report) != nil || report.RunID != "remote run" {
		t.Fatal(out.String())
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("remote query initialized local store: %v", err)
	}
}

func TestAuditAssociationJSONDoesNotFollowUILanguage(t *testing.T) {
	dir := t.TempDir()
	if _, err := auditCLI(t, dir, auditCLIRecord); err != nil {
		t.Fatal(err)
	}
	var baseline string
	for _, locale := range []string{"en", "zh-CN"} {
		root := NewRootCommand()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{"--lang", locale, "--data-dir", dir, "telemetry", "audit-associations", "--run", "run-audit", "--json"})
		if err := root.Execute(); err != nil {
			t.Fatal(err)
		}
		var report telemetry.AuditAssociationReport
		if err := json.Unmarshal(out.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if len(report.Items) != 1 || report.Items[0].Process.Status != "unassociated" || report.AnalysisScope != "query_page" {
			t.Fatalf("unexpected API contract: %+v", report)
		}
		if locale == "en" {
			baseline = out.String()
		} else if out.String() != baseline {
			t.Fatalf("UI language changed JSON output:\n%s\n%s", baseline, out.String())
		}
	}
}
