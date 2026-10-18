package cli

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestAuditAssociationCommandReadsSavedEvidence(t *testing.T) {
	dir := t.TempDir()
	if _, err := auditCLI(t, dir, auditCLIRecord); err != nil {
		t.Fatal(err)
	}
	cmd := telemetryAuditAssociationsCmd(&dir)
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
		cmd := telemetryAuditAssociationsCmd(&dir)
		cmd.SilenceErrors, cmd.SilenceUsage = true, true
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil {
			t.Fatalf("invalid options accepted: %v", args)
		}
	}
}
