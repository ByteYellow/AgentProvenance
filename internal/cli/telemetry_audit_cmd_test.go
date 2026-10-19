package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

const auditCLIRecord = `type=SECCOMP msg=audit(1792342593.757:130): pid=42 comm="fixture" arch=c00000b7 syscall=203 sig=0 code=0x7ffc0000`

func auditCLI(t *testing.T, dir, input string, args ...string) (telemetry.AuditIngestResult, error) {
	t.Helper()
	cmd := telemetryIngestAuditCmd(&dir)
	cmd.SilenceErrors, cmd.SilenceUsage = true, true
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetIn(strings.NewReader(input))
	cmd.SetArgs(append([]string{"--file", "-", "--run", "run-audit", "--host-id", "test-host", "--boot-id", "01234567-89ab-cdef-0123-456789abcdef", "--json"}, args...))
	err := cmd.ExecuteContext(context.Background())
	var result telemetry.AuditIngestResult
	if stdout.Len() != 0 {
		if decodeErr := json.Unmarshal(stdout.Bytes(), &result); decodeErr != nil {
			t.Fatalf("invalid JSON result %q: %v", stdout.String(), decodeErr)
		}
	}
	return result, err
}

func TestAuditCommandUsesFixedRunRetention(t *testing.T) {
	for _, preset := range []string{"basic", "detailed"} {
		t.Run(preset, func(t *testing.T) {
			dir := t.TempDir()
			r, err := auditCLI(t, dir, auditCLIRecord, "--capture", preset)
			if err != nil || r.Ingested != 1 || r.Status != "completed" || r.RawRecordsRetained != (preset == "detailed") {
				t.Fatalf("import: %+v %v", r, err)
			}
			r, err = auditCLI(t, dir, auditCLIRecord)
			if err != nil || r.Ingested != 0 || r.Duplicates != 1 || r.RawRecordsRetained != (preset == "detailed") {
				t.Fatalf("retry changed fixed capture settings: %+v %v", r, err)
			}
			other := "basic"
			if preset == "basic" {
				other = "detailed"
			}
			if _, err := auditCLI(t, dir, auditCLIRecord, "--capture", other); err == nil || !strings.Contains(err.Error(), "fixed") {
				t.Fatalf("changed capture policy: %v", err)
			}
			paths, err := store.Init(dir)
			if err != nil {
				t.Fatal(err)
			}
			db, err := store.Open(paths)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			events, err := telemetry.ListEvents(db, "run-audit", "")
			if err != nil || len(events) != 1 || strings.Contains(events[0].Payload, `"text":`) != (preset == "detailed") {
				t.Fatalf("stored source retention: %+v %v", events, err)
			}
		})
	}
}

func TestAuditCommandHonorsExistingCaptureOverride(t *testing.T) {
	dir := t.TempDir()
	paths, err := store.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	disabled := false
	policy, err := agentcontext.NewCapturePolicy("detailed", &disabled)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (agentcontext.Service{DB: db, Paths: paths, CapturePolicy: &policy}).EnsureCapturePolicy(context.Background(), "run-audit"); err != nil {
		t.Fatal(err)
	}
	r, err := auditCLI(t, dir, auditCLIRecord)
	if err != nil || r.RawRecordsRetained || r.Ingested != 1 {
		t.Fatalf("source override ignored: %+v %v", r, err)
	}
}

func TestAuditCommandFileFilterAndPartialStatus(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(t.TempDir(), "audit.log")
	input := auditCLIRecord + "\n" + `type=AVC msg=audit(1792342593.757:131): apparmor="DENIED" operation="open" pid=42 name="/tmp/fixture"`
	if err := os.WriteFile(path, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := auditCLI(t, dir, "", "--file", path, "--mechanism", "apparmor")
	if err != nil || r.Ingested != 1 || r.Skipped != 1 || r.Rows[1].Source != "apparmor_audit" {
		t.Fatalf("file/filter: %+v %v", r, err)
	}
	r, err = auditCLI(t, dir, auditCLIRecord+"\ntype=SECCOMP msg=audit(bad)")
	if err == nil || r.Status != "partial" || r.Ingested != 1 || r.Failed != 1 || r.FileSHA256 == "" {
		t.Fatalf("partial import not reported: %+v %v", r, err)
	}
	for _, args := range [][]string{{}, {"--run", "run"}, {"--file", "-"}} {
		cmd := telemetryIngestAuditCmd(&dir)
		cmd.SilenceErrors, cmd.SilenceUsage = true, true
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil {
			t.Fatalf("required flags not checked: %v", args)
		}
	}
	if _, err := auditCLI(t, dir, auditCLIRecord, "--mechanism", "invalid"); err == nil {
		t.Fatal("unknown mechanism accepted")
	}
}
