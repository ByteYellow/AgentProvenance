//go:build linux || darwin

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestAuditFollowJSONEnglishAndSourceTextUnchanged(t *testing.T) {
	for _, lang := range []string{"en", "zh-CN"} {
		t.Run(lang, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(t.TempDir(), "audit.log")
			input := `type=AVC msg=audit(1792342593.757:131): apparmor="DENIED" operation="open" pid=42 name="/tmp/原始证据"` + "\n"
			if err := os.WriteFile(path, []byte(input), 0600); err != nil {
				t.Fatal(err)
			}
			root := NewRootCommand()
			var out, stderr bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&stderr)
			root.SetArgs([]string{"--lang", lang, "--data-dir", dir, "telemetry", "follow-audit", "--run", "audit-follow", "--file", path, "--capture", "detailed", "--once", "--json"})
			if err := root.Execute(); err != nil {
				t.Fatalf("follow CLI: %v %s", err, stderr.String())
			}
			var status telemetry.AuditFollowStatus
			if err := json.Unmarshal(out.Bytes(), &status); err != nil || status.Reader.Status != "stopped" || status.Reader.Reason != "snapshot_drained" || status.Reader.Ingested != 1 || status.Reader.UpstreamLoss != "unknown" {
				t.Fatalf("JSON contract: %s %v", out.String(), err)
			}
			if strings.IndexFunc(out.String(), func(r rune) bool { return unicode.Is(unicode.Han, r) }) != -1 {
				t.Fatalf("localized machine output: %s", out.String())
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
			var payload string
			if err := db.QueryRow(`SELECT payload FROM events WHERE event_type='access_control'`).Scan(&payload); err != nil || !strings.Contains(payload, "原始证据") {
				t.Fatalf("original text changed: %s %v", payload, err)
			}
		})
	}
}

func TestAuditFollowCLIMissingSourceHasEnglishStatus(t *testing.T) {
	dir := t.TempDir()
	root := NewRootCommand()
	root.SilenceErrors, root.SilenceUsage = true, true
	var out, stderr bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&stderr)
	root.SetArgs([]string{"--lang", "zh-CN", "--data-dir", dir, "telemetry", "follow-audit", "--run", "audit-follow", "--file", filepath.Join(t.TempDir(), "missing"), "--once", "--json"})
	err := root.Execute()
	var status telemetry.AuditFollowStatus
	if err == nil || json.Unmarshal(out.Bytes(), &status) != nil || status.Reader.Status != "failed" || status.Reader.Reason != "source_missing" {
		t.Fatalf("missing source: %s %v", out.String(), err)
	}
}

func TestAuditFollowCLIUsesExistingRetention(t *testing.T) {
	dir := t.TempDir()
	if _, err := auditCLI(t, dir, auditCLIRecord, "--capture", "basic"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, []byte(strings.Replace(auditCLIRecord, ":130)", ":131)", 1)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := telemetryFollowAuditCmd(&dir)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--run", "run-audit", "--file", path, "--once", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var status telemetry.AuditFollowStatus
	if err := json.Unmarshal(out.Bytes(), &status); err != nil || status.Reader.RawRecordsRetained || status.Reader.Ingested != 1 {
		t.Fatalf("fixed basic retention ignored: %s %v", out.String(), err)
	}
}
