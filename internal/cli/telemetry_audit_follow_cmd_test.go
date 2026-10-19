//go:build linux || darwin

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"github.com/byteyellow/agentprovenance/internal/daemon"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestAuditReaderJSONDiagnosticsStayEnglish(t *testing.T) {
	for _, name := range []string{"ingest-audit", "follow-audit"} {
		for _, machine := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/json=%t", name, machine), func(t *testing.T) {
				dir := t.TempDir()
				path := filepath.Join(t.TempDir(), "audit.log")
				if err := os.WriteFile(path, []byte(auditCLIRecord+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
				lock, err := json.Marshal(daemon.LockInfo{PID: os.Getppid(), Addr: "127.0.0.1:1"})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, ".daemon.lock"), lock, 0600); err != nil {
					t.Fatal(err)
				}
				root := NewRootCommand()
				var stdout, stderr bytes.Buffer
				root.SetOut(&stdout)
				root.SetErr(&stderr)
				args := []string{"--lang", "zh-CN", "--data-dir", dir, "telemetry", name, "--run", "fixture", "--file", path}
				if name == "follow-audit" {
					args = append(args, "--once")
				}
				if machine {
					args = append(args, "--json")
				}
				root.SetArgs(args)
				if err := root.Execute(); err != nil {
					t.Fatal(err)
				}
				hasChinese := strings.ContainsFunc(stderr.String(), func(r rune) bool { return unicode.Is(unicode.Han, r) })
				if stderr.Len() == 0 || hasChinese == machine {
					t.Fatalf("unexpected diagnostic language: %q", stderr.String())
				}
			})
		}
	}
}

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
