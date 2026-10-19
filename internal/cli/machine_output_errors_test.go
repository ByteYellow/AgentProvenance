package cli

import (
	"bytes"
	"strings"
	"testing"
	"unicode"
)

func TestAuditAndAIToolErrorsStayEnglish(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"audit query", []string{"telemetry", "audit-associations", "--run", "fixture", "--limit", "0", "--json"}, "audit association limit"},
		{"audit flags", []string{"telemetry", "audit-associations", "--limit", "invalid", "--json"}, "invalid argument"},
		{"audit import", []string{"telemetry", "ingest-audit", "--run", "fixture", "--json"}, "required flag"},
		{"audit follow", []string{"telemetry", "follow-audit", "--run", "fixture", "--once", "--json"}, "required flag"},
		{"AI input", []string{"ai", "call", "get_audit_associations", "--input", "{"}, "invalid --input JSON"},
		{"AI provider", []string{"ai", "tools", "--provider", "invalid"}, "unknown provider"},
		{"MCP args", []string{"ai", "mcp", "unexpected"}, "unknown command"},
	} {
		for _, locale := range []string{"en", "zh-CN"} {
			t.Run(tc.name+"/"+locale, func(t *testing.T) {
				root := NewRootCommand()
				var stdout, stderr bytes.Buffer
				root.SetOut(&stdout)
				root.SetErr(&stderr)
				root.SetArgs(append([]string{"--lang", locale, "--data-dir", t.TempDir()}, tc.args...))
				err := root.Execute()
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("error=%v, want %q", err, tc.want)
				}
				if stdout.Len() != 0 || stderr.Len() != 0 {
					t.Fatalf("machine error included help: stdout=%q stderr=%q", stdout.String(), stderr.String())
				}
				message := ErrorText(root, err)
				if strings.ContainsFunc(message, func(r rune) bool { return unicode.Is(unicode.Han, r) }) {
					t.Fatalf("machine error was translated: %q", message)
				}
			})
		}
	}
}
