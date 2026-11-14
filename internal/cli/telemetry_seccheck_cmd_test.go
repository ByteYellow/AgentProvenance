package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecCheckPublicCollectionCommands(t *testing.T) {
	for _, name := range []string{"receive-seccheck", "seccheck-config"} {
		cmd, _, err := NewRootCommand().Find([]string{"telemetry", name})
		if err != nil || cmd.Name() != name {
			t.Fatalf("missing public collection command %s: %v", name, err)
		}
	}
}

func TestSecCheckConfigCommandAndInvalidRegistration(t *testing.T) {
	cmd := NewRootCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--lang", "zh-CN", "telemetry", "seccheck-config", "--socket", "/tmp/private/events.sock"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if json.Unmarshal(out.Bytes(), &config) != nil || config["trace_session"] == nil {
		t.Fatal(out.String())
	}
	for _, input := range []string{`{}`, `{"unknown":true}`, `{} {}`, strings.Repeat(" ", (1<<20)+1)} {
		root := t.TempDir()
		path, data := filepath.Join(root, "registration.json"), filepath.Join(root, "data")
		if err := os.WriteFile(path, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		cmd := telemetryReceiveSecCheckCmd(&data)
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs([]string{"--config", path, "--json"})
		if err := cmd.Execute(); err == nil {
			t.Fatal("invalid registration accepted")
		}
		if _, err := os.Stat(data); !os.IsNotExist(err) {
			t.Fatalf("invalid configuration modified store: %v", err)
		}
	}
}
