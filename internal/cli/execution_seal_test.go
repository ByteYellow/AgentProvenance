package cli

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/daemon"
	"github.com/byteyellow/agentprovenance/internal/handoff"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestExecutionSealRequiresDelivery(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "execution.json")
	if err := os.WriteFile(config, []byte(`{"target":{"producer_id":"vm","instance_id":"one","generation":"first"},"caller":{"principal_id":"router","producer_id":"mac","namespace":"user"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := NewRootCommand()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--data-dir", filepath.Join(root, "store"), "forensics", "seal-executions", "--execution-config", config, "--operation", "shutdown"})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := cmd.ExecuteContext(ctx)
	if err == nil || !strings.Contains(err.Error(), "execution sealing requires delivery configuration") {
		t.Fatalf("unexpected configuration validation: %v", err)
	}
}

func sealCLIConfig(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	pub, key, _, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string][]byte{"sender.key": key, "receiver.pub": pub} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(hex.EncodeToString(value)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	config := filepath.Join(root, "execution.json")
	if err := os.WriteFile(config, []byte(`{"target":{"producer_id":"vm","instance_id":"one","generation":"first"},"caller":{"principal_id":"router","producer_id":"mac","namespace":"user"},"delivery":{"receiver_id":"receiver","sign_key_file":"sender.key","receiver_public_key_file":"receiver.pub"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, config
}

func TestExecutionSealCLIJSONAndLocalBoundary(t *testing.T) {
	root, config := sealCLIConfig(t)
	for _, remote := range []bool{false, true} {
		cmd := NewRootCommand()
		var output bytes.Buffer
		cmd.SetOut(&output)
		cmd.SetErr(io.Discard)
		args := []string{"--data-dir", filepath.Join(root, "store"), "--lang", "zh-CN"}
		if remote {
			args = append(args, "--daemon-url", "http://127.0.0.1:1")
		}
		args = append(args, "forensics", "seal-executions", "--execution-config", config, "--operation", "retirement-1")
		cmd.SetArgs(args)
		err := cmd.Execute()
		if remote {
			if err == nil || !strings.Contains(err.Error(), "requires the stopped local store") {
				t.Fatalf("remote boundary: %v", err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		var summary handoff.SealSummary
		if err := json.Unmarshal(output.Bytes(), &summary); err != nil || summary.SchemaVersion != handoff.SealSchema || !summary.Complete || summary.Attempts != 0 {
			t.Fatalf("JSON summary: %s %v", output.String(), err)
		}
		if summary.Target.Generation != "first" || summary.ReceiverID != "receiver" || summary.OperationID != "retirement-1" {
			t.Fatalf("missing seal identity: %+v", summary)
		}
	}
}

func TestExecutionSealCLIRejectsLiveDaemon(t *testing.T) {
	root, config := sealCLIConfig(t)
	paths, err := store.Init(filepath.Join(root, "store"))
	if err != nil {
		t.Fatal(err)
	}
	process := exec.Command("sleep", "30")
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = process.Process.Kill(); _ = process.Wait() }()
	raw, err := json.Marshal(daemon.LockInfo{PID: process.Process.Pid, Addr: "127.0.0.1:8574", StartedAt: time.Now().UTC().Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(paths.Root, ".daemon.lock"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	receipt := filepath.Join(root, "receipt.json")
	if err := os.WriteFile(receipt, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, action := range [][]string{{"seal-executions", "--operation", "retirement-1"}, {"acknowledge-execution", "delivery", receipt}} {
		cmd := NewRootCommand()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		args := append([]string{"--data-dir", paths.Root, "forensics"}, action...)
		cmd.SetArgs(append(args, "--execution-config", config))
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "requires a stopped daemon") {
			t.Fatalf("live daemon %s: %v", action[0], err)
		}
	}
	actual, err := os.ReadFile(filepath.Join(paths.Root, ".daemon.lock"))
	if err != nil || !bytes.Equal(actual, raw) {
		t.Fatalf("live daemon ownership changed: %v", err)
	}
}
