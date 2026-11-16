package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/handoff"
	"github.com/byteyellow/agentprovenance/internal/runtimeadapter"
)

func TestExecutionBackendNativeDefaultWired(t *testing.T) {
	base := `{"target":{"producer_id":"executor","instance_id":"node","generation":"1"},"caller":{"principal_id":"router","producer_id":"source","namespace":"lab"}`
	for _, backend := range []string{`}`, `,"backend":{"mode":"native"}}`, `,"backend":{"mode":"guest"},"capture":{"mode":"native","placement":"guest_kernel"}}`} {
		c, err := handoff.ReadConfig(strings.NewReader(base + backend))
		if err != nil {
			t.Fatal(err)
		}
		e := &handoff.Executor{}
		if err := configureExecutionBackend(e, c); err != nil {
			t.Fatal(err)
		}
		if e.Backend != nil || e.RuntimeCapture != nil {
			t.Fatal("native/guest execution was replaced")
		}
		if c.Backend != nil && (e.Binding == nil || e.Binding.Mode != c.Backend.Mode) {
			t.Fatal("backend config did not reach executor")
		}
	}
}

func TestExecutionBackendRequiresTrustedGuestConfigInRealCommand(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "execution.json")
	raw := `{"target":{"producer_id":"executor","instance_id":"node","generation":"1"},"caller":{"principal_id":"router","producer_id":"source","namespace":"lab"},"backend":{"mode":"guest"},"capture":{"mode":"native","placement":"guest_kernel"}}`
	if err := os.WriteFile(config, []byte(raw), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(config, 0o666); err != nil {
		t.Fatal(err)
	}
	cmd := NewRootCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--data-dir", filepath.Join(root, "store"), "daemon", "serve", "--execution-config", config, "--auth-token", "fixture-token", "--listen", "127.0.0.1:0"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "root-owned") {
		t.Fatalf("daemon did not enforce backend trust: %v", err)
	}
}

func TestExecutionBackendNativeConfigRemainsUsableWithoutRoot(t *testing.T) {
	config := filepath.Join(t.TempDir(), "execution.json")
	raw := `{"target":{"producer_id":"executor","instance_id":"node","generation":"1"},"caller":{"principal_id":"router","producer_id":"source","namespace":"lab"}}`
	if err := os.WriteFile(config, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readExecutionBackendConfig(config); err != nil {
		t.Fatal(err)
	}
}

func TestExecutionBackendGuestChecksKernelBootIdentity(t *testing.T) {
	c := handoff.Config{Target: handoff.Target{ProducerID: "executor", InstanceID: "pod", Generation: "generation"}, Backend: &handoff.BackendConfig{Mode: "guest", Guest: &runtimeadapter.GuestIdentity{
		RuntimeClass: "kata-qemu", RuntimeHandler: "kata-qemu-runtime-rs", PodUID: "pod", ContainerID: "container", GuestBootID: "wrong-boot"}}}
	if err := configureExecutionBackend(&handoff.Executor{}, c); err == nil || !strings.Contains(err.Error(), "boot identity") {
		t.Fatalf("accepted wrong kernel identity: %v", err)
	}
	if boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		c.Backend.Guest.GuestBootID = strings.TrimSpace(string(boot))
		e := &handoff.Executor{}
		if err := configureExecutionBackend(e, c); err != nil {
			t.Fatal(err)
		}
		if e.Backend != nil || e.Binding.PodUID != "pod" || e.Binding.GuestBootID != c.Backend.Guest.GuestBootID {
			t.Fatal("guest metadata lost or changed the executor")
		}
	}
}
