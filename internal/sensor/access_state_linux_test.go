//go:build linux && (amd64 || arm64)

package sensor

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/accesscontrol"
)

func TestLiveSensorAccessState(t *testing.T) {
	if os.Getenv("AGENTPROV_ACCESS_STATE_LIVE") != "1" {
		t.Skip("set AGENTPROV_ACCESS_STATE_LIVE=1 on a disposable Linux host")
	}
	f, err := os.CreateTemp(t.TempDir(), "state-events-")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ready, finished := make(chan struct{}), make(chan error, 1)
	go func() {
		finished <- RunWithOptions(f, Options{Context: ctx, AppArmorState: true, SeccompState: true, Diagnostics: io.Discard, OnReady: func() { close(ready) }})
	}()
	select {
	case <-ready:
	case err := <-finished:
		t.Fatalf("sensor startup: %v", err)
	case <-ctx.Done():
		<-finished
		t.Fatal("sensor startup timeout")
	}
	cmd := exec.CommandContext(ctx, "sleep", "2")
	if err := cmd.Start(); err != nil {
		cancel()
		<-finished
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	err = cmd.Wait()
	cancel()
	if sensorErr := <-finished; sensorErr != nil {
		t.Fatal(sensorErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 2<<20)
	found := 0
	for scanner.Scan() {
		var event struct {
			Source string                 `json:"source"`
			Type   string                 `json:"event_type"`
			State  accesscontrol.Snapshot `json:"state"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		if event.Source != "procfs_access_control" || event.Type != "access_control_state" || event.State.Identity.PID != pid || event.State.Identity.Status != "observed" {
			continue
		}
		if err := accesscontrol.ValidateSnapshot(event.State); err != nil {
			t.Fatal(err)
		}
		if event.State.Seccomp.Status != "observed" {
			t.Fatalf("missing actual state: %+v", event.State)
		}
		found++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if found == 0 {
		t.Fatal("sensor did not emit target procfs state")
	}
	if evidence := os.Getenv("AGENTPROV_ACCESS_STATE_EVIDENCE"); evidence != "" {
		if err := os.MkdirAll(evidence, 0700); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(evidence, "sensor-state.jsonl"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("captured %d automatic state snapshots for pid %d", found, pid)
}
