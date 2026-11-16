//go:build linux

package runtimeadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/seccheck"
	"github.com/byteyellow/agentprovenance/internal/seccheck/wire"
)

// This is an implementation-choice probe. It preserves exact runtime and raw
// receiver identities, and does not promote a command's capture to complete.
func probeControlledGate(t *testing.T, ctx context.Context, s Runsc, root, helper string, records func() []seccheck.Record) {
	t.Helper()
	type birth struct {
		PID   int32 `json:"pid"`
		Start int64 `json:"start_ns,string"`
	}
	lookup := func(pid int32) (birth, bool) {
		t.Helper()
		raw, err := s.control(ctx, "--root="+s.Config.Root, "trace", "procfs", s.Config.ContainerID)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if !strings.HasPrefix(line, "{") {
				continue
			}
			var value struct {
				Start  int64 `json:"clone_ts"`
				Status struct {
					PID int32 `json:"pid"`
				} `json:"status"`
			}
			if err := json.Unmarshal([]byte(line), &value); err != nil {
				t.Fatal(err)
			}
			if value.Status.PID == pid {
				return birth{pid, value.Start}, value.Start > 0
			}
		}
		return birth{}, false
	}
	type gated struct {
		cmd      *exec.Cmd
		gate     *os.File
		identity birth
		done     chan error
	}
	start := func(label string, argv ...string) gated {
		t.Helper()
		read, write, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(helper)
		if err != nil {
			t.Fatal(err)
		}
		pidfile := filepath.Join(root, label+".pid")
		args := []string{"--root=" + s.Config.Root, "exec", "--new-pidns", "--internal-pid-file=" + pidfile,
			"--pass-fd=3:3", "--exec-fd=4", s.Config.ContainerID, "agentprov-owned-probe"}
		args = append(args, argv...)
		cmd := exec.CommandContext(ctx, s.Config.Binary, args...)
		cmd.Env = []string{"PATH=/usr/bin:/bin"}
		cmd.ExtraFiles = []*os.File{read, file}
		log, err := os.OpenFile(filepath.Join(root, label+".log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stdout, cmd.Stderr = log, log
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		read.Close()
		file.Close()
		done := make(chan error, 1)
		go func() { done <- cmd.Wait(); log.Close() }()
		t.Cleanup(func() { write.Close() })
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case err := <-done:
				t.Fatalf("gate exited before release: %v", err)
			default:
			}
			if raw, err := os.ReadFile(pidfile); err == nil {
				pid, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 32)
				if err == nil {
					if identity, ok := lookup(int32(pid)); ok {
						return gated{cmd, write, identity, done}
					}
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("gated runtime identity timeout")
		return gated{}
	}
	release := func(g gated) {
		t.Helper()
		if _, err := g.gate.Write([]byte{0xa5}); err != nil {
			t.Fatal(err)
		}
		g.gate.Close()
		select {
		case err := <-g.done:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	marker := "/tmp/agentprov-gate-" + filepath.Base(root)
	command := start("controlled-command", "/bin/sh", "-c", "printf command > "+marker+"; (/bin/sleep 0.1; printf child > "+marker+"-child) & wait")
	for _, r := range records() {
		if r.Packet == nil {
			continue
		}
		if open, ok := r.Packet.Message.(*wire.Open); ok && strings.HasPrefix(open.Pathname, marker) {
			t.Fatal("workload ran before durable release")
		}
	}
	binding := map[string]any{"target": s.Binding.Target, "operation_id": "controlled-probe", "attempt_id": "controlled-attempt",
		"runtime_lifecycle": s.Config.StateCreated, "root": command.identity, "basis": "private_exec_fd_gate_and_runtime_procfs"}
	raw, _ := json.MarshalIndent(binding, "", "  ")
	p, err := os.OpenFile(filepath.Join(root, "controlled-gate-binding.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := p.Sync(); err != nil {
		t.Fatal(err)
	}
	p.Close()
	d, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Sync(); err != nil {
		t.Fatal(err)
	}
	d.Close()
	release(command)
	if _, exists := lookup(command.identity.PID); exists {
		t.Fatal("root remains visible after wait")
	}
	// A second owned process generates an explicit transport marker only after
	// the command root is gone. Exact ancestry and all-task drain are still
	// separate production obligations; this probe reports the available fields.
	barrier := start("controlled-barrier", "/bin/cat", marker)
	release(barrier)
	var observations []map[string]any
	deadline := time.Now().Add(3 * time.Second)
	rootOpen, childOpen, barrierOpen := false, false, false
	for time.Now().Before(deadline) {
		observations = nil
		for _, r := range records() {
			if r.Packet == nil || r.Packet.Context == nil {
				continue
			}
			c := r.Packet.Context
			if open, ok := r.Packet.Message.(*wire.Open); ok && strings.HasPrefix(open.Pathname, marker) {
				identity := birth{c.ThreadGroupId, c.ThreadGroupStartTimeNs}
				rootOpen = rootOpen || (identity == command.identity && open.Pathname == marker)
				childOpen = childOpen || (identity != command.identity && open.Pathname == marker+"-child")
				barrierOpen = barrierOpen || (identity == barrier.identity && open.Pathname == marker)
				observations = append(observations, map[string]any{"sequence": r.Sequence, "connection_id": r.ConnectionID,
					"identity": identity, "pathname": open.Pathname, "dropped_count": r.Packet.Header.DroppedCount, "is_exit": open.Exit != nil})
			}
		}
		if rootOpen && childOpen && barrierOpen {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	report := map[string]any{"root_identity_preserved_across_exec": rootOpen, "child_marker_observed": childOpen,
		"barrier_identity": barrier.identity, "barrier_observed": barrierOpen, "observations": observations,
		"production_capture_watermark": "pending_all_task_drain_and_durable_receiver_integration"}
	raw, _ = json.MarshalIndent(report, "", "  ")
	if err := os.WriteFile(filepath.Join(root, "controlled-gate-probe.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if !rootOpen || !childOpen || !barrierOpen {
		t.Fatal(fmt.Sprintf("gate probe incomplete: root=%v child=%v barrier=%v", rootOpen, childOpen, barrierOpen))
	}
}
