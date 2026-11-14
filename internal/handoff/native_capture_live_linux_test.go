//go:build linux && (amd64 || arm64)

package handoff

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/producer"
	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/byteyellow/agentprovenance/internal/sensor"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestLiveExecutorSealsNativeCapture(t *testing.T) {
	if os.Getenv("AGENTPROV_TEST_EXECUTION_CAPTURE") != "1" {
		t.Skip("set AGENTPROV_TEST_EXECUTION_CAPTURE=1 with Linux BPF and delegated cgroup v2 permissions")
	}
	e, p, request := testExecutor(t)
	e.Options.AllowShell = true
	ingest := telemetry.JSONLIngestOptions{Format: "native", DropUncorrelated: true}
	if own := producer.SelfCgroupID(); own != "" {
		ingest.ExcludeCgroupIDs = []string{own}
	}
	stream, err := telemetry.NewNativeStream(e.Ledger.DB, e.Paths, telemetry.NativeStreamOptions{
		Ingest: ingest, BatchEvents: 128})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	cp := sensor.NewCheckpointer()
	var caps sensor.CapabilityReport
	var capsMu sync.Mutex
	e.Capture = &NativeCapture{Checkpointer: cp, Stream: stream, Timeout: 3 * time.Second, Capabilities: func() sensor.CapabilityReport {
		capsMu.Lock()
		defer capsMu.Unlock()
		return caps
	}}
	ctx, cancel := context.WithCancel(context.Background())
	ready, done := make(chan struct{}), make(chan error, 1)
	go func() {
		done <- sensor.RunWithOptions(stream, sensor.Options{
			Context: ctx, Checkpointer: cp, Diagnostics: io.Discard, OnReady: func() { close(ready) },
			OnCapabilities: func(report sensor.CapabilityReport) { capsMu.Lock(); caps = report; capsMu.Unlock() },
		})
	}()
	stopped := false
	defer func() {
		cancel()
		if !stopped {
			select {
			case err := <-done:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(10 * time.Second):
				t.Error("sensor shutdown timeout")
			}
		}
	}()
	select {
	case <-ready:
	case err := <-done:
		stopped = true
		t.Fatalf("sensor start: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("sensor readiness timeout")
	}
	// A separate recorder creates real node events without publishing bindings
	// into this executor's store. Its backlog must remain visible throughout.
	foreign, _, _ := testExecutor(t)
	if _, err := (record.Service{DB: foreign.Ledger.DB, Paths: foreign.Paths}).Run(record.Request{
		RunID: "unrelated-node-work", Command: []string{"touch", "unrelated.txt"}, DisableSnapshot: true, PostRootGraceMS: 1,
	}); err != nil {
		t.Fatal(err)
	}
	stopExecutor := startExecutor(t, e)
	defer func() {
		if err := stopExecutor(); err != nil {
			t.Error(err)
		}
	}()
	ids := []string{}
	for i := 0; i < 2; i++ {
		r := request
		r.DispatchID, r.OperationID = fmt.Sprintf("capture-%d", i), fmt.Sprintf("capture-op-%d", i)
		r.Source.ToolCallID = fmt.Sprintf("capture-tool-%d", i)
		r.Command.Workdir = filepath.Join(e.Paths.Workspaces, fmt.Sprintf("capture-%d", i))
		if err := os.MkdirAll(r.Command.Workdir, 0o700); err != nil {
			t.Fatal(err)
		}
		r.Command.Argv = []string{"/bin/sh", "-c", "printf 'native execution capture\\n' > result.txt; sleep 0.05"}
		a, _, err := e.Ledger.Admit(context.Background(), p, r)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, a.ID)
	}
	groups := map[string]bool{}
	for _, id := range ids {
		r := waitCapture(t, e, p, id)
		writeCaptureReport(t, r)
		c := r.Checkpoint.Capture
		if r.Attempt.State.Execution != Succeeded || r.Attempt.State.Capture != Sealed || c == nil || c.State != Sealed ||
			c.Start.Sensor.KernelTimeNS == 0 || c.End.Sensor.Sequence <= c.Start.Sensor.Sequence || c.ScopeProgress == nil || c.ScopeProgress.State != "settled" ||
			c.Progress == nil || c.Progress.Pending == 0 || c.Progress.State != "pending" ||
			c.Scope.Empty == nil || !*c.Scope.Empty || groups[r.Checkpoint.Scope.CgroupID] {
			t.Fatalf("native execution not sealed independently: %+v capture=%+v", r, c)
		}
		groups[r.Checkpoint.Scope.CgroupID] = true
		t.Logf("attempt=%s run=%s cgroup=%s boundaries=%d..%d scope=%+v shared_prefix=%+v", id, r.Attempt.LocalRunID,
			r.Checkpoint.Scope.CgroupID, c.Start.Sensor.Sequence, c.End.Sensor.Sequence, c.ScopeProgress, c.Progress)
		var count int
		if err := e.Ledger.DB.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id=? AND cgroup_id=? AND source='agentprov_ebpf' AND event_type='file_write' AND json_extract(payload,'$.payload.raw.path')='result.txt'`, r.Attempt.LocalRunID, r.Checkpoint.Scope.CgroupID).Scan(&count); err != nil || count == 0 {
			rows, queryErr := e.Ledger.DB.Query(`SELECT run_id,event_type,source,payload FROM events WHERE event_type='file_write' LIMIT 20`)
			if queryErr == nil {
				for rows.Next() {
					var run, kind, source, payload string
					if scanErr := rows.Scan(&run, &kind, &source, &payload); scanErr != nil {
						t.Error(scanErr)
						break
					}
					t.Logf("file event: run=%s kind=%s source=%s payload=%s", run, kind, source, payload)
				}
				rows.Close()
			}
			t.Fatalf("sealed execution lacks actual file-write event: count=%d err=%v", count, err)
		}
		t.Logf("native file writes=%d; checking signed delivery and receiver restart", count)
		checkCaptureDelivery(t, deliveryFromReport(t, e, p, r, r.Checkpoint.Scope.Workdir))
	}

	background := request
	background.DispatchID, background.OperationID = "background", "background-operation"
	background.Command.Argv = []string{"/bin/sh", "-c", "sleep 60 >/dev/null 2>&1 &"}
	a, _, err := e.Ledger.Admit(context.Background(), p, background)
	if err != nil {
		t.Fatal(err)
	}
	r := waitCapture(t, e, p, a.ID)
	writeCaptureReport(t, r)
	if r.Checkpoint != nil && r.Checkpoint.Scope != nil {
		scope := r.Checkpoint.Scope
		t.Cleanup(func() {
			parent := os.Getenv("AGENTPROV_CGROUP_PARENT")
			if parent == "" {
				parent = "/sys/fs/cgroup/agentprov"
			}
			dir := filepath.Join(parent, scope.AttemptID)
			_ = os.WriteFile(filepath.Join(dir, "cgroup.kill"), []byte("1"), 0o600)
			for i := 0; i < 100; i++ {
				if err := os.Remove(dir); err == nil || os.IsNotExist(err) {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Error("background fixture scope cleanup failed")
		})
	}
	if r.Attempt.State.Execution != Succeeded || r.Attempt.State.Capture != Incomplete ||
		r.Checkpoint.Capture.Scope.Empty == nil || *r.Checkpoint.Capture.Scope.Empty ||
		!strings.Contains(strings.Join(r.Checkpoint.Capture.Issues, ","), "scope_still_populated") {
		t.Fatalf("background process became sealed: %+v capture=%+v", r, r.Checkpoint.Capture)
	}
	t.Logf("background root=%s capture=%s issues=%v", r.Attempt.State.Execution, r.Attempt.State.Capture, r.Checkpoint.Capture.Issues)
}

func writeCaptureReport(t *testing.T, report Report) {
	t.Helper()
	dir := os.Getenv("AGENTPROV_TEST_CAPTURE_REPORT_DIR")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, report.Attempt.ID+".json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func waitCapture(t *testing.T, e *Executor, p Principal, id string) Report {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	var report Report
	for time.Now().Before(deadline) {
		var err error
		report, err = e.Ledger.Report(context.Background(), p, id)
		if err != nil {
			t.Fatal(err)
		}
		if report.Attempt.State.Capture == Sealed || report.Attempt.State.Capture == Incomplete {
			return report
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("capture did not finish: %+v", report)
	return report
}
