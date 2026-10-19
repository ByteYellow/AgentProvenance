package telemetry

import (
	"bufio"
	"bytes"
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

	"github.com/byteyellow/agentprovenance/internal/sensor"
)

type auditSensorBuffer struct {
	mu   sync.Mutex
	data bytes.Buffer
}

// The C fixture is run by sensor.TestLiveSyscallOutcomes. This second gate
// imports its actual capture and the host's existing journal, without enabling
// audit rules or inventing an ERRNO log on hosts that did not produce one.
func TestLiveSeccompAuditAssociations(t *testing.T) {
	directory := os.Getenv("AGENTPROV_AUDIT_SECCOMP_EVIDENCE")
	if directory == "" {
		t.Skip("set AGENTPROV_AUDIT_SECCOMP_EVIDENCE to current live syscall outcome captures")
	}
	type fixture struct {
		PID          int64            `json:"kernel_pid"`
		Observations []map[string]any `json:"observations"`
	}
	pids := map[int64]string{}
	var runtime bytes.Buffer
	var since time.Time
	for _, mode := range []string{"seccomp-errno", "seccomp-log", "seccomp-kill"} {
		raw, err := os.ReadFile(filepath.Join(directory, mode+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var data fixture
		if err := json.Unmarshal(raw, &data); err != nil || data.PID <= 0 || len(data.Observations) == 0 {
			t.Fatalf("invalid live fixture %s: %v", mode, err)
		}
		pids[data.PID] = mode
		for _, event := range data.Observations {
			at, err := time.Parse(time.RFC3339Nano, stringAt(event, "timestamp"))
			if err != nil {
				t.Fatal(err)
			}
			if since.IsZero() || at.Before(since) {
				since = at
			}
			if err := json.NewEncoder(&runtime).Encode(event); err != nil {
				t.Fatal(err)
			}
		}
	}
	journal := liveAuditCommand(t, "journalctl", "-k", "--since", since.Add(-time.Second).Format("2006-01-02 15:04:05 UTC"), "-n", "2000", "-o", "json", "--no-pager")
	var selected bytes.Buffer
	decisions := map[string]int{}
	scanner := bufio.NewScanner(bytes.NewReader(journal))
	scanner.Buffer(make([]byte, 4096), MaxAuditLineBytes)
	for scanner.Scan() {
		record, ok, err := ParseAuditLine(scanner.Bytes(), AuditSource{})
		if err != nil || !ok || record.Mechanism != "seccomp" || record.AuditPID == nil || pids[*record.AuditPID] == "" {
			continue
		}
		selected.Write(scanner.Bytes())
		selected.WriteByte('\n')
		decisions[record.Decision]++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if decisions["LOG"] != 1 || decisions["KILL_PROCESS"] != 1 {
		t.Fatalf("actual seccomp LOG/KILL audit records required: %+v", decisions)
	}
	saveLiveAuditFixture(t, "seccomp-runtime.jsonl", runtime.Bytes())
	saveLiveAuditFixture(t, "seccomp-journal.jsonl", selected.Bytes())
	db, _ := nativeTestStore(t)
	scanner = bufio.NewScanner(bytes.NewReader(runtime.Bytes()))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		var raw map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &raw); err != nil {
			t.Fatal(err)
		}
		event, ok, err := mapNative(raw)
		if err != nil || !ok {
			t.Fatalf("live native mapping: %v", err)
		}
		event.RunID = "live-seccomp-association"
		if _, err := IngestFiltered(db, event); err != nil {
			t.Fatal(err)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := IngestAuditReader(context.Background(), db, AuditIngestOptions{RunID: "live-seccomp-association", RetainRaw: true}, strings.NewReader(selected.String())); err != nil {
		t.Fatal(err)
	}
	report, err := BuildAuditAssociations(context.Background(), db, AuditAssociationOptions{RunID: "live-seccomp-association"})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.MarshalIndent(report, "", "  ")
	saveLiveAuditFixture(t, "seccomp-associations.json", encoded)
	for _, item := range report.Items {
		if item.Process.Status != "inferred" || len(item.ProcessExits) == 0 {
			t.Fatalf("seccomp process lifetime/exit missing: %+v", item)
		}
		switch item.Decision {
		case "LOG":
			if item.Operation.Status != "inferred" || len(item.Operations) != 1 || item.Operations[0].Result == nil || *item.Operations[0].Result != 0 {
				t.Fatalf("LOG did not pair with actual connect return: %+v", item)
			}
		case "KILL_PROCESS", "ERRNO":
			if item.Operation.Status != "unassociated" || len(item.Operations) != 0 {
				t.Fatalf("filtered syscall invented an operation: %+v", item)
			}
		default:
			t.Fatalf("unexpected fixture decision: %s", item.Decision)
		}
	}
	t.Logf("actual seccomp records=%v; LOG linked to captured return; KILL linked only to lifetime/exit", decisions)
}

func (b *auditSensorBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.data.Len()+len(p) > 16<<20 {
		return 0, fmt.Errorf("audit fixture sensor output exceeds 16 MiB")
	}
	return b.data.Write(p)
}

func (b *auditSensorBuffer) snapshot() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.data.Bytes()...)
}

func startLiveAuditSensor(t *testing.T) func([]int64) []byte {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var output auditSensorBuffer
	ready, done := make(chan struct{}), make(chan error, 1)
	go func() {
		done <- sensor.RunWithOptions(&output, sensor.Options{Context: ctx, Diagnostics: io.Discard, OnReady: func() { close(ready) }})
	}()
	var stopped bool
	stop := func() {
		if stopped {
			return
		}
		cancel()
		select {
		case err := <-done:
			stopped = true
			if err != nil {
				t.Errorf("live sensor: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("live sensor did not stop")
		}
	}
	t.Cleanup(stop)
	select {
	case <-ready:
	case err := <-done:
		stopped = true
		cancel()
		t.Fatalf("live sensor exited before readiness: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("live sensor not ready")
	}
	return func(pids []int64) []byte {
		t.Helper()
		wanted := map[int64]bool{}
		for _, pid := range pids {
			wanted[pid] = true
		}
		var selected bytes.Buffer
		deadline := time.Now().Add(4 * time.Second)
		for {
			selected.Reset()
			exits := map[int64]bool{}
			scanner := bufio.NewScanner(bytes.NewReader(output.snapshot()))
			scanner.Buffer(make([]byte, 4096), 1<<20)
			for scanner.Scan() {
				var event struct {
					PID   int64  `json:"pid"`
					Type  string `json:"event_type"`
					Scope string `json:"exit_scope"`
				}
				if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
					t.Fatal(err)
				}
				if !wanted[event.PID] {
					continue
				}
				selected.Write(scanner.Bytes())
				selected.WriteByte('\n')
				if event.Type == "process_exit" && event.Scope == "thread_group" {
					exits[event.PID] = true
				}
			}
			if err := scanner.Err(); err != nil {
				t.Fatal(err)
			}
			if len(exits) == len(wanted) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("live fixture exits missing: wanted=%v observed=%v", wanted, exits)
			}
			time.Sleep(50 * time.Millisecond)
		}
		stop()
		return append([]byte(nil), selected.Bytes()...)
	}
}
