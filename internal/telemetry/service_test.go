package telemetry

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestIngestFilteredCorrelatesRawRuntimeEvent(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".acf"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	started := time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
	if _, err := correlation.RecordBinding(db, correlation.Binding{
		RunID:         "run-1",
		SessionID:     "session-1",
		AttemptID:     "attempt-1",
		ToolCallID:    "tool-1",
		ProcessID:     "proc-1",
		ContainerID:   "container-1",
		CgroupID:      "cgroup-1",
		PID:           1234,
		StartedAt:     started,
		BindingSource: "test",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := IngestFiltered(db, IngestEvent{
		RawEventID:  "raw-1",
		ContainerID: "container-1",
		EventType:   "execve",
		Source:      "tetragon_jsonl",
		Payload:     `{"argv":["sh","-lc","echo hi"]}`,
	}); err != nil {
		t.Fatal(err)
	}

	events, err := ListEventsFiltered(db, Filter{RunID: "run-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	event := events[0]
	if event.RunID != "run-1" || event.SessionID != "session-1" || event.ToolCallID != "tool-1" || event.ProcessID != "proc-1" {
		t.Fatalf("event correlation = %+v, want run/session/tool/process", event)
	}
	if !strings.Contains(event.CorrelationMethod, "container_time_window") || event.CorrelationConfidence <= 0 {
		t.Fatalf("correlation method/confidence = %q %.2f", event.CorrelationMethod, event.CorrelationConfidence)
	}
	if !strings.Contains(event.Payload, `"binding_id"`) {
		t.Fatalf("payload missing correlation binding: %s", event.Payload)
	}
}

func TestIngestFilteredLeavesUnresolvedRawEvent(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".acf"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := IngestFiltered(db, IngestEvent{
		RawEventID: "raw-missing",
		PID:        9999,
		EventType:  "execve",
		Source:     "falco_jsonl",
		Payload:    `{"argv":["unknown"]}`,
	}); err != nil {
		t.Fatal(err)
	}
	events, err := ListEventsFiltered(db, Filter{Type: "execve"})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	event := events[0]
	if event.ToolCallID != "" || event.CorrelationMethod != "unresolved" || event.CorrelationConfidence != 0 {
		t.Fatalf("unresolved event = %+v", event)
	}
}
