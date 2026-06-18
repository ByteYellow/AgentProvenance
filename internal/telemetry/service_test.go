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
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
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
	for _, edgeType := range []string{"runtime_tool_call_process", "runtime_tool_call_event", "runtime_process_event", "runtime_process_observed"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE edge_type = ?`, edgeType).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count == 0 {
			t.Fatalf("missing runtime causality edge %s", edgeType)
		}
	}
}

func TestIngestFilteredLeavesUnresolvedRawEvent(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
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

func TestIngestFilteredCorrelatesCgroupScopedRuntimeEvent(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
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
		StartedAt:     started,
		BindingSource: "test",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := IngestFiltered(db, IngestEvent{
		RawEventID: "raw-cgroup-1",
		CgroupID:   "cgroup-1",
		EventType:  "network_connect",
		Source:     "tetragon_jsonl",
		Payload:    `{"dst":"api.example.com:443"}`,
	}); err != nil {
		t.Fatal(err)
	}

	events, err := ListEventsFiltered(db, Filter{RunID: "run-1", Type: "network_connect"})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	event := events[0]
	if event.ToolCallID != "tool-1" || event.ProcessID != "proc-1" {
		t.Fatalf("event correlation = %+v, want tool/process", event)
	}
	if event.CorrelationMethod != "cgroup_time_window:cgroup_id+time" {
		t.Fatalf("correlation method = %q", event.CorrelationMethod)
	}
	var edgeCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE edge_type = 'runtime_tool_call_event' AND from_id = 'tool-1'`).Scan(&edgeCount); err != nil {
		t.Fatal(err)
	}
	if edgeCount == 0 {
		t.Fatalf("missing runtime_tool_call_event edge for cgroup-scoped event")
	}
}

func TestIngestFilteredAcceptsFileRuntimeEvents(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := IngestFiltered(db, IngestEvent{
		RunID:      "run-1",
		SessionID:  "session-1",
		ToolCallID: "tool-1",
		ProcessID:  "process-1",
		EventType:  "file_write",
		Source:     "native_runtime",
		Payload:    `{"path":"calculator.py","op":"write"}`,
	}); err != nil {
		t.Fatal(err)
	}
	var edges int
	if err := db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE edge_type = 'runtime_process_event'`).Scan(&edges); err != nil {
		t.Fatal(err)
	}
	if edges != 1 {
		t.Fatalf("runtime_process_event edges=%d, want 1", edges)
	}
}
