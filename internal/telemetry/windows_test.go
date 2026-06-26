package telemetry

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestRebuildEventWindowsIsIdempotent(t *testing.T) {
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

	base := time.Date(2026, 1, 1, 12, 0, 4, 0, time.UTC)
	insertWindowEvent(t, db, "evt-1", "run-window", "session-1", "tool-1", "falco_jsonl", "execve", "container_time_window:container_id+time", base)
	insertWindowEvent(t, db, "evt-2", "run-window", "session-1", "tool-1", "falco_jsonl", "metadata_ip", "container_time_window:container_id+time", base.Add(2*time.Second))
	insertWindowEvent(t, db, "evt-3", "run-window", "session-1", "tool-1", "falco_jsonl", "network_connect", "unresolved", base.Add(13*time.Second))
	insertWindowEvent(t, db, "evt-other", "run-other", "session-2", "tool-2", "falco_jsonl", "execve", "provided_context", base)

	count, err := RebuildEventWindows(db, "run-window")
	if err != nil {
		t.Fatal(err)
	}
	if count != 6 {
		t.Fatalf("expected 6 windows, got %d", count)
	}
	count, err = RebuildEventWindows(db, "run-window")
	if err != nil {
		t.Fatal(err)
	}
	if count != 6 {
		t.Fatalf("expected idempotent rebuild to keep 6 windows, got %d", count)
	}

	result, err := ListEventWindows(db, EventWindowFilter{RunID: "run-window", WindowSeconds: 10})
	if err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion != "agentprovenance.telemetry_event_windows/v1" || result.WindowCount != 3 {
		t.Fatalf("unexpected window result: %+v", result)
	}
	var metadataWindow EventWindow
	for _, item := range result.Windows {
		if item.EventType == "metadata_ip" {
			metadataWindow = item
		}
	}
	if metadataWindow.EventCount != 1 || metadataWindow.ResolvedCount != 1 || metadataWindow.HighRiskCount != 1 {
		t.Fatalf("unexpected metadata window: %+v", metadataWindow)
	}
	var unresolved EventWindow
	for _, item := range result.Windows {
		if item.EventType == "network_connect" {
			unresolved = item
		}
	}
	if unresolved.EventCount != 1 || unresolved.UnresolvedCount != 1 {
		t.Fatalf("unexpected unresolved window: %+v", unresolved)
	}
	other, err := ListEventWindows(db, EventWindowFilter{RunID: "run-other"})
	if err != nil {
		t.Fatal(err)
	}
	if other.WindowCount != 0 {
		t.Fatalf("rebuilding run-window should not create run-other windows, got %+v", other)
	}
}

func insertWindowEvent(t *testing.T, db *sql.DB, id, runID, sessionID, toolCallID, source, eventType, method string, createdAt time.Time) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO events
		(id, run_id, session_id, tool_call_id, source, event_type, payload, correlation_method, correlation_confidence, created_at)
		VALUES (?, ?, ?, ?, ?, ?, '{}', ?, 1, ?)`,
		id, runID, sessionID, toolCallID, source, eventType, method, createdAt.Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
}
