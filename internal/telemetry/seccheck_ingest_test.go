package telemetry

import (
	"encoding/json"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/correlation"
)

func TestSecCheckNeverBorrowsOrClosesHostPIDBinding(t *testing.T) {
	db, _ := nativeTestStore(t)
	_, err := correlation.RecordBinding(db, correlation.Binding{
		RunID: "shared-run", SessionID: "host-session", ToolCallID: "host-call", ProcessID: "host-process",
		PID: 42, StartedAt: "2026-11-14T00:00:00Z", BindingSource: "control_exec",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Sentry and the host can use the same PID even within the same Run.
	for _, kind := range []string{"process_observed", "process_exit"} {
		payload, _ := json.Marshal(map[string]any{"pid": 42, "exit_code": 0})
		id, err := IngestFiltered(db, IngestEvent{
			RunID: "shared-run", PID: 42, TGID: 42, Timestamp: "2026-11-14T00:00:01Z",
			Source: "gvisor_seccheck", EventType: kind, Payload: string(payload),
		})
		if err != nil {
			t.Fatal(err)
		}
		var session, call, process, method string
		if err := db.QueryRow(`SELECT session_id,tool_call_id,process_id,correlation_method FROM events WHERE id=?`, id).Scan(&session, &call, &process, &method); err != nil {
			t.Fatal(err)
		}
		if session != "" || call != "" || process != "" || method != "runtime_scope" {
			t.Errorf("Sentry observation borrowed host context: %q %q %q %q", session, call, process, method)
		}
	}
	var ended string
	if err := db.QueryRow(`SELECT ended_at FROM execution_context_bindings WHERE tool_call_id='host-call'`).Scan(&ended); err != nil {
		t.Fatal(err)
	}
	if ended != "" {
		t.Errorf("Sentry exit closed host binding: %q", ended)
	}
}
