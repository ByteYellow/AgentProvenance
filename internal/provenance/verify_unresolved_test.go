package provenance

import (
	"path/filepath"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestVerifyBindingsDoesNotInventUnresolvedContext(t *testing.T) {
	paths, err := store.Init(filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	id, err := telemetry.IngestFiltered(db, telemetry.IngestEvent{
		RunID: "run", Source: "filtered_telemetry", EventType: "execve", Payload: `{"argv":["fixture"]}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method     string
		confidence float64
		missing    bool
	}{
		{"", 0, false}, {"unresolved", 0, false}, {"ambiguous_binding", 0, false},
		{"pid_time_window", 0.8, true}, {"process_instance_id", 1, true},
	} {
		if _, err := db.Exec(`UPDATE events SET correlation_method=?, correlation_confidence=? WHERE id=?`, tc.method, tc.confidence, id); err != nil {
			t.Fatal(err)
		}
		missing := false
		err := verifyExecutionContextBindings(db, "run", func(severity, kind, id, format string, args ...any) {
			if kind == "missing_execution_context_binding" {
				missing = true
			}
		})
		if err != nil || missing != tc.missing {
			t.Fatalf("method=%q confidence=%g: missing=%v err=%v", tc.method, tc.confidence, missing, err)
		}
	}
}
