package telemetry

import (
	"reflect"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/correlation"
)

func TestIngestOverlappingBindingsPreservesAmbiguity(t *testing.T) {
	for _, sameRun := range []bool{true, false} {
		db, _ := nativeTestStore(t)
		runB := "run"
		if !sameRun {
			runB = "other-run"
		}
		for _, b := range []correlation.Binding{
			{ID: "alice", RunID: "run", SessionID: "session", AttemptID: "attempt", ToolCallID: "tool-alice", ProcessID: "proc-alice", CgroupID: "cg", StartedAt: "2026-10-17T00:00:00Z"},
			{ID: "bob", RunID: runB, SessionID: "session", AttemptID: "attempt", ToolCallID: "tool-bob", ProcessID: "proc-bob", CgroupID: "cg", StartedAt: "2026-10-17T00:00:01Z"},
		} {
			if _, err := correlation.RecordBinding(db, b); err != nil {
				t.Fatal(err)
			}
		}
		id, err := IngestFiltered(db, IngestEvent{
			CgroupID: "cg", PID: 30, Source: "agentprov_ebpf", EventType: "execve",
			Timestamp: "2026-10-17T00:00:02Z", Payload: `{"argv":["python3","setup.py","install"]}`,
		})
		if err != nil {
			t.Fatal(err)
		}
		check := func() {
			t.Helper()
			report, err := BuildCorrelationReport(db, CorrelationReportOptions{EventID: id})
			if err != nil || len(report.Items) != 1 {
				t.Fatalf("report=%+v err=%v", report, err)
			}
			item := report.Items[0]
			if item.Match.Status != "ambiguous" || !item.Match.ScopeOnly || !item.Match.Ambiguous || item.Binding != nil || item.Match.BindingID != "" || item.Match.CandidateCount != 2 || !reflect.DeepEqual(item.Match.CandidateBindingIDs, []string{"alice", "bob"}) {
				t.Fatalf("lost candidate evidence: %+v", item)
			}
			wantRun := ""
			if sameRun {
				wantRun = "run"
			}
			if item.ResolvedContext.RunID != wantRun || item.ResolvedContext.ToolCallID != "" || item.ResolvedContext.ProcessID != "" {
				t.Fatalf("fabricated precise attribution: %+v", item)
			}
			if !sameRun && item.Match.Confidence != 0 {
				t.Fatalf("cross-run ambiguity has confidence: %+v", item.Match)
			}
		}
		check()
		// A later binding update must not rewrite the recorded decision into
		// a unique match when the report is opened again.
		if err := correlation.CloseBindingByID(db, "bob", "2026-10-17T00:00:01.5Z"); err != nil {
			t.Fatal(err)
		}
		check()
		var edges int
		if err := db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE edge_type IN ('runtime_tool_call_event', 'runtime_tool_call_process')`).Scan(&edges); err != nil || edges != 0 {
			t.Fatalf("ambiguous event created tool edges: %d err=%v", edges, err)
		}
	}
}

func TestCorrelationReportPreservesHistoricalMetadata(t *testing.T) {
	for _, payload := range []string{
		`{"raw":{},"correlation":{"binding_id":"historical","method":"cgroup_time_window:cgroup_id+time","confidence":0.8}}`,
		`{"attempt_id":"attempt","payload":{"raw":{},"correlation":{"binding_id":"historical","method":"cgroup_time_window:cgroup_id+time","confidence":0.8}}}`,
	} {
		event := EventRecord{CorrelationMethod: "cgroup_time_window:cgroup_id+time", CorrelationConfidence: 0.8, Payload: payload}
		match, ok := recordedCorrelation(payload)
		if !ok || match.BindingID != "historical" || correlationStatus(event) != "resolved" {
			t.Fatalf("historical attribution was reclassified: %s", payload)
		}
	}
}
