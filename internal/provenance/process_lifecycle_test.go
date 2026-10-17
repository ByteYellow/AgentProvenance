package provenance

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

const graphBoot = "01234567-89ab-cdef-0123-456789abcdef"

func ingestGraphProcess(t *testing.T, db *sql.DB, kind, instance, parent, command, at string) string {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{
		"command": command, "argv": []string{command}, "comm": command,
		"process_instance_id": instance, "parent_process_instance_id": parent,
		"path": "/home/test/.aws/credentials", "dst_ip": "169.254.169.254",
	})
	id, err := telemetry.IngestFiltered(db, telemetry.IngestEvent{
		RunID: "run-lifecycle", Source: "agentprov_ebpf", EventType: kind,
		PID: 42, PPID: 1, TGID: 42, Payload: string(payload), Timestamp: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestRuntimeGraphPreservesProcessLifetimes(t *testing.T) {
	db := newLensTestDB(t)
	db.SetMaxOpenConns(1)
	otherBoot := "11234567-89ab-cdef-0123-456789abcdef"
	instances := []string{graphBoot + ":42:100", graphBoot + ":42:200", otherBoot + ":42:100"}
	parents := []string{graphBoot + ":1:10", graphBoot + ":1:10", otherBoot + ":1:10"}
	for i, instance := range instances {
		command := fmt.Sprintf("worker-%d", i)
		id := ingestGraphProcess(t, db, "execve", instance, parents[i], command, fmt.Sprintf("2026-10-17T00:00:0%dZ", i))
		var node string
		if err := db.QueryRow(`SELECT from_id FROM graph_edges WHERE to_id=? AND edge_type='runtime_process_event'`, "runtime_event/"+id).Scan(&node); err != nil {
			t.Fatal(err)
		}
		if node != "runtime_process/instance/"+instance {
			t.Errorf("process %s collapsed into %s", instance, node)
		}
	}
	// More events in the same lifetime keep its ID.
	ingestGraphProcess(t, db, "file_open", instances[0], parents[0], "file-event-comm", "2026-10-17T00:00:04Z")
	nodes, _, err := graphLensNodes(db, "run-lifecycle")
	if err != nil {
		t.Fatal(err)
	}
	for i, instance := range instances {
		node := nodes["runtime_process/instance/"+instance]
		if node.Label != fmt.Sprintf("worker-%d", i) || node.Data["process_instance_id"] != instance {
			t.Errorf("lifetime label or identity lost: %+v", node)
		}
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE from_id=? AND to_id=? AND edge_type='runtime_process_parent'`, "runtime_process/instance/"+parents[i], "runtime_process/instance/"+instance).Scan(&count); err != nil || count == 0 {
			t.Errorf("parent lifetime missing: count=%d err=%v", count, err)
		}
	}
	if err := verifyRuntimeCausality(db, "run-lifecycle", func(severity, kind, id, format string, args ...any) {
		t.Errorf("verify %s %s: %s", kind, id, fmt.Sprintf(format, args...))
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeGraphVerifyUsesSourceEventIdentity(t *testing.T) {
	db := newLensTestDB(t)
	parent, child := graphBoot+":1:10", graphBoot+":42:100"
	first := ingestGraphProcess(t, db, "execve", child, parent, "worker", "2026-10-17T00:00:00Z")
	ingestGraphProcess(t, db, "file_open", child, parent, "worker", "2026-10-17T00:00:01Z")
	if _, err := db.Exec(`DELETE FROM graph_edges WHERE source_event_id=? AND edge_type='runtime_process_parent'`, first); err != nil {
		t.Fatal(err)
	}
	found := false
	if err := verifyRuntimeCausality(db, "run-lifecycle", func(severity, kind, id, format string, args ...any) {
		if kind == "missing_runtime_process_parent_edge" && id == first {
			found = true
		}
	}); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("another event's edge hid the missing parent evidence")
	}
}

func TestRuntimeGraphThreadIdentitySurvivesCgroupMove(t *testing.T) {
	db := newLensTestDB(t)
	for i, cg := range []string{"before", "after"} {
		payload, _ := json.Marshal(map[string]any{
			"process_instance_id": graphBoot + ":42:200", "parent_process_instance_id": graphBoot + ":1:10",
			"thread_group_instance_id": graphBoot + ":40:100", "argv": []string{"worker"},
		})
		id, err := telemetry.IngestFiltered(db, telemetry.IngestEvent{RunID: "run-thread", Source: "agentprov_ebpf", EventType: "execve", PID: 42, PPID: 1, TGID: 40, CgroupID: cg, Payload: string(payload), Timestamp: fmt.Sprintf("2026-10-17T00:00:0%dZ", i)})
		if err != nil {
			t.Fatal(err)
		}
		var from, to string
		if err := db.QueryRow(`SELECT from_id,to_id FROM graph_edges WHERE source_event_id=? AND edge_type='runtime_process_thread'`, id).Scan(&from, &to); err != nil {
			t.Fatal(err)
		}
		if from != "runtime_process/instance/"+graphBoot+":40:100" || to != "runtime_process/instance/"+graphBoot+":42:200" {
			t.Fatalf("thread changed with cgroup %s: %s -> %s", cg, from, to)
		}
	}
	if err := verifyRuntimeCausality(db, "run-thread", func(severity, kind, id, format string, args ...any) {
		t.Errorf("%s %s: %s", kind, id, fmt.Sprintf(format, args...))
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeGraphUnknownLifetimesDoNotMerge(t *testing.T) {
	db := newLensTestDB(t)
	seen := map[string]bool{}
	for i, instance := range []string{"", "", graphBoot + ":99:100", graphBoot + ":42:0"} {
		id := ingestGraphProcess(t, db, "execve", instance, "", "unknown", fmt.Sprintf("2026-10-17T00:00:0%dZ", i))
		var node string
		if err := db.QueryRow(`SELECT from_id FROM graph_edges WHERE to_id=? AND edge_type='runtime_process_event'`, "runtime_event/"+id).Scan(&node); err != nil {
			t.Fatal(err)
		}
		if seen[node] || node != "runtime_process/observation/"+id+"/pid" {
			t.Errorf("unknown lifetime grouped as %s", node)
		}
		seen[node] = true
	}
}

func TestRuntimeGraphDataFlowRejectsReusedPID(t *testing.T) {
	for _, tc := range []struct {
		name, sink string
		want       int
	}{
		{"same lifetime", graphBoot + ":42:100", 1},
		{"PID reuse", graphBoot + ":42:200", 0},
		{"other boot", "11234567-89ab-cdef-0123-456789abcdef:42:100", 0},
		{"missing lifetime", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newLensTestDB(t)
			ingestGraphProcess(t, db, "secret_path", graphBoot+":42:100", "", "reader", "2026-10-17T00:00:00Z")
			ingestGraphProcess(t, db, "metadata_ip", tc.sink, "", "sender", "2026-10-17T00:00:01Z")
			for _, detail := range []string{"summary", "raw"} {
				lens, err := BuildGraphLens(db, GraphLensOptions{RunID: "run-lifecycle", Lens: "data-flow-taint", Detail: detail})
				if err != nil || len(lens.DerivedEdges) != tc.want {
					t.Errorf("%s flows=%+v err=%v", detail, lens.DerivedEdges, err)
				}
			}
		})
	}
}
