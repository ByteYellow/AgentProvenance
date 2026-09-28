package hooksbridge

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func correlationTime(sec int) string {
	return time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC).Add(time.Duration(sec) * time.Second).Format(time.RFC3339Nano)
}

func correlationTool(t *testing.T, db *sql.DB, id, command string, start, end int) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO tool_calls (id,run_id,agent_id,command,started_at,ended_at,status,created_at) VALUES (?,'run',?,?,?,?,'completed','2026-09-28T00:00:00Z')`,
		id, "agent-"+id, command, correlationTime(start), correlationTime(end))
	if err != nil {
		t.Fatal(err)
	}
}

func correlationRuntime(t *testing.T, db *sql.DB, id, typ, command string, pid, ppid int64, sec int) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"payload": map[string]any{"raw": map[string]any{"command": command, "node_name": "node-a"}}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO events (id,run_id,source,event_type,cgroup_id,container_id,pid,ppid,payload,created_at)
		VALUES (?,'run','agentprov_ebpf',?,'cg-a','container-a',?,?,?,?)`, id, typ, pid, ppid, string(raw), correlationTime(sec))
	if err != nil {
		t.Fatal(err)
	}
}

func correlationLinks(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	rows, err := db.Query(`SELECT from_id,to_id FROM graph_edges WHERE run_id='run' AND edge_type='agent_syscall'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var from, to string
		if err := rows.Scan(&from, &to); err != nil {
			t.Fatal(err)
		}
		out[strings.TrimPrefix(to, "runtime_event/")] = from
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCorrelationConcurrentCommandIsAmbiguous(t *testing.T) {
	db, _ := openTestStore(t)
	correlationTool(t, db, "a", "python task.py", 0, 10)
	correlationTool(t, db, "b", "python task.py", 1, 10)
	correlationRuntime(t, db, "exec", "execve", "python task.py", 100, 1, 2)
	correlationRuntime(t, db, "write", "file_write", "", 100, 1, 3)
	r, err := CorrelateSyscallsWithReport(db, "run")
	if err != nil || r.Status != "ambiguous" || r.AmbiguousExecs != 1 || r.Edges != 0 {
		t.Fatalf("ambiguous command was attributed: %+v, %v", r, err)
	}
}

func TestCorrelationRetriesAndProcessLifetimes(t *testing.T) {
	db, _ := openTestStore(t)
	db.SetMaxOpenConns(1) // Readers must close before the next query/transaction.
	correlationTool(t, db, "a", "python task.py", 0, 10)
	correlationTool(t, db, "b", "python task.py", 20, 30)
	correlationRuntime(t, db, "before", "file_write", "", 100, 1, 1)
	correlationRuntime(t, db, "exec-a", "execve", "python task.py", 100, 1, 2)
	correlationRuntime(t, db, "write-a", "file_write", "", 100, 1, 3)
	correlationRuntime(t, db, "exit-a", "process_exit", "", 100, 1, 4)
	correlationRuntime(t, db, "after-exit", "file_write", "", 100, 1, 5)
	correlationRuntime(t, db, "exec-b", "execve", "python task.py", 100, 1, 22)
	correlationRuntime(t, db, "write-b", "file_write", "", 100, 1, 23)
	correlationRuntime(t, db, "unrelated-exec", "execve", "unrelated", 100, 1, 24)
	correlationRuntime(t, db, "after-reexec", "file_write", "", 100, 1, 25)
	correlationRuntime(t, db, "late-child", "execve", "child", 101, 100, 35)
	for i := 0; i < 2; i++ {
		r, err := CorrelateSyscallsWithReport(db, "run")
		if err != nil || r.Edges != 4 {
			t.Fatalf("pass %d: %+v, %v", i, r, err)
		}
		want := map[string]string{"exec-a": "a", "write-a": "a", "exec-b": "b", "write-b": "b"}
		if got := correlationLinks(t, db); !reflect.DeepEqual(got, want) {
			t.Fatalf("process lifetime mismatch: %v", got)
		}
	}
}

func TestCorrelationDescendantsRespectScopeAndTime(t *testing.T) {
	db, _ := openTestStore(t)
	correlationTool(t, db, "a", "sh -c task", 0, 10)
	correlationRuntime(t, db, "root", "execve", "sh -c task", 100, 1, 1)
	correlationRuntime(t, db, "child", "execve", "python helper.py", 101, 100, 2)
	correlationRuntime(t, db, "write", "file_write", "", 101, 100, 3)
	correlationRuntime(t, db, "grandchild", "execve", "curl local", 102, 101, 4)
	correlationRuntime(t, db, "network", "network_connect", "", 102, 101, 5)
	correlationRuntime(t, db, "exit-root", "process_exit", "", 100, 1, 6)
	correlationRuntime(t, db, "child-after-parent-exit", "execve", "other", 103, 100, 7)
	correlationRuntime(t, db, "late-write", "file_write", "", 101, 100, 11)
	for i, column := range []string{"cgroup_id", "container_id", "source"} {
		id := "other-" + column
		correlationRuntime(t, db, id, "file_write", "", 101, 100, 3+i)
		value := "different"
		if column == "source" {
			value = "tetragon_jsonl"
		}
		if _, err := db.Exec("UPDATE events SET "+column+"=? WHERE id=?", value, id); err != nil {
			t.Fatal(err)
		}
	}
	correlationRuntime(t, db, "other-node", "file_write", "", 101, 100, 3)
	if _, err := db.Exec(`UPDATE events SET payload='{"node_name":"node-b"}' WHERE id='other-node'`); err != nil {
		t.Fatal(err)
	}
	r, err := CorrelateSyscallsWithReport(db, "run")
	if err != nil || r.Edges != 5 || r.InheritedExecs != 2 {
		t.Fatalf("descendants: %+v, %v", r, err)
	}
	for event, wantAnchor := range map[string]string{"child": "root", "write": "child", "grandchild": "child", "network": "grandchild"} {
		var anchor string
		if err := db.QueryRow(`SELECT source_event_id FROM graph_edges WHERE run_id='run' AND edge_type='agent_syscall' AND to_id=?`, "runtime_event/"+event).Scan(&anchor); err != nil || anchor != wantAnchor {
			t.Fatalf("lost lineage anchor for %s: %q, %v", event, anchor, err)
		}
	}
	for event := range correlationLinks(t, db) {
		if strings.HasPrefix(event, "other-") || strings.Contains(event, "after-parent") || strings.HasPrefix(event, "late-") {
			t.Fatalf("crossed process boundary: %s", event)
		}
	}
}

func TestCorrelationRejectsUncertainLifecycle(t *testing.T) {
	for _, tc := range []struct{ name, query string }{
		{"unknown_scope", `UPDATE events SET cgroup_id='',container_id='' WHERE id='boundary'`},
		{"invalid_time", `UPDATE events SET created_at='bad' WHERE id='boundary'`},
		{"invalid_payload", `UPDATE events SET payload='{' WHERE id='boundary'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, _ := openTestStore(t)
			correlationTool(t, db, "a", "python task.py", 0, 10)
			correlationRuntime(t, db, "exec", "execve", "python task.py", 100, 1, 1)
			correlationRuntime(t, db, "boundary", "process_exit", "", 100, 1, 2)
			correlationRuntime(t, db, "write", "file_write", "", 100, 1, 3)
			if _, err := db.Exec(tc.query); err != nil {
				t.Fatal(err)
			}
			r, err := CorrelateSyscallsWithReport(db, "run")
			if err != nil || r.Edges != 0 || r.Status != "partial" {
				t.Fatalf("uncertain lifecycle: %+v, %v", r, err)
			}
		})
	}
}

func TestCorrelationSameInstantCannotProveOrder(t *testing.T) {
	db, _ := openTestStore(t)
	correlationTool(t, db, "a", "python task.py", 0, 10)
	correlationRuntime(t, db, "exec", "execve", "python task.py", 100, 1, 1)
	correlationRuntime(t, db, "equal-write", "file_write", "", 100, 1, 1)
	correlationRuntime(t, db, "equal-child", "execve", "helper", 101, 100, 1)
	r, err := CorrelateSyscallsWithReport(db, "run")
	if err != nil || r.Edges != 1 {
		t.Fatalf("same-instant ordering guessed: %+v, %v", r, err)
	}
	correlationRuntime(t, db, "conflicting-cgroup", "execve", "python task.py", 100, 1, 1)
	if _, err := db.Exec(`UPDATE events SET cgroup_id='cg-b' WHERE id='conflicting-cgroup'`); err != nil {
		t.Fatal(err)
	}
	r, err = CorrelateSyscallsWithReport(db, "run")
	if err != nil || r.Edges != 0 || r.AmbiguousExecs != 2 {
		t.Fatalf("tied execs across cgroups guessed an order: %+v %v", r, err)
	}
}

func TestCorrelationReexecAcrossCgroupsInvalidatesOldOwner(t *testing.T) {
	db, _ := openTestStore(t)
	correlationTool(t, db, "a", "python task.py", 0, 10)
	correlationRuntime(t, db, "exec", "execve", "python task.py", 100, 1, 1)
	correlationRuntime(t, db, "reused", "execve", "unrelated", 100, 1, 2)
	correlationRuntime(t, db, "returns-to-old-cgroup", "file_write", "", 100, 1, 3)
	if _, err := db.Exec(`UPDATE events SET cgroup_id='cg-b' WHERE id='reused'`); err != nil {
		t.Fatal(err)
	}
	r, err := CorrelateSyscallsWithReport(db, "run")
	if err != nil || r.Edges != 1 {
		t.Fatalf("old cgroup retained stale PID owner: %+v, %v", r, err)
	}
}

func TestCorrelationParentAndCommandDisagreementIsAmbiguous(t *testing.T) {
	db, _ := openTestStore(t)
	correlationTool(t, db, "a", "python task.py", 0, 10)
	correlationTool(t, db, "b", "curl local", 0, 10)
	correlationRuntime(t, db, "parent", "execve", "python task.py", 100, 1, 1)
	correlationRuntime(t, db, "child", "execve", "curl local", 101, 100, 2)
	correlationRuntime(t, db, "network", "network_connect", "", 101, 100, 3)
	r, err := CorrelateSyscallsWithReport(db, "run")
	if err != nil || r.Edges != 1 || r.AmbiguousExecs != 1 {
		t.Fatalf("conflicting evidence chose a candidate: %+v, %v", r, err)
	}
}

func TestCorrelationComparesInstantsNotTimestampStrings(t *testing.T) {
	db, _ := openTestStore(t)
	correlationTool(t, db, "a", "python task.py", 0, 10)
	correlationRuntime(t, db, "exec", "execve", "python task.py", 100, 1, 1)
	correlationRuntime(t, db, "write", "file_write", "", 100, 1, 2)
	if _, err := db.Exec(`UPDATE events SET created_at='2026-09-28T08:00:01+08:00' WHERE id='exec'`); err != nil {
		t.Fatal(err)
	}
	r, err := CorrelateSyscallsWithReport(db, "run")
	if err != nil || r.Edges != 2 {
		t.Fatalf("timezone changed association: %+v, %v", r, err)
	}
}

func TestCorrelationRollbackKeepsPublishedEdges(t *testing.T) {
	for _, failure := range []string{"insert", "delete", "read"} {
		t.Run(failure, func(t *testing.T) {
			db, _ := openTestStore(t)
			correlationTool(t, db, "a", "python task.py", 0, 10)
			correlationRuntime(t, db, "exec", "execve", "python task.py", 100, 1, 1)
			if _, err := CorrelateSyscallsWithReport(db, "run"); err != nil {
				t.Fatal(err)
			}
			before := correlationLinks(t, db)
			var query string
			if failure == "read" {
				query = `ALTER TABLE tool_calls RENAME TO unavailable_calls`
			} else {
				query = fmt.Sprintf(`CREATE TRIGGER fail_correlation BEFORE %s ON graph_edges BEGIN SELECT RAISE(ABORT,'simulated write failure'); END`, failure)
			}
			if _, err := db.Exec(query); err != nil {
				t.Fatal(err)
			}
			r, err := CorrelateSyscallsWithReport(db, "run")
			if err == nil || r.Status != "failed" || r.Edges != 0 {
				t.Fatalf("failure hidden: %+v, %v", r, err)
			}
			if got := correlationLinks(t, db); !reflect.DeepEqual(got, before) {
				t.Fatalf("failure damaged prior graph: %v != %v", got, before)
			}
		})
	}
}

func TestCorrelationInputLimitsAndUnknownClock(t *testing.T) {
	db, _ := openTestStore(t)
	correlationTool(t, db, "a", "python task.py", 0, 10)
	correlationRuntime(t, db, "exec", "execve", "python task.py", 100, 1, 1)
	if _, err := db.Exec(`UPDATE tool_calls SET started_at=''`); err != nil {
		t.Fatal(err)
	}
	r, err := CorrelateSyscallsWithReport(db, "run")
	if err != nil || r.Edges != 0 || r.UnclockedCalls != 1 {
		t.Fatalf("unknown tool clock guessed: %+v, %v", r, err)
	}
	if _, err := db.Exec(`UPDATE events SET payload=?`, strings.Repeat(" ", 65537)); err != nil {
		t.Fatal(err)
	}
	if r, err := CorrelateSyscallsWithReport(db, "run"); err == nil || r.Status != "failed" {
		t.Fatalf("payload limit ignored: %+v, %v", r, err)
	}
}

func TestCorrelationMissingToolEndDoesNotInventWindow(t *testing.T) {
	db, _ := openTestStore(t)
	correlationTool(t, db, "a", "python task.py", 0, 10)
	correlationRuntime(t, db, "exec", "execve", "python task.py", 100, 1, 1)
	if _, err := db.Exec(`UPDATE tool_calls SET ended_at=''`); err != nil {
		t.Fatal(err)
	}
	r, err := CorrelateSyscallsWithReport(db, "run")
	if err != nil || r.Edges != 0 || r.UnclockedCalls != 1 || r.Status != "partial" {
		t.Fatalf("invented a tool-end interval: %+v %v", r, err)
	}
}

func TestCommandMatchingIsLiteral(t *testing.T) {
	for _, tc := range []struct {
		actual, requested string
		truncated, want   bool
	}{
		{"python task.py", "python task.py", false, true},
		{"/bin/bash -lc python task.py", "python task.py", false, true},
		{"sh -c task", "sh -c task", false, true},
		{"echo python task.py", "python task.py", false, false},
		{"python Task.py", "python task.py", false, false},
		{"echo 'a  b'", "echo 'a b'", false, false},
		{"python task.py", "python task.py extra", false, false},
		{"python task.py", "python task.py extra", true, true},
		{"python", "python task.py", true, false},
	} {
		if got := commandMatches(tc.actual, tc.requested, tc.truncated); got != tc.want {
			t.Errorf("match(%q,%q,%t)=%t, want %t", tc.actual, tc.requested, tc.truncated, got, tc.want)
		}
	}
}
