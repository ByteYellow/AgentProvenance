package record

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecordExecutionEvidenceFailure(t *testing.T) {
	for _, phase := range []string{"graph", "start", "finish"} {
		t.Run(phase, func(t *testing.T) {
			paths, db := newPolicyTestStore(t)
			trigger := `CREATE TRIGGER fail_record_evidence BEFORE INSERT ON graph_edges BEGIN SELECT RAISE(ABORT, 'evidence unavailable'); END`
			if phase != "graph" {
				eventType := "exec_start"
				if phase == "finish" {
					eventType = "exec_end"
				}
				trigger = `CREATE TRIGGER fail_record_evidence BEFORE INSERT ON events WHEN NEW.event_type='` + eventType + `' BEGIN SELECT RAISE(ABORT, 'evidence unavailable'); END`
			}
			if _, err := db.Exec(trigger); err != nil {
				t.Fatal(err)
			}
			svc := Service{DB: db, Paths: paths, Options: Options{AllowShell: true}}
			result, err := svc.Run(Request{RunID: "failed-evidence", Command: []string{"sh", "-c", "printf done > marker"},
				DisableSnapshot: true, PostRootGraceMS: 1, Stdout: io.Discard, Stderr: io.Discard})
			if err == nil || !strings.Contains(err.Error(), "evidence unavailable") {
				t.Fatalf("lost %s evidence reported success: result=%+v err=%v", phase, result, err)
			}
			if phase == "graph" {
				if _, err := os.Stat(filepath.Join(paths.Workspaces, "failed-evidence", "marker")); !os.IsNotExist(err) {
					t.Fatalf("command started without graph: %v", err)
				}
			}
			if phase == "finish" {
				var terminal int
				if err := db.QueryRow(`SELECT COUNT(*) FROM tool_calls WHERE status='passed'`).Scan(&terminal); err != nil {
					t.Fatal(err)
				}
				if terminal != 0 {
					t.Fatal("terminal state committed without its execution evidence")
				}
			}
		})
	}
}
