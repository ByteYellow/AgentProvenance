package record

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestRecordPreparationRollsBackBeforeWorkloadLaunch(t *testing.T) {
	for _, blocked := range []string{"leases", "processes", "graph_edges"} {
		t.Run(blocked, func(t *testing.T) {
			root := t.TempDir()
			paths, err := store.Init(filepath.Join(root, "store"))
			if err != nil {
				t.Fatal(err)
			}
			db, err := store.Open(paths)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec("CREATE TRIGGER reject_preparation BEFORE INSERT ON " + blocked + " BEGIN SELECT RAISE(ABORT, 'fixture rejected preparation'); END"); err != nil {
				t.Fatal(err)
			}
			work := filepath.Join(root, "workspace")
			if err := os.Mkdir(work, 0700); err != nil {
				t.Fatal(err)
			}
			_, err = policyFixtureService(db, paths).Run(Request{RunID: "atomic-preparation", Workdir: work,
				Command: []string{"sh", "-c", "printf started > launched"}, DisableSnapshot: true})
			if err == nil || !strings.Contains(err.Error(), "fixture rejected preparation") {
				t.Fatalf("preparation failure: %v", err)
			}
			if _, err := os.Stat(filepath.Join(work, "launched")); !os.IsNotExist(err) {
				t.Fatalf("workload ran before preparation committed: %v", err)
			}
			for _, table := range []string{"snapshots", "leases", "sessions", "rollouts", "fork_attempts", "tool_calls", "processes", "graph_edges"} {
				var n int
				if err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil || n != 0 {
					t.Fatalf("partial %s records: count=%d err=%v", table, n, err)
				}
			}
		})
	}
}
