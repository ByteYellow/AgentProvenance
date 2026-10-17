package security

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/signals"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func policySnapshot(t *testing.T, db *sql.DB) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, table := range []string{"events", "sessions", "snapshots", "processes", "policy_decisions", "risk_signals", "response_actions", "signals", "graph_edges", "cost_samples"} {
		rows, err := db.Query("SELECT * FROM " + table + " ORDER BY 1")
		if err != nil {
			t.Fatal(err)
		}
		cols, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		out[table] = nil
		for rows.Next() {
			values, ptrs := make([]any, len(cols)), make([]any, len(cols))
			for i := range values {
				ptrs[i] = &values[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(values)
			if err != nil {
				t.Fatal(err)
			}
			out[table] = append(out[table], string(raw))
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func TestReevaluateRunFailureKeepsPreviousAnalysis(t *testing.T) {
	for _, stage := range []string{"policy_decisions", "risk_signals", "response_actions", "signals", "graph_edges", "cost_samples", "commit"} {
		t.Run(stage, func(t *testing.T) {
			paths, err := store.Init(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			db, err := store.Open(paths)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			db.SetMaxOpenConns(1)
			insertPolicySession(t, db)
			if _, err := db.Exec(`INSERT INTO events (id,run_id,session_id,source,event_type,payload,created_at) VALUES
				('event','run-test','sbx-test','agentprov_ebpf','metadata_ip','{"dst_ip":"169.254.169.254"}','2026-01-01T00:00:01Z'),
				('other','other-run','','agentprov_ebpf','secret_path','{"path":"/home/a/.aws/credentials"}','2026-01-01T00:00:01Z')`); err != nil {
				t.Fatal(err)
			}
			for _, run := range []string{"run-test", "other-run"} {
				if _, _, err := ReevaluateRun(db, run, DefaultEngine()); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := signals.ProjectCostSamples(db); err != nil {
				t.Fatal(err)
			}
			before := policySnapshot(t, db)
			trigger := fmt.Sprintf(`CREATE TRIGGER fail_policy BEFORE INSERT ON %s BEGIN SELECT RAISE(ABORT,'injected policy failure'); END`, stage)
			if stage == "commit" {
				for _, stmt := range []string{
					`CREATE TABLE commit_parent (id INTEGER PRIMARY KEY)`,
					`CREATE TABLE commit_child (id INTEGER REFERENCES commit_parent(id) DEFERRABLE INITIALLY DEFERRED)`,
				} {
					if _, err := db.Exec(stmt); err != nil {
						t.Fatal(err)
					}
				}
				trigger = `CREATE TRIGGER fail_policy AFTER INSERT ON cost_samples BEGIN INSERT INTO commit_child VALUES(1); END`
			}
			if _, err := db.Exec(trigger); err != nil {
				t.Fatal(err)
			}
			if evaluated, alerts, err := ReevaluateRun(db, "run-test", DefaultEngine()); err == nil || evaluated != 0 || alerts != 0 {
				t.Fatalf("failure reported success: %d %d %v", evaluated, alerts, err)
			}
			if after := policySnapshot(t, db); !reflect.DeepEqual(before, after) {
				t.Fatal("failed reanalysis changed previous evidence or session state")
			}
			if _, err := db.Exec(`DROP TRIGGER fail_policy`); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				if evaluated, alerts, err := ReevaluateRun(db, "run-test", DefaultEngine()); err != nil || evaluated != 1 || alerts != 1 {
					t.Fatalf("retry: %d %d %v", evaluated, alerts, err)
				}
				if _, err := signals.ProjectCostSamples(db); err != nil {
					t.Fatal(err)
				}
				for table, old := range before {
					var n int
					if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil || n != len(old) {
						t.Fatalf("retry duplicated %s: %d, want %d (%v)", table, n, len(old), err)
					}
				}
			}
		})
	}
}

func TestReevaluateDetectOnlyCountersAreIdempotent(t *testing.T) {
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, stmt := range []string{
		`INSERT INTO events (id,run_id,source,event_type,payload,created_at) VALUES ('event','run','agentprov_ebpf','secret_path','{}','now')`,
		`INSERT INTO cost_samples (id,run_id,session_id,created_at) VALUES ('unowned','run','','now')`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	engine := Engine{Rules: []Rule{{ID: "audit", Mode: "detect", Decision: "kill", Match: RuleMatch{EventType: "secret_path"}}}}
	for i := 0; i < 3; i++ {
		if _, alerts, err := ReevaluateRun(db, "run", engine); err != nil || alerts != 1 {
			t.Fatalf("replay: alerts=%d %v", alerts, err)
		}
		if _, err := signals.ProjectCostSamples(db); err != nil {
			t.Fatal(err)
		}
		var costs, sigs, blocks int
		if err := db.QueryRow(`SELECT COUNT(*),SUM(policy_block_count + quarantine_count) FROM cost_samples`).Scan(&costs, &blocks); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(`SELECT COUNT(*) FROM signals WHERE source_table='cost_samples'`).Scan(&sigs); err != nil {
			t.Fatal(err)
		}
		if costs != 2 || sigs != 2 || blocks != 0 {
			t.Fatalf("detect-only counters accumulated: costs=%d signals=%d blocks=%d", costs, sigs, blocks)
		}
	}
}
