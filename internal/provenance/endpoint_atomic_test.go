package provenance

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/signals"
)

func endpointAtomicFixture(t *testing.T) (ObjectStore, *sql.DB, string) {
	t.Helper()
	st, db := intentTestStore(t)
	db.SetMaxOpenConns(1)
	dump := t.TempDir()
	for _, f := range []struct{ name, meta, body string }{
		{"01", `{"seq":1,"kind":"req","path":"/v1/chat/completions"}`, `{"messages":[{"role":"user","content":"summarize"}]}`},
		{"02", `{"seq":2,"kind":"resp","path":"/v1/chat/completions"}`, `{"choices":[{"message":{"content":"done"}}]}`},
		{"03", `{"seq":3,"kind":"EXFIL-REQ","path":"/storage","canary_hits":["CANARY"]}`, `{"files":[{"path":"/work/secret","content":"CANARY"}]}`},
	} {
		mustWrite(t, filepath.Join(dump, f.name+".meta.json"), f.meta)
		mustWrite(t, filepath.Join(dump, f.name+".body.bin"), f.body)
	}
	if _, err := db.Exec(`INSERT INTO events (id,run_id,source,event_type,payload,created_at) VALUES
		('raw-secret','intent-test','sensor','secret_path','{"path":"/work/secret"}','2026-01-01T00:00:00Z'),
		('other-event','other-run','endpoint_capture','network_connect','{}','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PutExternalObject(ExternalObjectInput{Type: "llm_message", RunID: "intent-test", SourceID: "transcript/keep", Payload: map[string]any{"content": "keep"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := IngestEndpointDump(st, db, "intent-test", dump); err != nil {
		t.Fatal(err)
	}
	return st, db, dump
}

func endpointSnapshot(t *testing.T, db *sql.DB) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, table := range []string{"provenance_objects", "events", "graph_edges", "policy_decisions", "risk_signals", "response_actions", "signals", "cost_samples"} {
		rows, err := db.Query("SELECT * FROM " + table + " ORDER BY 1")
		if err != nil {
			t.Fatal(err)
		}
		cols, err := rows.Columns()
		if err != nil {
			rows.Close()
			t.Fatal(err)
		}
		out[table] = nil
		for rows.Next() {
			values, ptrs := make([]any, len(cols)), make([]any, len(cols))
			for i := range values {
				ptrs[i] = &values[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				rows.Close()
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

func TestEndpointReanalysisRollsBackEveryProjection(t *testing.T) {
	for i, stage := range []struct{ table, operation, condition string }{
		{"provenance_objects", "DELETE", "OLD.source_id LIKE 'endpoint/%'"},
		{"provenance_objects", "INSERT", "NEW.source_id LIKE 'endpoint/%'"},
		{"events", "INSERT", "NEW.source='endpoint_capture'"},
		{"graph_edges", "INSERT", "NEW.edge_type='llm_response'"},
		{"graph_edges", "INSERT", "NEW.edge_type='risk_signal_response_action'"},
		{"policy_decisions", "INSERT", "1"},
		{"risk_signals", "INSERT", "1"},
		{"response_actions", "INSERT", "1"},
		{"signals", "INSERT", "NEW.dimension='security'"},
		{"cost_samples", "INSERT", "1"},
	} {
		t.Run(fmt.Sprintf("%02d_%s_%s", i, stage.table, stage.operation), func(t *testing.T) {
			st, db, dump := endpointAtomicFixture(t)
			before := endpointSnapshot(t, db)
			if _, err := db.Exec("CREATE TRIGGER fail_endpoint BEFORE " + stage.operation + " ON " + stage.table + " WHEN " + stage.condition + " BEGIN SELECT RAISE(ABORT,'injected endpoint failure'); END"); err != nil {
				t.Fatal(err)
			}
			res, err := IngestEndpointDump(st, db, "intent-test", dump)
			if err == nil || !strings.Contains(err.Error(), "injected endpoint failure") {
				t.Fatalf("failure was not returned: %+v %v", res, err)
			}
			if res != (EndpointResult{}) {
				t.Fatalf("rolled-back writes counted as saved: %+v", res)
			}
			if after := endpointSnapshot(t, db); !reflect.DeepEqual(before, after) {
				t.Fatal("failed reanalysis changed previously saved evidence")
			}
			if _, err := BuildGraphLens(db, GraphLensOptions{RunID: "intent-test", Lens: "data-flow-taint", Limit: 100}); err != nil {
				t.Fatalf("old graph is unreadable: %v", err)
			}
			if _, err := db.Exec("DROP TRIGGER fail_endpoint"); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				res, err := IngestEndpointDump(st, db, "intent-test", dump)
				if err != nil || res != (EndpointResult{LLMCalls: 1, Egress: 1, BlockedEgress: 1}) {
					t.Fatalf("retry: %+v %v", res, err)
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

func TestEndpointInvalidInputKeepsLastGraph(t *testing.T) {
	for _, name := range []string{"missing directory", "empty directory", "invalid metadata", "null metadata", "missing request", "missing response", "missing upload"} {
		t.Run(name, func(t *testing.T) {
			st, db, dump := endpointAtomicFixture(t)
			before := endpointSnapshot(t, db)
			switch name {
			case "missing directory":
				dump = filepath.Join(dump, "missing")
			case "empty directory":
				dump = t.TempDir()
			case "invalid metadata":
				mustWrite(t, filepath.Join(dump, "04.meta.json"), "{")
			case "null metadata":
				mustWrite(t, filepath.Join(dump, "04.meta.json"), "null")
			default:
				file := map[string]string{"missing request": "01", "missing response": "02", "missing upload": "03"}[name]
				if err := os.Remove(filepath.Join(dump, file+".body.bin")); err != nil {
					t.Fatal(err)
				}
			}
			res, err := IngestEndpointDump(st, db, "intent-test", dump)
			if err == nil || res != (EndpointResult{}) {
				t.Fatalf("expected input error and no saved results: %+v %v", res, err)
			}
			if after := endpointSnapshot(t, db); !reflect.DeepEqual(before, after) {
				t.Fatal("unreadable input replaced old graph")
			}
		})
	}
}

func TestEndpointCommitFailureKeepsLastGraph(t *testing.T) {
	st, db, dump := endpointAtomicFixture(t)
	before := endpointSnapshot(t, db)
	for _, stmt := range []string{
		`CREATE TABLE commit_parent (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE commit_child (id INTEGER REFERENCES commit_parent(id) DEFERRABLE INITIALLY DEFERRED)`,
		`CREATE TRIGGER fail_commit AFTER INSERT ON cost_samples BEGIN INSERT INTO commit_child VALUES(1); END`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	res, err := IngestEndpointDump(st, db, "intent-test", dump)
	if err == nil || res != (EndpointResult{}) {
		t.Fatalf("expected commit failure: %+v %v", res, err)
	}
	if after := endpointSnapshot(t, db); !reflect.DeepEqual(before, after) {
		t.Fatal("failed commit replaced old graph")
	}
	if _, err := db.Exec(`DROP TRIGGER fail_commit`); err != nil {
		t.Fatal(err)
	}
	if _, err := IngestEndpointDump(st, db, "intent-test", dump); err != nil {
		t.Fatalf("retry after failed commit: %v", err)
	}
}

func TestEndpointObjectWriteFailureKeepsLastGraph(t *testing.T) {
	st, db, dump := endpointAtomicFixture(t)
	before := endpointSnapshot(t, db)
	var path string
	if err := db.QueryRow(`SELECT path FROM provenance_objects WHERE source_id='endpoint/req-1'`).Scan(&path); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Redirect only this failed attempt to an unwritable object root.
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	mustWrite(t, blocked, "file")
	st.Paths.Provenance = blocked
	res, err := IngestEndpointDump(st, db, "intent-test", dump)
	if err == nil || res != (EndpointResult{}) {
		t.Fatalf("expected object write failure: %+v %v", res, err)
	}
	if after := endpointSnapshot(t, db); !reflect.DeepEqual(before, after) {
		t.Fatal("object write failure replaced old graph")
	}
	if saved, err := os.ReadFile(path); err != nil || string(saved) != string(original) {
		t.Fatalf("old object changed: %v", err)
	}
}

func TestEndpointUnpairedRequestRemainsReadable(t *testing.T) {
	st, db, dump := endpointAtomicFixture(t)
	if err := os.Remove(filepath.Join(dump, "02.meta.json")); err != nil {
		t.Fatal(err)
	}
	res, err := IngestEndpointDump(st, db, "intent-test", dump)
	if err != nil || res.LLMCalls != 1 {
		t.Fatalf("request without a captured response: %+v %v", res, err)
	}
}

func TestEndpointRetryReplacesOnlyOwnedCostProjections(t *testing.T) {
	st, db, dump := endpointAtomicFixture(t)
	var costID string
	if err := db.QueryRow(`SELECT id FROM cost_samples WHERE id LIKE 'cost-policy-%'`).Scan(&costID); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{costID, "legacy-cost"} {
		if id == "legacy-cost" {
			if _, err := db.Exec(`INSERT INTO cost_samples (id,run_id,created_at) VALUES (?,'intent-test','2026-01-01T00:00:00Z')`, id); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := signals.Record(db, signals.Signal{RunID: "intent-test", Dimension: signals.Cost, Type: "usage", SourceTable: "cost_samples", SourceID: id}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := IngestEndpointDump(st, db, "intent-test", dump); err != nil {
		t.Fatal(err)
	}
	var legacy, stale int
	if err := db.QueryRow(`SELECT COUNT(*) FROM cost_samples WHERE id='legacy-cost'`).Scan(&legacy); err != nil || legacy != 1 {
		t.Fatalf("legacy cost removed: %d %v", legacy, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM signals WHERE source_table='cost_samples' AND source_id='legacy-cost'`).Scan(&legacy); err != nil || legacy != 1 {
		t.Fatalf("legacy signal removed: %d %v", legacy, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM signals WHERE source_table='cost_samples' AND source_id=?`, costID).Scan(&stale); err != nil || stale != 0 {
		t.Fatalf("stale cost projection remains: %d %v", stale, err)
	}
}
