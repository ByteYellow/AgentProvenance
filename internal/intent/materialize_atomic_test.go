package intent

import (
	"database/sql"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func materializeSnapshot(t *testing.T, db *sql.DB) []string {
	t.Helper()
	var out []string
	for _, query := range []string{
		`SELECT id,run_id,status,observed_effects,created_at FROM intent_diffs ORDER BY id`,
		`SELECT id,run_id,from_id,to_id,edge_type,created_at FROM graph_edges ORDER BY id`,
		`SELECT id,run_id,source_id,signal_type,created_at FROM signals ORDER BY id`,
	} {
		rows, err := db.Query(query)
		if err != nil {
			t.Fatal(err)
		}
		cols, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
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
			out = append(out, string(raw))
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func TestMaterializeFailurePreservesDiffsSignalsAndAttribution(t *testing.T) {
	for _, stage := range []struct{ table, operation, condition string }{
		{"intent_diffs", "INSERT", "1"},
		{"graph_edges", "INSERT", "NEW.edge_type='intent_diff_effect'"},
		{"signals", "DELETE", "OLD.dimension='intent_conformance'"},
		{"signals", "INSERT", "NEW.dimension='intent_conformance'"},
	} {
		t.Run(stage.table+stage.operation, func(t *testing.T) {
			db := attributionStore(t, false)
			db.SetMaxOpenConns(1)
			if res, err := Materialize(db, "run"); err != nil || res.Mismatches == 0 {
				t.Fatalf("baseline: %+v %v", res, err)
			}
			// Exercise creation of attribution in the same pass as replacing diffs.
			if _, err := db.Exec(`DELETE FROM graph_edges WHERE edge_type='agent_syscall'`); err != nil {
				t.Fatal(err)
			}
			before := materializeSnapshot(t, db)
			if _, err := db.Exec("CREATE TRIGGER fail_intent BEFORE " + stage.operation + " ON " + stage.table + " WHEN " + stage.condition + " BEGIN SELECT RAISE(ABORT,'injected intent failure'); END"); err != nil {
				t.Fatal(err)
			}
			res, err := Materialize(db, "run")
			if err == nil || !strings.Contains(err.Error(), "injected intent failure") {
				t.Fatalf("failure not returned: %+v %v", res, err)
			}
			if res.Diffs != 0 || res.Mismatches != 0 {
				t.Fatalf("rolled-back results counted as saved: %+v", res)
			}
			if after := materializeSnapshot(t, db); !reflect.DeepEqual(before, after) {
				t.Fatal("failure changed previous diffs, signals or attribution")
			}
			if _, err := db.Exec("DROP TRIGGER fail_intent"); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				res, err := Materialize(db, "run")
				if err != nil || res.Mismatches == 0 {
					t.Fatalf("retry: %+v %v", res, err)
				}
				var diffs, sigs, orphan int
				if err := db.QueryRow(`SELECT COUNT(*) FROM intent_diffs WHERE run_id='run'`).Scan(&diffs); err != nil {
					t.Fatal(err)
				}
				if err := db.QueryRow(`SELECT COUNT(*) FROM signals WHERE dimension='intent_conformance' AND run_id='run'`).Scan(&sigs); err != nil {
					t.Fatal(err)
				}
				if err := db.QueryRow(`SELECT COUNT(*) FROM signals s LEFT JOIN intent_diffs d ON s.source_id=d.id
					WHERE s.dimension='intent_conformance' AND d.id IS NULL`).Scan(&orphan); err != nil {
					t.Fatal(err)
				}
				if diffs != res.Diffs || sigs != res.Mismatches+res.CoverageGaps || orphan != 0 {
					t.Fatalf("retry projections diverged: diffs=%d signals=%d orphan=%d result=%+v", diffs, sigs, orphan, res)
				}
			}
		})
	}
}

func TestMaterializeUnreadableModelResponsePreservesAnalysis(t *testing.T) {
	for _, damaged := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "corrupt"}[damaged], func(t *testing.T) {
			db := attributionStore(t, false)
			db.SetMaxOpenConns(1)
			st := provenance.ObjectStore{DB: db, Paths: store.Paths{Root: t.TempDir()}}
			obj, err := st.PutExternalObject(provenance.ExternalObjectInput{
				RunID: "run", Type: "llm_message", SourceID: "endpoint/resp-1",
				Payload: map[string]any{"content": "done", "semantics": map[string]any{"intent_role": "primary", "declared_tool_call": false}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Materialize(db, "run"); err != nil {
				t.Fatal(err)
			}
			before := materializeSnapshot(t, db)
			if damaged {
				err = os.WriteFile(obj.Path, []byte("null"), 0o644)
			} else {
				err = os.Remove(obj.Path)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Materialize(db, "run"); err == nil {
				t.Fatal("unreadable response should abort reanalysis")
			}
			if after := materializeSnapshot(t, db); !reflect.DeepEqual(before, after) {
				t.Fatal("source error replaced previous analysis")
			}
		})
	}
}

func TestMaterializePagedMessagesStayInTransaction(t *testing.T) {
	db := attributionStore(t, false)
	db.SetMaxOpenConns(1)
	st := provenance.ObjectStore{DB: db, Paths: store.Paths{Root: t.TempDir()}}
	for _, body := range []string{
		"install dependencies " + strings.Repeat("project notes ", provenance.MaxContentPageBytes/8),
		"read the project files",
	} {
		content, err := st.PutTextContent(provenance.TextContentInput{RunID: "run", SourceID: "message", Text: body})
		if err != nil {
			t.Fatal(err)
		}
		obj, err := st.PutExternalObject(provenance.ExternalObjectInput{
			RunID: "run", Type: "agent_message", SourceID: content.Ref,
			Payload: map[string]any{"content_ref": content.Ref},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO graph_edges (id,run_id,from_id,to_id,edge_type,created_at) VALUES
			(?,'run','agent/orchestrator',?,'agent_message','2026-01-01T00:00:00Z'),
			(?,'run',?,'agent/a','agent_message','2026-01-01T00:00:00Z')`, "from-"+obj.Hash, obj.Hash, "to-"+obj.Hash, obj.Hash); err != nil {
			t.Fatal(err)
		}
	}
	var before []IntentContract
	for i := 0; i < 8; i++ {
		res, err := Materialize(db, "run")
		if err != nil || res.Contracts != 3 {
			t.Fatalf("paged messages: %+v %v", res, err)
		}
		contracts, err := ExtractContracts(db, "run", DefaultProfiles())
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 && !reflect.DeepEqual(before, contracts) {
			t.Fatal("retry changed message contract identities")
		}
		before = contracts
	}
}

func TestMaterializeCommitFailurePreservesAnalysis(t *testing.T) {
	db := attributionStore(t, false)
	db.SetMaxOpenConns(1)
	if _, err := Materialize(db, "run"); err != nil {
		t.Fatal(err)
	}
	before := materializeSnapshot(t, db)
	for _, stmt := range []string{
		`CREATE TABLE commit_parent (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE commit_child (id INTEGER REFERENCES commit_parent(id) DEFERRABLE INITIALLY DEFERRED)`,
		`CREATE TRIGGER fail_commit AFTER INSERT ON signals BEGIN INSERT INTO commit_child VALUES(1); END`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	res, err := Materialize(db, "run")
	if err == nil || res.Diffs != 0 {
		t.Fatalf("expected commit failure: %+v %v", res, err)
	}
	if after := materializeSnapshot(t, db); !reflect.DeepEqual(before, after) {
		t.Fatal("failed commit replaced previous analysis")
	}
	if _, err := db.Exec(`DROP TRIGGER fail_commit`); err != nil {
		t.Fatal(err)
	}
	if _, err := Materialize(db, "run"); err != nil {
		t.Fatalf("retry after failed commit: %v", err)
	}
}
