package dashboard

import (
	"database/sql"
	"fmt"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/intent"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func addIntentAssociationFixture(t *testing.T, db *sql.DB, paths store.Paths) {
	t.Helper()
	for _, statement := range []string{
		`INSERT INTO agents(id,run_id,name,created_at) VALUES ('bob','ui-intent','Synthetic worker','2026-11-06T00:00:00Z'),('other','ui-intent','Other worker','2026-11-06T00:00:00Z')`,
		`INSERT INTO tool_calls(id,run_id,agent_id,command,status,created_at) VALUES
		('ui-intent-work','ui-intent','bob','','completed','2026-11-06T00:00:02Z'),
		('ui-intent-uncovered','ui-intent','other','','completed','2026-11-06T00:00:02Z'),
		('ui-intent-bound','ui-intent','other','echo done','completed','2026-11-06T00:00:02Z')`,
		`INSERT INTO events(id,run_id,tool_call_id,source,event_type,payload,correlation_confidence,created_at) VALUES
		('ui-intent-secret','ui-intent','ui-intent-work','agentprov_ebpf','secret_path','{"path":"/fixture/.aws/credentials","fixture":true}',1,'2026-11-06T00:00:03Z'),
		('ui-intent-missing','ui-intent','ui-intent-uncovered','agentprov_ebpf','secret_path','{"path":"/fixture/.aws/credentials","fixture":true}',1,'2026-11-06T00:00:03Z'),
		('ui-intent-exec','ui-intent','ui-intent-bound','agentprov_ebpf','execve','{"command":"echo done","fixture":true}',1,'2026-11-06T00:00:03Z')`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"A", "B"} {
		object, err := (provenance.ObjectStore{DB: db, Paths: paths}).PutExternalObject(provenance.ExternalObjectInput{
			RunID: "ui-intent", Type: "artifact", SourceID: "agent_message/ui-intent-" + name,
			Payload: map[string]any{"kind": "agent_message", "body": "Synthetic delegation " + name + ": install package " + name, "content": "Synthetic delegation " + name + ": install package " + name, "fixture": true},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO graph_edges(id,run_id,from_id,to_id,edge_type,created_at) VALUES (?,'ui-intent',?,'agent/bob','agent_message','2026-11-06T00:00:01Z')`, "ui-intent-msg-"+name, object.Hash); err != nil {
			t.Fatal(err)
		}
	}
	result, err := intent.Materialize(db, "ui-intent")
	if err != nil || result.AssociationGaps != 1 || result.CoverageGaps != 1 || result.Mismatches != 0 || result.ByStatus[intent.StatusExecuted] != 1 {
		t.Fatalf("intent browser fixture: %+v %v", result, err)
	}
	graph, err := provenance.BuildGraphLens(db, provenance.GraphLensOptions{RunID: "ui-intent", Lens: "intent", Detail: "raw"})
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, node := range graph.Nodes {
		if node.Kind == "intent_diff" {
			found[node.Subtype] = true
			if fmt.Sprint(node.Data["rule_version"]) != intent.RuleVersion {
				t.Fatalf("graph analysis version: %+v", node)
			}
		}
	}
	for _, status := range []string{intent.StatusAssociationGap, intent.StatusCoverageGap, intent.StatusExecuted} {
		if !found[status] {
			t.Errorf("graph omitted %s", status)
		}
	}
}
