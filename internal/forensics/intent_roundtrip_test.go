package forensics_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/intent"
	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func TestSignedBundleRetainsIntentAnalysis(t *testing.T) {
	for _, materialize := range []bool{false, true} {
		t.Run(map[bool]string{false: "historical", true: "current"}[materialize], func(t *testing.T) {
			testIntentRoundTrip(t, materialize)
		})
	}
}

func testIntentRoundTrip(t *testing.T, materialize bool) {
	paths := mustInit(t, filepath.Join(t.TempDir(), "source"))
	db := mustOpen(t, paths)
	defer db.Close()
	for _, stmt := range []string{
		`INSERT INTO events (id,run_id,event_type,source,payload,created_at) VALUES ('secret','run','secret_path','agentprov_ebpf','{"path":"/work/.aws/credentials"}','2026-11-06T00:00:00Z')`,
		`INSERT INTO intent_diffs (id,run_id,status,contract_kind,observed_effects,mismatch_reason,source,created_at) VALUES ('diff/historical-gap','run','intent_coverage_gap','none','["credential_read"]','No captured intent','coverage','2026-11-06T00:00:00Z')`,
		`INSERT INTO graph_edges (id,run_id,from_id,to_id,edge_type,created_at) VALUES ('intent-edge','run','diff/historical-gap','runtime_event/secret','intent_diff_effect','2026-11-06T00:00:00Z')`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	wantRule := "agentprov.intent_scope/v1"
	if materialize {
		if _, err := intent.Materialize(db, "run"); err != nil {
			t.Fatal(err)
		}
		wantRule = intent.RuleVersion
	}
	var wantID string
	if err := db.QueryRow(`SELECT id FROM intent_diffs WHERE run_id='run'`).Scan(&wantID); err != nil {
		t.Fatal(err)
	}
	opts := provenance.GraphLensOptions{RunID: "run", Lens: "intent", Detail: "raw"}
	before, err := provenance.BuildGraphLens(db, opts)
	if err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key}).ExportBundle("run")
	if err != nil {
		t.Fatal(err)
	}
	if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, pub); err != nil {
		t.Fatal(err)
	}
	replayPaths := mustInit(t, filepath.Join(t.TempDir(), "replay"))
	replayDB := mustOpen(t, replayPaths)
	defer replayDB.Close()
	for i := 0; i < 2; i++ {
		if _, err := (forensics.Service{DB: replayDB, Paths: replayPaths}).ImportBundle(bundle.Path); err != nil {
			t.Fatal(err)
		}
		var id, status, source, rule string
		if err := replayDB.QueryRow(`SELECT id,status,source,rule_version FROM intent_diffs WHERE run_id='run'`).Scan(&id, &status, &source, &rule); err != nil {
			t.Fatalf("analysis missing after signed import: %v", err)
		}
		if id != wantID || status != "intent_coverage_gap" || source != "coverage" || rule != wantRule {
			t.Fatalf("saved analysis changed: %s %s %s %s", id, status, source, rule)
		}
		after, err := provenance.BuildGraphLens(replayDB, opts)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(before.Nodes, after.Nodes) || !reflect.DeepEqual(before.Edges, after.Edges) || !reflect.DeepEqual(before.DerivedEdges, after.DerivedEdges) {
			t.Fatal("intent graph changed across signed roundtrip")
		}
	}
}
