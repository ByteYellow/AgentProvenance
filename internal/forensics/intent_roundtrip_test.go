package forensics_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
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

func TestSignedBundleRetainsPeerCandidatesAndPolicies(t *testing.T) {
	for _, policy := range []bool{false, true} {
		t.Run(fmt.Sprint("policy=", policy), func(t *testing.T) {
			paths := mustInit(t, filepath.Join(t.TempDir(), "source"))
			db := mustOpen(t, paths)
			defer db.Close()
			for _, stmt := range []string{
				`INSERT INTO tool_calls(id,run_id,agent_id,command,status,created_at) VALUES ('work','run','bob','python setup.py install','completed','2026-11-06T00:00:01Z')`,
				`INSERT INTO events(id,run_id,tool_call_id,event_type,source,payload,created_at) VALUES ('secret','run','work','secret_path','agentprov_ebpf','{"path":"/work/.aws/credentials"}','2026-11-06T00:00:02Z')`,
			} {
				if _, err := db.Exec(stmt); err != nil {
					t.Fatal(err)
				}
			}
			objects := provenance.ObjectStore{DB: db, Paths: paths}
			for _, id := range []string{"message-a", "message-b"} {
				payload := map[string]any{"body": "install dependency"}
				if policy {
					payload["intent_scope"] = map[string]any{"kind": "agent_policy", "agent_id": "bob", "valid_from": "2026-11-06T00:00:00Z", "valid_until": "2026-11-06T00:01:00Z"}
				}
				obj, err := objects.PutExternalObject(provenance.ExternalObjectInput{RunID: "run", Type: "artifact", SourceID: "agent_message/" + id, Payload: payload})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(`INSERT INTO graph_edges(id,run_id,from_id,to_id,edge_type,created_at) VALUES (?,'run',?,'agent/bob','agent_message','2026-11-06T00:00:00Z')`, id, obj.Hash); err != nil {
					t.Fatal(err)
				}
			}
			res, err := intent.Materialize(db, "run")
			if err != nil {
				t.Fatal(err)
			}
			if res.MismatchEvents != 1 || policy && (res.Mismatches != 3 || res.AssociationGaps != 0) || !policy && (res.Mismatches != 1 || res.AssociationGaps != 1) {
				t.Fatalf("contract/event counting: %+v", res)
			}
			opts := provenance.GraphLensOptions{RunID: "run", Lens: "intent", Detail: "raw"}
			before, err := provenance.BuildGraphLens(db, opts)
			if err != nil {
				t.Fatal(err)
			}
			want, err := intent.ExtractContracts(db, "run", intent.DefaultProfiles())
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
			replay := mustOpen(t, replayPaths)
			defer replay.Close()
			// Import relocates object files while retaining their content identities.
			for _, node := range before.Nodes {
				if !strings.HasPrefix(node.ID, "sha256:") {
					continue
				}
				if path, ok := node.Data["path"].(string); ok {
					rel, err := filepath.Rel(paths.Root, path)
					if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
						t.Fatalf("unexpected source object path: %s", path)
					}
					node.Data["path"] = filepath.Join(replayPaths.Root, rel)
				}
			}
			for i := 0; i < 2; i++ {
				if _, err := (forensics.Service{DB: replay, Paths: replayPaths}).ImportBundle(bundle.Path); err != nil {
					t.Fatal(err)
				}
				after, err := provenance.BuildGraphLens(replay, opts)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(before.Nodes, after.Nodes) || !reflect.DeepEqual(before.DerivedEdges, after.DerivedEdges) {
					wantJSON, _ := json.Marshal(before)
					gotJSON, _ := json.Marshal(after)
					t.Fatalf("peer association graph changed in signed import\nbefore=%s\nafter=%s", wantJSON, gotJSON)
				}
				got, err := intent.ExtractContracts(replay, "run", intent.DefaultProfiles())
				if err != nil || !reflect.DeepEqual(want, got) {
					t.Fatalf("source contracts changed: %v\nwant=%+v\ngot=%+v", err, want, got)
				}
				if !policy {
					var raw string
					if err := replay.QueryRow(`SELECT payload FROM signals WHERE source_table='intent_diffs' AND signal_type=?`, intent.StatusAssociationGap).Scan(&raw); err != nil {
						t.Fatal(err)
					}
					var a intent.IntentAssociation
					if err := json.Unmarshal([]byte(raw), &a); err != nil || a.Status != "ambiguous" || len(a.Candidates) != 2 {
						t.Fatalf("candidate evidence lost: %s %v", raw, err)
					}
				}
			}
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
