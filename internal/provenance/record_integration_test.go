package provenance_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestVerifyRejectsMissingOrphanLifecycleEvidence(t *testing.T) {
	root := t.TempDir()
	paths, err := store.Init(filepath.Join(root, ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	workdir := filepath.Join(root, "workspace")
	if err := os.MkdirAll(workdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workdir, "app.py"), []byte("value = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := (record.Service{DB: db, Paths: paths}).Run(record.Request{
		RunID: "run-orphan-verify", Name: "orphan-verify", Workdir: workdir,
		Command: []string{"sh", "-c", "printf 'value = 2\\n' > app.py"},
	})
	if err != nil {
		t.Fatal(err)
	}
	seedOrphanObservation(t, db, result)

	clean, err := provenance.Verify(db, result.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if clean.ErrorCount != 0 {
		t.Fatalf("clean orphan record should verify: %+v", clean.Issues)
	}
	if _, err := db.Exec(`DELETE FROM evidence_events WHERE run_id = ? AND event_type = 'orphan_lifecycle_decision'`, result.RunID); err != nil {
		t.Fatal(err)
	}
	broken, err := provenance.Verify(db, result.RunID)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"missing_orphan_lifecycle_evidence", "missing_orphan_lifecycle_policy_decision"} {
		found := false
		for _, issue := range broken.Issues {
			found = found || issue.Kind == want
		}
		if !found {
			t.Fatalf("missing %s in %+v", want, broken.Issues)
		}
	}
}
