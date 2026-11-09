package forensics_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/record"
)

func TestSignedRecordQuotedCommandRoundtrip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a POSIX shell")
	}
	paths := mustInit(t, filepath.Join(t.TempDir(), "source"))
	db := mustOpen(t, paths)
	defer db.Close()
	const runID = "quoted-command"
	svc := record.Service{DB: db, Paths: paths, Options: record.Options{AllowShell: true}}
	result, err := svc.Run(record.Request{
		RunID: runID, DisableSnapshot: true,
		Command: []string{"sh", "-c", `export SERVICE_API_KEY="${SERVICE_API_KEY:-synthetic-credential-value}"; printf 'completed\n'`},
	})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("record: %v, %+v", err, result)
	}
	if _, err := (provenance.ObjectStore{DB: db, Paths: paths}).MaterializeRun(runID); err != nil {
		t.Fatal(err)
	}
	before, err := provenance.Verify(db, runID)
	if err != nil || before.ErrorCount != 0 {
		t.Fatalf("source verification: %v, %+v", err, before)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key}).ExportBundle(runID)
	if err != nil {
		t.Fatal(err)
	}
	if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, pub); err != nil {
		t.Fatal(err)
	}
	replayPaths := mustInit(t, filepath.Join(t.TempDir(), "replay"))
	replayDB := mustOpen(t, replayPaths)
	defer replayDB.Close()
	if _, err := (forensics.Service{DB: replayDB, Paths: replayPaths}).ImportBundle(bundle.Path); err != nil {
		t.Fatal(err)
	}
	after, err := provenance.Verify(replayDB, runID)
	if err != nil || after.ErrorCount != 0 {
		t.Fatalf("replay verification: %v, %+v", err, after)
	}
	var objectPath string
	if err := replayDB.QueryRow(`SELECT path FROM provenance_objects WHERE run_id=? AND object_type='record_manifest'`, runID).Scan(&objectPath); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(objectPath)
	if err != nil || strings.Contains(string(raw), "synthetic-credential-value") {
		t.Fatalf("object retained the credential: %v", err)
	}
	if _, err := replayDB.Exec(`UPDATE fork_attempts SET command=command || '; changed-action' WHERE id=?`, result.AttemptID); err != nil {
		t.Fatal(err)
	}
	tampered, err := provenance.Verify(replayDB, runID)
	if err != nil {
		t.Fatal(err)
	}
	for _, issue := range tampered.Issues {
		if issue.Kind == "record_manifest_mismatch" {
			return
		}
	}
	t.Fatal("changed non-secret command escaped verification")
}
