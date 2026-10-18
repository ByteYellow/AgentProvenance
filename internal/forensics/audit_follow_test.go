//go:build linux || darwin

package forensics_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestAuditFollowerSignedRoundtrip(t *testing.T) {
	input := []byte(`type=SECCOMP msg=audit(1792342593.758:131): pid=42 arch=c00000b7 syscall=203 code=0x7ffc0000` + "\n")
	source := telemetry.AuditSource{HostID: "fixture-host", BootID: "01234567-89ab-cdef-0123-456789abcdef"}
	if path := os.Getenv("AGENTPROV_AUDIT_FOLLOW_INPUT"); path != "" {
		var err error
		input, err = os.ReadFile(path)
		if err != nil || len(input) > 2<<20 {
			t.Fatalf("live input: %v", err)
		}
		source = telemetry.AuditSource{}
	}
	for _, keep := range []bool{false, true} {
		paths := mustInit(t, t.TempDir())
		db := mustOpen(t, paths)
		defer db.Close()
		path := filepath.Join(t.TempDir(), "audit.log")
		if err := os.WriteFile(path, input, 0600); err != nil {
			t.Fatal(err)
		}
		status, err := telemetry.FollowAuditFile(context.Background(), db, paths, telemetry.AuditFollowOptions{
			AuditIngestOptions: telemetry.AuditIngestOptions{RunID: "follow-roundtrip", Path: path, Source: source, RetainRaw: keep}, Once: true}, nil)
		if err != nil || status.Reader.Ingested == 0 {
			t.Fatalf("follow=%+v %v", status, err)
		}
		before, err := telemetry.ListEvents(db, "follow-roundtrip", "")
		if err != nil {
			t.Fatal(err)
		}
		public, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key}).ExportBundle("follow-roundtrip")
		if err != nil {
			t.Fatal(err)
		}
		if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, public); err != nil {
			t.Fatal(err)
		}
		replayPaths := mustInit(t, t.TempDir())
		replayDB := mustOpen(t, replayPaths)
		defer replayDB.Close()
		if _, err := (forensics.Service{DB: replayDB, Paths: replayPaths}).ImportBundle(bundle.Path); err != nil {
			t.Fatal(err)
		}
		after, err := telemetry.ListEvents(replayDB, "follow-roundtrip", "")
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatalf("collection evidence changed after signed import: %v", err)
		}
		var checkpoints int
		if err := replayDB.QueryRow(`SELECT COUNT(*) FROM telemetry_audit_checkpoints`).Scan(&checkpoints); err != nil || checkpoints != 0 {
			t.Fatalf("replay resumed a local collector checkpoint: %d %v", checkpoints, err)
		}
		verified, err := provenance.Verify(replayDB, "follow-roundtrip")
		if err != nil || verified.ErrorCount != 0 || verified.WarningCount != 0 {
			t.Fatalf("verify=%+v %v", verified, err)
		}
		t.Logf("retained %d audit decisions and %d collection observations through signed replay, raw_records=%v", status.Reader.Ingested, len(after)-status.Reader.Ingested, keep)
	}
}
