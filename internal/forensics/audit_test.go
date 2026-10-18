package forensics_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/security"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestSignedBundleRetainsAuditDecisions(t *testing.T) {
	for _, preset := range []string{"basic", "detailed"} {
		t.Run(preset, func(t *testing.T) {
			const runID = "run-audit"
			paths := mustInit(t, filepath.Join(t.TempDir(), "source"))
			db := mustOpen(t, paths)
			defer db.Close()
			policy, err := agentcontext.NewCapturePolicy(preset, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := (agentcontext.Service{DB: db, Paths: paths, CapturePolicy: &policy}).EnsureCapturePolicy(context.Background(), runID); err != nil {
				t.Fatal(err)
			}
			input := `type=AVC msg=audit(1792342593.757:130): apparmor="DENIED" operation="open" profile="fixture-policy" pid=42 name="/tmp/fixture" requested_mask="r" denied_mask="r"
type=SECCOMP msg=audit(1792342593.758:131): pid=42 arch=c00000b7 syscall=203 sig=0 code=0x7ffc0000
type=SECCOMP msg=audit(1792342593.759:132): pid=43 arch=c000003e syscall=39 sig=31 code=0x80000000
`
			opts := telemetry.AuditIngestOptions{RunID: runID, RetainRaw: policy.SourceRecords, Source: telemetry.AuditSource{
				HostID: "fixture-host", BootID: "01234567-89ab-cdef-0123-456789abcdef"}}
			result, err := telemetry.IngestAuditReader(context.Background(), db, opts, strings.NewReader(input))
			if err != nil || result.Ingested != 3 {
				t.Fatalf("ingest=%+v err=%v", result, err)
			}
			before, err := telemetry.ListEvents(db, runID, "")
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range before {
				if _, recorded, err := security.EvaluateRuntimeEvent(db, e.ID); err != nil || recorded {
					t.Fatalf("external audit decision caused enforcement: recorded=%v err=%v", recorded, err)
				}
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
			after, err := telemetry.ListEvents(replayDB, runID, "")
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("audit evidence changed across signed roundtrip: %v", err)
			}
			verified, err := provenance.Verify(replayDB, runID)
			if err != nil || verified.ErrorCount != 0 {
				t.Fatalf("verify=%+v err=%v", verified, err)
			}
			result, err = telemetry.IngestAuditReader(context.Background(), replayDB, opts, strings.NewReader(input))
			if err != nil || result.Ingested != 0 || result.Duplicates != 3 {
				t.Fatalf("reimport changed stable identity: %+v %v", result, err)
			}
		})
	}
}
