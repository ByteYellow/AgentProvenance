package forensics_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestLiveMixedAuditSignedRoundtrip(t *testing.T) {
	directory := os.Getenv("AGENTPROV_AUDIT_MIXED_EVIDENCE")
	if directory == "" {
		t.Skip("set AGENTPROV_AUDIT_MIXED_EVIDENCE to the controlled mixed-mechanism capture")
	}
	inputs := map[string][]byte{}
	for _, name := range []string{"mixed-runtime.jsonl", "mixed-state.jsonl", "mixed-journal.jsonl"} {
		path := filepath.Join(directory, name)
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 16<<20 {
			t.Fatalf("invalid capture file %s: %v", name, err)
		}
		inputs[name], err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, preset := range []string{"basic", "detailed"} {
		t.Run(preset, func(t *testing.T) {
			const run = "live-audit-mixed"
			ctx := context.Background()
			paths := mustInit(t, filepath.Join(t.TempDir(), "source"))
			db := mustOpen(t, paths)
			defer db.Close()
			policy, err := agentcontext.NewCapturePolicy(preset, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := (agentcontext.Service{DB: db, Paths: paths, CapturePolicy: &policy}).EnsureCapturePolicy(ctx, run); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"mixed-runtime.jsonl", "mixed-state.jsonl"} {
				r, err := telemetry.IngestJSONLReader(db, telemetry.JSONLIngestOptions{Format: "auto", RunID: run}, bytes.NewReader(inputs[name]))
				if err != nil || r.Failed != 0 || r.Ingested == 0 {
					t.Fatalf("native/state import: %+v %v", r, err)
				}
			}
			opts := telemetry.AuditIngestOptions{RunID: run, RetainRaw: policy.SourceRecords}
			r, err := telemetry.IngestAuditReader(ctx, db, opts, bytes.NewReader(inputs["mixed-journal.jsonl"]))
			if err != nil || r.Failed != 0 || r.Ingested < 6 {
				t.Fatalf("mixed audit import: %+v %v", r, err)
			}
			before, err := telemetry.ListEvents(db, run, "")
			if err != nil {
				t.Fatal(err)
			}
			counts := map[string]int{}
			for _, event := range before {
				if event.EventType != "access_control" {
					continue
				}
				var stored struct {
					Raw telemetry.AuditRecord `json:"raw"`
				}
				if err := json.Unmarshal([]byte(event.Payload), &stored); err != nil || stored.Raw.SchemaVersion != telemetry.AuditSchemaVersion {
					t.Fatalf("invalid stored audit: %v", err)
				}
				record := stored.Raw
				counts[record.Mechanism+"/"+record.Decision]++
				if preset == "basic" && (record.RawRecord.Text != "" || record.RawRecord.State != "omitted" || record.RawRecord.Reason != "capture_policy") {
					t.Fatalf("basic capture retained audit source: %+v", record.RawRecord)
				}
				if preset == "detailed" && (record.RawRecord.Text == "" || record.RawRecord.State != "available") {
					t.Fatalf("detailed capture lost audit source: %+v", record.RawRecord)
				}
				if record.Decision == "ERRNO" && (record.ActionData == nil || *record.ActionData != 0 || record.ActionCode == nil || *record.ActionCode != 0x50000) {
					t.Fatalf("logged action was replaced with fixture errno: %+v", record)
				}
			}
			if counts["apparmor/DENIED"] != 1 || counts["apparmor/ALLOWED"] != 1 || counts["seccomp/LOG"] != 2 || counts["seccomp/ERRNO"] < 2 {
				t.Fatalf("incomplete mixed capture: %v", counts)
			}
			associationBefore, err := telemetry.BuildAuditAssociations(ctx, db, telemetry.AuditAssociationOptions{RunID: run})
			if err != nil || associationBefore.Status != "complete" || len(associationBefore.Items) != r.Ingested {
				t.Fatalf("mixed associations: %+v %v", associationBefore, err)
			}
			for _, item := range associationBefore.Items {
				if item.Process.Status != "inferred" || item.Decision == "ERRNO" && item.Operation.Status != "unassociated" || item.Decision != "ERRNO" && item.Operation.Status != "inferred" {
					t.Fatalf("mixed association semantics changed: %+v", item)
				}
			}
			public, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key}).ExportBundle(run)
			if err != nil {
				t.Fatal(err)
			}
			if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, public); err != nil {
				t.Fatal(err)
			}
			replayPaths := mustInit(t, filepath.Join(t.TempDir(), "replay"))
			replayDB := mustOpen(t, replayPaths)
			defer replayDB.Close()
			if _, err := (forensics.Service{DB: replayDB, Paths: replayPaths}).ImportBundle(bundle.Path); err != nil {
				t.Fatal(err)
			}
			after, err := telemetry.ListEvents(replayDB, run, "")
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("live evidence changed after signed roundtrip: %v", err)
			}
			associationAfter, err := telemetry.BuildAuditAssociations(ctx, replayDB, telemetry.AuditAssociationOptions{RunID: run})
			if err != nil || !reflect.DeepEqual(associationBefore, associationAfter) {
				t.Fatalf("live associations changed after signed roundtrip: %v", err)
			}
			verified, err := provenance.Verify(replayDB, run)
			if err != nil || verified.ErrorCount != 0 || verified.WarningCount != 0 {
				t.Fatalf("graph verification: %+v %v", verified, err)
			}
			repeated, err := telemetry.IngestAuditReader(ctx, replayDB, opts, bytes.NewReader(inputs["mixed-journal.jsonl"]))
			if err != nil || repeated.Ingested != 0 || repeated.Duplicates != r.Ingested {
				t.Fatalf("signed replay lost deduplication identity: %+v %v", repeated, err)
			}
			if output := os.Getenv("AGENTPROV_AUDIT_MIXED_OUTPUT"); output != "" {
				if err := os.MkdirAll(output, 0700); err != nil {
					t.Fatal(err)
				}
				for name, source := range map[string]string{preset + ".forensics.json": bundle.Path, preset + ".attestation.json": bundle.AttestationPath} {
					data, err := os.ReadFile(source)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(output, name), data, 0600); err != nil {
						t.Fatal(err)
					}
				}
				data, err := json.MarshalIndent(map[string]any{"preset": preset, "event_count": len(after), "audit_counts": counts,
					"public_key_hex": hex.EncodeToString(public), "verification": verified, "associations": associationAfter, "repeat": repeated}, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(output, preset+"-report.json"), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			t.Logf("%s: %d live records, audit=%v, identical signed replay and associations", preset, len(after), counts)
		})
	}
}
