package forensics_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestSignedTelemetryBatchesRemainVerifiableAfterImport(t *testing.T) {
	const runID = "batch-portability"
	pathsA := mustInit(t, filepath.Join(t.TempDir(), "source"))
	dbA := mustOpen(t, pathsA)
	defer dbA.Close()
	source := filepath.Join(t.TempDir(), "native.jsonl")
	if err := os.WriteFile(source, []byte(`{"event_type":"execve","source":"agentprov_ebpf","pid":451,"cgroup_id":"42","command":"python3 --version","argv":["python3","--version"],"timestamp":"2026-09-28T06:45:00Z"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	batch, err := telemetry.IngestJSONL(dbA, telemetry.JSONLIngestOptions{Path: source, Format: "native", RunID: runID})
	if err != nil || batch.Ingested != 1 {
		t.Fatalf("ingest: %+v, %v", batch, err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	svc := forensics.Service{DB: dbA, Paths: pathsA, SignKey: priv}
	info, err := svc.ExportBundle(runID)
	if err != nil {
		t.Fatal(err)
	}
	if err := forensics.VerifyBundleAttestation(info.Path, info.AttestationPath, pub); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(info.Path)
	if err != nil {
		t.Fatal(err)
	}
	var original map[string]any
	if err := json.Unmarshal(raw, &original); err != nil {
		t.Fatal(err)
	}
	records, ok := original["telemetry_batch_records"].([]any)
	if !ok || len(records) != 1 {
		t.Fatal("full batch records missing; summaries cannot verify event membership")
	}
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	pathsB := mustInit(t, filepath.Join(t.TempDir(), "replay"))
	dbB := mustOpen(t, pathsB)
	defer dbB.Close()
	replay := forensics.Service{DB: dbB, Paths: pathsB}
	for i := 0; i < 2; i++ {
		imported, err := replay.ImportBundle(info.Path)
		if err != nil || imported.Tables["telemetry_batches"] != 1 {
			t.Fatalf("import: %+v, %v", imported, err)
		}
		if countRows(t, dbB, "telemetry_batches", runID) != 1 {
			t.Fatal("duplicate import changed batch multiplicity")
		}
	}
	exported, err := replay.ExportBundle(runID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(exported.Path)
	if err != nil {
		t.Fatal(err)
	}
	var restored map[string]any
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"telemetry_batch_records", "telemetry_batches"} {
		if !reflect.DeepEqual(original[field], restored[field]) {
			t.Fatalf("%s changed after offline import/export", field)
		}
	}
	verified, err := provenance.Verify(dbB, runID)
	if err != nil {
		t.Fatal(err)
	}
	for _, issue := range verified.Issues {
		if strings.HasPrefix(issue.Kind, "telemetry_batch_") {
			t.Fatalf("restored batch failed verification: %+v", issue)
		}
	}
	if _, err := dbB.Exec(`UPDATE telemetry_batches SET event_ids_sha256='tampered' WHERE id=?`, batch.BatchID); err != nil {
		t.Fatal(err)
	}
	verified, err = provenance.Verify(dbB, runID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, issue := range verified.Issues {
		found = found || issue.Kind == "telemetry_batch_event_hash_mismatch"
	}
	if !found {
		t.Fatal("batch verification was skipped after replay")
	}

	// Historical summaries did not contain the ordered event-ID list. Do not
	// invent one to satisfy the new batch verifier.
	delete(original, "telemetry_batch_records")
	raw, err = json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(t.TempDir(), "summary-only.json")
	if err := os.WriteFile(legacy, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	pathsC := mustInit(t, filepath.Join(t.TempDir(), "legacy"))
	dbC := mustOpen(t, pathsC)
	defer dbC.Close()
	if _, err := (forensics.Service{DB: dbC, Paths: pathsC}).ImportBundle(legacy); err != nil {
		t.Fatal(err)
	}
	if countRows(t, dbC, "telemetry_batches", runID) != 0 {
		t.Fatal("summary-only history acquired invented batch records")
	}
}
