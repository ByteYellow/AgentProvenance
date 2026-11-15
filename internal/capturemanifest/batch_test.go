package capturemanifest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestJSONLManifestUsesSavedProcessingEvidence(t *testing.T) {
	for _, tc := range []struct{ format, line string }{
		{"native", `{"event_type":"execve","source":"agentprov_ebpf","pid":42,"argv":["python3","task.py"]}`},
		{"tetragon", `{"process_exec":{"process":{"pid":42,"binary":"/usr/bin/python3","arguments":"task.py"}}}`},
		{"falco", `{"rule":"fixture","output_fields":{"evt.type":"execve","proc.pid":42,"proc.cmdline":"python3 task.py"}}`},
		{"loongcollector", `{"source":"loongcollector","event_type":"execve","pid":42,"command":"python3 task.py"}`},
	} {
		t.Run(tc.format, func(t *testing.T) {
			db, paths := testStore(t)
			input := tc.line + "\n"
			batch, err := telemetry.IngestJSONLReader(db, telemetry.JSONLIngestOptions{RunID: "r", Format: tc.format, Path: "PRIVATE-IMPORT-PATH"}, strings.NewReader(input))
			if err != nil || batch.Ingested != 1 {
				t.Fatalf("ingest: %+v %v", batch, err)
			}
			before := all(t, db, "r", 1)
			if len(before) != 1 {
				t.Fatalf("saved JSONL processing observation missing: %+v", before)
			}
			r := before[0]
			if r.ID != "batch/"+batch.BatchID || r.EvidenceRef != "telemetry_batch/"+batch.BatchID || r.EvidenceKind != "batch" ||
				r.Source != "telemetry_jsonl" || r.Identity["format"] != tc.format || r.Identity["file_sha256"] != batch.FileSHA256 ||
				r.Identity["event_ids_sha256"] != batch.EventIDsSHA256 || r.IntervalBasis != "source_processing_range" || r.Status != "processed" {
				t.Fatalf("processing identity changed: %+v", r)
			}
			if r.ProducerVersion != "unknown" || r.ProducerCommit != "unknown" || r.Placement != "unknown" || r.IdentityDomain != "ingest_batch" ||
				r.StartedAt != "" || r.EndedAt != "" || len(r.Snapshots) != 0 || len(r.Retention) != 0 || len(r.Loss) != 1 || r.Loss[0].Value != nil {
				t.Fatalf("import acquired an upstream capability claim: %+v", r)
			}
			raw, _ := json.Marshal(r)
			if strings.Contains(string(raw), "PRIVATE-IMPORT-PATH") {
				t.Fatal("manifest disclosed local input path")
			}
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key}).ExportBundle("r")
			if err != nil {
				t.Fatal(err)
			}
			if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, pub); err != nil {
				t.Fatal(err)
			}
			dst, destPaths := testStore(t)
			for i := 0; i < 2; i++ {
				if _, err := (forensics.Service{DB: dst, Paths: destPaths}).ImportBundle(bundle.Path); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Rename(paths.Provenance, paths.Provenance+"-unavailable"); err != nil {
				t.Fatal(err)
			}
			if after := all(t, dst, "r", 1); !reflect.DeepEqual(before, after) {
				t.Fatalf("signed import changed processing evidence:\n%+v\n%+v", before, after)
			}
			if page, err := (Service{DB: dst}).List(context.Background(), Options{RunID: "foreign"}); err != nil || len(page.Records) != 0 {
				t.Fatalf("foreign Run leaked: %+v %v", page, err)
			}
		})
	}
}

func TestJSONLManifestKeepsProcessingCountsSeparateFromLoss(t *testing.T) {
	db, _ := testStore(t)
	input := `{"event_type":"execve","argv":["true"]}
{"event_type":"not_supported"}
{"event_type":"file_open","path":"/excluded/file"}
invalid-json
`
	batch, err := telemetry.IngestJSONLReader(db, telemetry.JSONLIngestOptions{RunID: "r", Format: "native", ExcludePathPrefixes: []string{"/excluded/"}}, strings.NewReader(input))
	if err != nil || batch.Read != 4 || batch.Ingested != 1 || batch.Skipped != 1 || batch.Failed != 1 || batch.Excluded != 1 {
		t.Fatalf("fixture: %+v %v", batch, err)
	}
	r := all(t, db, "r", 1)[0]
	want := map[string]string{"read": "4", "ingested": "1", "skipped": "1", "failed": "1", "unclassified": "1"}
	if len(r.Counts) != len(want) || r.Status != "partial" || r.Loss[0].Value != nil || !strings.Contains(strings.Join(r.Issues, ","), "row_dispositions_not_recorded") {
		t.Fatalf("processing counts changed into capture loss: %+v", r)
	}
	for _, c := range r.Counts {
		if c.Value == nil || *c.Value != want[c.Name] || c.Scope != "processing_range" || c.ScopeID != batch.BatchID {
			t.Fatalf("count: %+v", c)
		}
	}
	if _, err := db.Exec(`UPDATE telemetry_batches SET read_count=9007199254740993 WHERE id=?`, batch.BatchID); err != nil {
		t.Fatal(err)
	}
	if got := all(t, db, "r", 1)[0].Counts[0]; got.Value == nil || *got.Value != "9007199254740993" {
		t.Fatalf("receipt count rounded: %+v", got)
	}
	if _, err := telemetry.IngestJSONLReader(db, telemetry.JSONLIngestOptions{RunID: "empty", Format: "auto"}, strings.NewReader("\n")); err != nil {
		t.Fatal(err)
	}
	if got := all(t, db, "empty", 1); len(got) != 1 || got[0].Status != "processed" || got[0].Loss[0].Value != nil {
		t.Fatalf("empty input changed upstream coverage: %+v", got)
	}
}

func TestJSONLManifestPaginationAndInvalidMembership(t *testing.T) {
	db, _ := testStore(t)
	batch, err := telemetry.IngestJSONLReader(db, telemetry.JSONLIngestOptions{RunID: "r", Format: "native"}, strings.NewReader(`{"event_type":"execve","argv":["true"]}`))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 260; i++ {
		if _, err := db.Exec(`INSERT INTO telemetry_batches SELECT ?,run_id,format,path,file_sha256,
			read_count,ingested_count,skipped_count,failed_count,event_ids_json,event_ids_sha256,created_at
			FROM telemetry_batches WHERE id=?`, fmt.Sprintf("receipt-%03d", i), batch.BatchID); err != nil {
			t.Fatal(err)
		}
	}
	if got := all(t, db, "r", 17); len(got) != 261 {
		t.Fatalf("receipts truncated: %d", len(got))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (Service{DB: db}).List(ctx, Options{RunID: "r"}); err == nil {
		t.Fatal("cancelled enumeration succeeded")
	}
	for _, mutation := range []string{
		`event_ids_json='["absent"]'`, `event_ids_json='[7]'`, `event_ids_json='{}'`,
		`event_ids_json='invalid'`, `event_ids_sha256='wrong'`, `ingested_count=2`,
		`read_count=-1`, `failed_count=2`, `file_sha256='wrong'`, `created_at='invalid'`,
	} {
		t.Run(mutation, func(t *testing.T) {
			other, _ := testStore(t)
			b, err := telemetry.IngestJSONLReader(other, telemetry.JSONLIngestOptions{RunID: "r", Format: "native"}, strings.NewReader(`{"event_type":"execve","argv":["true"]}`))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := other.Exec(`UPDATE telemetry_batches SET `+mutation+` WHERE id=?`, b.BatchID); err != nil {
				t.Fatal(err)
			}
			if _, err := (Service{DB: other}).List(context.Background(), Options{RunID: "r"}); err == nil {
				t.Fatal("invalid receipt reported successful processing")
			}
		})
	}
	if _, err := db.Exec(`UPDATE events SET run_id='foreign' WHERE id=?`, batch.EventIDs[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := (Service{DB: db}).List(context.Background(), Options{RunID: "r"}); err == nil {
		t.Fatal("foreign event supports a batch")
	}
}
