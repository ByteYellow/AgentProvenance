package forensics_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestSignedBundleRetainsParsedTLSMetadata(t *testing.T) {
	t.Setenv("AGENTPROV_TLS_CAPTURE_BODY", "")
	const runID = "tls-metadata"
	paths := mustInit(t, filepath.Join(t.TempDir(), "source"))
	db := mustOpen(t, paths)
	defer db.Close()
	const connectionID = "tls-v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	raw := `{"source":"agentprov_ebpf","pid":42,"event_type":"tls_write","protocol":"h2","connection_id":"` + connectionID + `","headers_decoded":true,"stream_id":5,"method":"POST","host":"api.example","path":"/v1/messages?token=private","content_type":"application/json","model":"m","data":"{}","length":2,"time":"2026-10-17T00:00:00Z"}`
	input := filepath.Join(t.TempDir(), "capture.jsonl")
	if err := os.WriteFile(input, []byte(raw+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := telemetry.IngestJSONL(db, telemetry.JSONLIngestOptions{Format: "native", Path: input, RunID: runID})
	if err != nil || result.Ingested != 1 {
		t.Fatalf("ingest = %+v, err = %v", result, err)
	}
	before, err := telemetry.ListEventsFiltered(db, telemetry.Filter{RunID: runID, Type: "tls_write"})
	if err != nil || len(before) != 1 {
		t.Fatalf("query = %+v, err = %v", before, err)
	}
	var payload struct {
		HTTP    map[string]any  `json:"http"`
		Content string          `json:"content"`
		Payload json.RawMessage `json:"payload"`
		Raw     json.RawMessage `json:"raw"`
	}
	data := []byte(before[0].Payload)
	for i := 0; i < 4; i++ {
		payload.Payload = nil
		payload.Raw = nil
		if err := json.Unmarshal(data, &payload); err != nil {
			t.Fatal(err)
		}
		if len(payload.Payload) > 0 {
			data = payload.Payload
		} else if len(payload.Raw) > 0 {
			data = payload.Raw
		} else {
			break
		}
	}
	if payload.HTTP["stream_id"] != float64(5) || payload.HTTP["connection_id"] != connectionID || payload.HTTP["endpoint"] != "api.example/v1/messages" || payload.Content != "" {
		t.Fatalf("stored TLS metadata/body policy: %+v; event=%s", payload, before[0].Payload)
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
	after, err := telemetry.ListEventsFiltered(replayDB, telemetry.Filter{RunID: runID, Type: "tls_write"})
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("TLS metadata changed across signed export/import: before=%+v after=%+v err=%v", before, after, err)
	}
}
