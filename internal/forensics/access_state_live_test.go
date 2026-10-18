package forensics_test

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestLiveAccessStateSignedRoundtrip(t *testing.T) {
	path := os.Getenv("AGENTPROV_ACCESS_STATE_EVENTS")
	if path == "" {
		t.Skip("set AGENTPROV_ACCESS_STATE_EVENTS to a live sensor JSONL file")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	var input bytes.Buffer
	for scanner.Scan() {
		var event struct {
			Type string `json:"event_type"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		if event.Type == "access_control_state" {
			input.Write(scanner.Bytes())
			input.WriteByte('\n')
			if input.Len() > 5<<20 {
				t.Fatal("state acceptance input exceeds 5 MiB")
			}
		}
	}
	if err := scanner.Err(); err != nil || input.Len() == 0 {
		t.Fatalf("missing state input: %v", err)
	}
	paths := mustInit(t, filepath.Join(t.TempDir(), "source"))
	db := mustOpen(t, paths)
	defer db.Close()
	result, err := telemetry.IngestJSONLReader(db, telemetry.JSONLIngestOptions{Format: "auto", RunID: "state-live"}, &input)
	if err != nil || result.Ingested == 0 || result.Failed != 0 {
		t.Fatalf("ingest=%+v %v", result, err)
	}
	before, err := telemetry.ListEvents(db, "state-live", "")
	if err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key}).ExportBundle("state-live")
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
	after, err := telemetry.ListEvents(replayDB, "state-live", "")
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("live state changed after signed roundtrip: %v", err)
	}
	verified, err := provenance.Verify(replayDB, "state-live")
	if err != nil || verified.ErrorCount != 0 || verified.WarningCount != 0 {
		t.Fatalf("graph verification=%+v %v", verified, err)
	}
	t.Logf("preserved %d live state snapshots through signed export/import", len(after))
}
