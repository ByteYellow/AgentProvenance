package forensics_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/tlsintent"
)

func TestSignedBundleRetainsTLSFragmentPosition(t *testing.T) {
	paths := mustInit(t, filepath.Join(t.TempDir(), "source"))
	db := mustOpen(t, paths)
	defer db.Close()
	capture := tlsintent.CaptureIntegrity{Rule: tlsintent.CaptureRule, State: "incomplete", Reason: tlsintent.GapChunkSequence,
		DataKind: tlsintent.DataTLSFragment,
		Position: &tlsintent.ChunkPosition{StreamID: 123456789012345678, CallSequence: 9, Offset: 768, TotalBytes: 4096}}
	payload, err := json.Marshal(map[string]any{"content": "YWJj/wA=", "content_encoding": "base64", "capture": capture, "truncated": true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO events (id,run_id,source,event_type,created_at,payload) VALUES ('gap','tls-run','agentprov_ebpf','tls_read','2026-11-06T00:00:00Z',?)`, string(payload)); err != nil {
		t.Fatal(err)
	}
	if _, err := provenance.MaterializeLLMCalls(provenance.ObjectStore{DB: db, Paths: paths}, db, "tls-run"); err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key}).ExportBundle("tls-run")
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
	var saved string
	if err := replayDB.QueryRow(`SELECT payload FROM events WHERE id='gap'`).Scan(&saved); err != nil || saved != string(payload) {
		t.Fatalf("source capture changed: %s %v", saved, err)
	}
	graph, err := provenance.BuildGraphLens(replayDB, provenance.GraphLensOptions{RunID: "tls-run", Lens: "agent-intent", Detail: "raw"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, node := range graph.Nodes {
		if node.Data["source_id"] != "llm_response/gap" {
			continue
		}
		found = true
		var got tlsintent.CaptureIntegrity
		encoded, err := json.Marshal(node.Data["capture"])
		if err != nil || json.Unmarshal(encoded, &got) != nil || !reflect.DeepEqual(capture, got) ||
			node.Data["command"] != "" || node.Data["truncated"] != true || node.Data["content_encoding"] != "base64" {
			t.Fatalf("fragment gained semantics or lost position: %+v %v", node.Data, err)
		}
	}
	if !found {
		t.Fatal("fragment missing from replay graph")
	}
}
