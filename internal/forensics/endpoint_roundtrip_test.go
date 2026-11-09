package forensics_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func TestSignedEndpointAttributionRoundTrip(t *testing.T) {
	paths := mustInit(t, filepath.Join(t.TempDir(), "source"))
	db := mustOpen(t, paths)
	defer db.Close()
	for _, id := range []string{"a", "b"} {
		if _, err := db.Exec(`INSERT INTO events(id,run_id,process_id,event_type,source,payload,created_at)
			VALUES (?,'endpoint-test',?,'secret_path','sensor','{"path":"/work/secret"}','2026-11-06T00:00:01Z')`, id, "process-"+id); err != nil {
			t.Fatal(err)
		}
	}
	dump := t.TempDir()
	for name, raw := range map[string]string{
		"01.meta.json": `{"seq":1,"kind":"EXFIL-REQ","path":"/storage","host":"fixture.invalid","observed_at":"2026-11-06T00:00:03Z","canary_hits":["PUBLIC-TEST-CANARY"]}`,
		"01.body.bin":  `{"files":[{"path":"/work/secret","content":"PUBLIC-TEST-CANARY"}]}`,
	} {
		if err := os.WriteFile(filepath.Join(dump, name), []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := provenance.IngestEndpointDump(provenance.ObjectStore{DB: db, Paths: paths}, db, "endpoint-test", dump); err != nil {
		t.Fatal(err)
	}
	readPayload := func(db *sql.DB) string {
		t.Helper()
		var raw string
		if err := db.QueryRow(`SELECT payload FROM events WHERE source='endpoint_capture'`).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	want := readPayload(db)
	if !strings.Contains(want, `"status":"ambiguous"`) || !strings.Contains(want, `"status":"matched"`) || !strings.Contains(want, `"status":"unknown"`) {
		t.Fatalf("fixture stages: %s", want)
	}
	opts := provenance.GraphLensOptions{RunID: "endpoint-test", Lens: "data-flow-taint", Detail: "raw"}
	before, err := provenance.BuildGraphLens(db, opts)
	if err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key}).ExportBundle("endpoint-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, pub); err != nil {
		t.Fatal(err)
	}
	replayPaths := mustInit(t, filepath.Join(t.TempDir(), "import"))
	replay := mustOpen(t, replayPaths)
	defer replay.Close()
	for _, node := range before.Nodes {
		if strings.HasPrefix(node.ID, "sha256:") {
			if path, ok := node.Data["path"].(string); ok {
				rel, err := filepath.Rel(paths.Root, path)
				if err != nil || strings.HasPrefix(rel, "..") {
					t.Fatalf("object path outside source: %s", path)
				}
				node.Data["path"] = filepath.Join(replayPaths.Root, rel)
			}
		}
	}
	for i := 0; i < 2; i++ {
		if _, err := (forensics.Service{DB: replay, Paths: replayPaths}).ImportBundle(bundle.Path); err != nil {
			t.Fatal(err)
		}
		if got := readPayload(replay); got != want {
			t.Fatalf("frozen endpoint attribution rewritten\nwant=%s\ngot=%s", want, got)
		}
		after, err := provenance.BuildGraphLens(replay, opts)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(before.Nodes, after.Nodes) || !reflect.DeepEqual(before.Edges, after.Edges) || !reflect.DeepEqual(before.DerivedEdges, after.DerivedEdges) {
			a, _ := json.Marshal(before)
			b, _ := json.Marshal(after)
			t.Fatalf("signed endpoint graph changed\n%s\n%s", a, b)
		}
	}
}
