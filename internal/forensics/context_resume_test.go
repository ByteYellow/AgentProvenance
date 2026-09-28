package forensics_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func TestSignedResumedContextRetainsBothRangesOffline(t *testing.T) {
	ctx := context.Background()
	paths := mustInit(t, filepath.Join(t.TempDir(), "source"))
	db := mustOpen(t, paths)
	defer db.Close()
	input := `{"type":"session_meta","payload":{"id":"s"}}
{"type":"turn_context","payload":{"model":"first","mcp_servers":{"docs":{"version":"1","tools":[]}}}}
{"type":"response_item","payload":{"type":"message","role":"user","content":"previous task"}}
{"type":"turn_context","payload":{"model":"second","mcp_servers":{"docs":{"version":"2","tools":["read"]}}}}
{"type":"response_item","payload":{"type":"message","role":"user","content":"resumed task"}}
`
	p, err := agentcontext.Parse(ctx, strings.NewReader(input), agentcontext.ParseOptions{Harness: "codex", Binding: "explicit", AfterLine: 3})
	if err != nil {
		t.Fatal(err)
	}
	svc := agentcontext.Service{DB: db, Paths: paths}
	if _, err := svc.Save(ctx, "run", p.Source, p.Records, p.Coverage); err != nil {
		t.Fatal(err)
	}
	before, err := svc.Entries(ctx, agentcontext.PageOptions{RunID: "run"})
	if err != nil || len(before.Entries) != 5 {
		t.Fatalf("entries: %+v %v", before, err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key}).ExportBundle("run")
	if err != nil {
		t.Fatal(err)
	}
	if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, pub); err != nil {
		t.Fatal(err)
	}
	fresh := mustInit(t, filepath.Join(t.TempDir(), "replay"))
	dbFresh := mustOpen(t, fresh)
	defer dbFresh.Close()
	if _, err := (forensics.Service{DB: dbFresh, Paths: fresh}).ImportBundle(bundle.Path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(paths.Provenance, paths.Provenance+"-offline"); err != nil {
		t.Fatal(err)
	}
	replayed := agentcontext.Service{DB: dbFresh, Paths: fresh}
	after, err := replayed.Entries(ctx, agentcontext.PageOptions{RunID: "run"})
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("context changed in transit: %+v %v", after, err)
	}
	for _, e := range after.Entries {
		expected := agentcontext.CurrentExecution
		if e.Sequence <= 3 {
			expected = agentcontext.PriorContext
		}
		if e.ExecutionScope != expected {
			t.Fatalf("lost execution boundary: %+v", e)
		}
		if _, err := provenance.ReadTextContentPage(dbFresh, "run", e.Content.Ref, 0, 1000); err != nil {
			t.Fatal(err)
		}
	}
	o, err := replayed.Overview(ctx, "run")
	if err != nil || o.Coverage[0].PriorContext == nil || *o.Coverage[0].Counts.Stored != 2 || *o.Coverage[0].PriorContext.Counts.Stored != 3 {
		t.Fatalf("portable ranges: %+v %v", o, err)
	}
	comparison, err := replayed.CompareSnapshots(ctx, "run", after.Entries[1].ID, "", after.Entries[3].ID)
	if err != nil || comparison.Status != "different" || len(comparison.Changes) != 3 {
		t.Fatalf("historical configuration comparison lost: %+v %v", comparison, err)
	}
	v, err := provenance.Verify(dbFresh, "run")
	if err != nil || v.ErrorCount != 0 {
		t.Fatalf("verify: %+v %v", v, err)
	}
}
