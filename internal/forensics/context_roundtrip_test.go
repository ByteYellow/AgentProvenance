package forensics_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func TestSignedContextRoundTripBeyondLegacyLimits(t *testing.T) {
	for _, size := range []int{(64 << 10) + 19, (4 << 20) + 19, (8 << 20) + 19} {
		t.Run(stringSize(size), func(t *testing.T) {
			ctx := context.Background()
			pathsA := mustInit(t, filepath.Join(t.TempDir(), "source"))
			dbA := mustOpen(t, pathsA)
			t.Cleanup(func() { dbA.Close() })
			body := strings.Repeat("x", size) + "END-OF-RESULT"
			svc := agentcontext.Service{DB: dbA, Paths: pathsA}
			_, err := svc.Save(ctx, "run", agentcontext.Source{Harness: "codex", SessionID: "session", ParserVersion: "test/v1", Binding: "explicit"}, []agentcontext.Record{
				{Key: "result", Sequence: 1, Kind: "tool_result", ToolCallID: "tool", Body: &body},
			}, agentcontext.Coverage{Status: agentcontext.OK, Counts: agentcontext.Counts{Read: agentcontext.Number(1)}})
			if err != nil {
				t.Fatal(err)
			}
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			bundle, err := (forensics.Service{DB: dbA, Paths: pathsA, SignKey: key}).ExportBundle("run")
			if err != nil {
				t.Fatal(err)
			}
			if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, pub); err != nil {
				t.Fatal(err)
			}
			pathsB := mustInit(t, filepath.Join(t.TempDir(), "replay"))
			dbB := mustOpen(t, pathsB)
			t.Cleanup(func() { dbB.Close() })
			info, err := (forensics.Service{DB: dbB, Paths: pathsB}).ImportBundle(bundle.Path)
			if err != nil || info.Omitted != 0 {
				t.Fatalf("import: %+v %v", info, err)
			}
			// Remove the original blob location: replay must use only store B.
			if err := os.Rename(pathsA.Provenance, pathsA.Provenance+"-offline"); err != nil {
				t.Fatal(err)
			}
			page, err := (agentcontext.Service{DB: dbB, Paths: pathsB}).Entries(ctx, agentcontext.PageOptions{RunID: "run"})
			if err != nil || len(page.Entries) != 1 {
				t.Fatalf("entries: %+v %v", page, err)
			}
			var output strings.Builder
			for offset := int64(0); ; {
				p, err := provenance.ReadTextContentPage(dbB, "run", page.Entries[0].Content.Ref, offset, 200000)
				if err != nil {
					t.Fatal(err)
				}
				output.WriteString(p.Content)
				if !p.HasMore {
					break
				}
				offset = p.NextOffset
			}
			if output.String() != body {
				t.Fatal("offline full text differs")
			}
			o, err := (agentcontext.Service{DB: dbB, Paths: pathsB}).Overview(ctx, "run")
			if err != nil || len(o.Coverage) != 1 || o.Coverage[0].Status != agentcontext.OK || o.ToolResults == nil || *o.ToolResults != 1 {
				t.Fatalf("coverage: %+v %v", o, err)
			}
		})
	}
}

func stringSize(n int) string {
	if n < 1<<20 {
		return "64KiB"
	}
	if n < 8<<20 {
		return "4MiB"
	}
	return "8MiB"
}
