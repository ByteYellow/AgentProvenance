package agentcontext_test

import (
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/dashboard"
	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/staticdata"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func forkRoundtripService(t *testing.T) agentcontext.Service {
	t.Helper()
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return agentcontext.Service{DB: db, Paths: paths}
}

func TestSessionForkSignedRoundtrip(t *testing.T) {
	for _, preset := range []string{"basic", "detailed"} {
		t.Run(preset, func(t *testing.T) {
			ctx := context.Background()
			src := forkRoundtripService(t)
			policy, err := agentcontext.NewCapturePolicy(preset, nil)
			if err != nil {
				t.Fatal(err)
			}
			src.CapturePolicy = &policy
			for _, fixture := range []struct{ run, input string }{
				{"parent-a", `{"type":"session_meta","payload":{"id":"root"}}`},
				{"parent-b", `{"type":"session_meta","payload":{"id":"root"}}`},
				{"child", `{"timestamp":"2026-10-19T00:00:00Z","type":"session_meta","payload":{"id":"branch","forked_from_id":"root","instructions":"private configuration"}}`},
			} {
				parsed, err := agentcontext.Parse(ctx, strings.NewReader(fixture.input), agentcontext.ParseOptions{Harness: "codex", Binding: "explicit"})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := src.Save(ctx, fixture.run, parsed.Source, parsed.Records, parsed.Coverage); err != nil {
					t.Fatal(err)
				}
			}
			opts := agentcontext.SessionRelationOptions{RunID: "child", Harness: "codex", SessionID: "branch"}
			before, err := src.SessionRelations(ctx, opts)
			if err != nil || len(before.Relations) != 1 || len(before.Relations[0].From.RunIDs) != 2 {
				t.Fatalf("source fork: %+v %v", before, err)
			}
			selectedOpts := opts
			selectedOpts.VisibleRuns = []string{"child"}
			selected, err := src.SessionRelations(ctx, selectedOpts)
			if err != nil || len(selected.Relations) != 1 || selected.Relations[0].From.Available {
				t.Fatalf("selected-run visibility: %+v %v", selected, err)
			}
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			bundles := map[string]string{}
			for _, run := range []string{"child", "parent-a", "parent-b"} {
				bundle, err := (forensics.Service{DB: src.DB, Paths: src.Paths, SignKey: key}).ExportBundle(run)
				if err != nil || !bundle.Signed {
					t.Fatalf("signed export: %+v %v", bundle, err)
				}
				if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, pub); err != nil {
					t.Fatal(err)
				}
				bundles[run] = bundle.Path
			}
			if err := src.DB.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(src.Paths.Provenance, src.Paths.Provenance+"-offline"); err != nil {
				t.Fatal(err)
			}
			dst := forkRoundtripService(t)
			for _, run := range []string{"child", "parent-a", "parent-b"} {
				result, err := (forensics.Service{DB: dst.DB, Paths: dst.Paths}).ImportBundle(bundles[run])
				if err != nil || result.Omitted != 0 {
					t.Fatalf("import %s: %+v %v", run, result, err)
				}
				if v, err := provenance.Verify(dst.DB, run); err != nil || v.ErrorCount != 0 {
					t.Fatalf("offline provenance %s: %+v %v", run, v, err)
				}
				if run == "child" {
					page, err := dst.SessionRelations(ctx, selectedOpts)
					if err != nil || !reflect.DeepEqual(page, selected) {
						t.Fatalf("selected-only fork/ref changed: %+v want %+v: %v", page, selected, err)
					}
				}
			}
			after, err := dst.SessionRelations(ctx, opts)
			if err != nil || !reflect.DeepEqual(after, before) {
				t.Fatalf("offline fork endpoints/type/evidence changed: %+v want %+v: %v", after, before, err)
			}
			stillSelected, err := dst.SessionRelations(ctx, selectedOpts)
			if err != nil || !reflect.DeepEqual(stillSelected, selected) {
				t.Fatalf("private imports widened selected-run visibility: %+v %v", stillSelected, err)
			}
			ev := after.Relations[0].Evidence[0]
			var entry agentcontext.Entry
			if err := provenance.ReadObjectPayload(dst.DB, ev.RunID, ev.ObjectHash, &entry); err != nil {
				t.Fatal(err)
			}
			if entry.ID != ev.EntryID || entry.SessionMetadata == nil || entry.SessionMetadata.ForkedFromID != "root" {
				t.Fatalf("offline typed metadata/evidence lost: %+v", entry)
			}
			if preset == "basic" && (entry.Content.State != "omitted" || entry.RawContent.State != "omitted" || entry.Content.Ref != "" || entry.RawContent.Ref != "") {
				t.Fatalf("offline basic reconstructed omitted bodies: %+v", entry)
			}
			for _, visible := range [][]string{{"child"}, {"child", "parent-a", "parent-b"}} {
				root := t.TempDir()
				replay, err := (dashboard.Server{DB: dst.DB}).ExportReplaySet(ctx, "child", &staticdata.Writer{Root: root}, visible)
				if err != nil {
					t.Fatal(err)
				}
				session, ok := replay.Sessions[`["codex","branch"]`]
				if !ok || len(session.Relations) != 1 {
					t.Fatalf("export omitted fork session/relations: %+v", replay.Sessions)
				}
				file, err := os.Open(filepath.Join(root, session.Relations[""].Path))
				if err != nil {
					t.Fatal(err)
				}
				gz, err := gzip.NewReader(file)
				if err != nil {
					file.Close()
					t.Fatal(err)
				}
				var exported agentcontext.SessionRelationsPage
				err = json.NewDecoder(gz).Decode(&exported)
				gz.Close()
				file.Close()
				want := before
				if len(visible) == 1 {
					want = selected
				}
				if err != nil || !reflect.DeepEqual(exported, want) {
					t.Fatalf("selective replay fork/ref boundary %v: %+v want %+v: %v", visible, exported, want, err)
				}
			}
		})
	}
}
