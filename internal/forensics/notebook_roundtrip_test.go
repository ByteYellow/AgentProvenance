package forensics_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/hooksbridge"
	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func TestNotebookSignedRoundTripRetainsNativeParents(t *testing.T) {
	const input = `{"type":"notebook_session","schema_version":"agentprovenance.jupyter_capture/v1","producer_id":"lab","namespace":"team","instance_id":"vm","generation":"g1","notebook_id":"analysis","kernel_id":"python","kernel_session_id":"kernel"}
{"type":"notebook_message","schema_version":"agentprovenance.jupyter_capture/v1","channel":"shell","direction":"send","message":{"header":{"session":"client","msg_id":"c1","msg_type":"execute_request","date":"2026-11-14T10:00:00Z","version":"5.3"},"parent_header":{},"content":{"code":"print(18)"}}}
{"type":"notebook_message","schema_version":"agentprovenance.jupyter_capture/v1","channel":"shell","direction":"receive","message":{"header":{"session":"kernel","msg_id":"r1","msg_type":"execute_reply","date":"2026-11-14T10:00:01Z","version":"5.3"},"parent_header":{"session":"client","msg_id":"c1","msg_type":"execute_request"},"content":{"status":"ok","execution_count":1}}}
{"type":"notebook_message","schema_version":"agentprovenance.jupyter_capture/v1","channel":"iopub","direction":"receive","message":{"header":{"session":"kernel","msg_id":"late","msg_type":"stream","date":"2026-11-14T10:00:02Z","version":"5.3"},"parent_header":{"session":"client","msg_id":"c1","msg_type":"execute_request"},"content":{"name":"stdout","text":"late output"}}}
`
	var raster bytes.Buffer
	if err := png.Encode(&raster, image.NewGray(image.Rect(0, 0, 4, 3))); err != nil {
		t.Fatal(err)
	}
	rich := fmt.Sprintf(`{"type":"notebook_message","schema_version":"agentprovenance.jupyter_capture/v1","channel":"iopub","direction":"receive","message":{"header":{"session":"kernel","msg_id":"chart","msg_type":"display_data","version":"5.3"},"parent_header":{"session":"client","msg_id":"c1","msg_type":"execute_request"},"content":{"data":{"image/png":%q,"text/plain":"chart"}}}}`+"\n", base64.StdEncoding.EncodeToString(raster.Bytes()))
	for _, preset := range []string{"basic", "detailed"} {
		t.Run(preset, func(t *testing.T) {
			ctx := context.Background()
			paths := mustInit(t, filepath.Join(t.TempDir(), "source"))
			db := mustOpen(t, paths)
			defer db.Close()
			policy, _ := agentcontext.NewCapturePolicy(preset, nil)
			svc := agentcontext.Service{DB: db, Paths: paths, CapturePolicy: &policy}
			parsed, err := agentcontext.Parse(ctx, strings.NewReader(input+rich), agentcontext.ParseOptions{Harness: "jupyter", Binding: "explicit"})
			if err != nil || parsed.Coverage.Status != agentcontext.OK {
				t.Fatalf("parse: %+v %v", parsed.Coverage, err)
			}
			if _, err := svc.Save(ctx, "notebook", parsed.Source, parsed.Records, parsed.Coverage); err != nil {
				t.Fatal(err)
			}
			if _, err := hooksbridge.IngestContext(ctx, db, paths, "notebook"); err != nil {
				t.Fatal(err)
			}
			before, err := svc.Entries(ctx, agentcontext.PageOptions{RunID: "notebook"})
			if err != nil {
				t.Fatal(err)
			}
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key}).ExportBundle("notebook")
			if err != nil {
				t.Fatal(err)
			}
			if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, pub); err != nil {
				t.Fatal(err)
			}
			fresh := mustInit(t, filepath.Join(t.TempDir(), "offline"))
			replay := mustOpen(t, fresh)
			defer replay.Close()
			if _, err := (forensics.Service{DB: replay, Paths: fresh}).ImportBundle(bundle.Path); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(paths.Provenance, paths.Provenance+"-unavailable"); err != nil {
				t.Fatal(err)
			}
			reader := agentcontext.Service{DB: replay, Paths: fresh}
			after, err := reader.Entries(ctx, agentcontext.PageOptions{RunID: "notebook"})
			if err != nil || len(after.Entries) != 5 {
				t.Fatalf("round trip: %+v %v", after, err)
			}
			for i, e := range after.Entries {
				if !reflect.DeepEqual(e.Attachments, before.Entries[i].Attachments) {
					t.Fatal("attachment references changed")
				}
				for _, a := range e.Attachments {
					if preset == "basic" {
						if a.State != "omitted" {
							t.Fatal("basic retained pixels")
						}
						continue
					}
					if err := provenance.VerifyAttachment(ctx, replay, "notebook", a.Ref); err != nil {
						t.Fatal(err)
					}
				}
				if !reflect.DeepEqual(e.Notebook, before.Entries[i].Notebook) || !reflect.DeepEqual(e.Source, before.Entries[i].Source) || e.ToolCallID != before.Entries[i].ToolCallID {
					t.Fatal("notebook scope or native parent changed")
				}
				if e.Kind == "tool_result" {
					links, err := reader.Links(ctx, "notebook", e.ID)
					if err != nil || len(links.Links) != 1 {
						t.Fatalf("native output edge missing: %+v %v", links, err)
					}
				}
			}
			verified, err := provenance.Verify(replay, "notebook")
			if err != nil || verified.ErrorCount != 0 || verified.WarningCount != 0 {
				t.Fatalf("graph: %+v %v", verified, err)
			}
		})
	}
}
