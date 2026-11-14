package dashboard

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func TestReplayAttachmentSelection(t *testing.T) {
	paths, db, _ := artifactStore(t)
	ctx := context.Background()
	svc := agentcontext.Service{DB: db, Paths: paths}
	header := `{"type":"notebook_session","schema_version":"agentprovenance.jupyter_capture/v1","producer_id":"lab","namespace":"team","instance_id":"vm","generation":"g1","notebook_id":"book","kernel_id":"python","kernel_session_id":"kernel"}` + "\n"
	var input strings.Builder
	input.WriteString(header)
	for i := 0; i < 2; i++ {
		im := image.NewNRGBA(image.Rect(0, 0, 8, 6))
		im.Set(0, 0, color.NRGBA{uint8(50 + i*100), 70, 240, 255})
		var pngBytes bytes.Buffer
		if err := png.Encode(&pngBytes, im); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&input, `{"type":"notebook_message","schema_version":"agentprovenance.jupyter_capture/v1","channel":"iopub","direction":"receive","message":{"header":{"session":"kernel","msg_id":"chart%d","msg_type":"display_data","version":"5.3"},"parent_header":{"session":"client","msg_id":"call%d","msg_type":"execute_request"},"content":{"data":{"image/png":%q,"text/plain":"chart %d"}}}}`+"\n", i, i, base64.StdEncoding.EncodeToString(pngBytes.Bytes()), i)
	}
	parsed, err := agentcontext.Parse(ctx, strings.NewReader(input.String()), agentcontext.ParseOptions{Harness: "jupyter", Binding: "explicit"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Save(ctx, "attachments", parsed.Source, parsed.Records, parsed.Coverage); err != nil {
		t.Fatal(err)
	}
	page, err := svc.Entries(ctx, agentcontext.PageOptions{RunID: "attachments"})
	if err != nil {
		t.Fatal(err)
	}
	ref := page.Entries[2].Attachments[0].Ref
	for _, mode := range []string{"full", "attachment", "record", "tools"} {
		t.Run(mode, func(t *testing.T) {
			selection := ReplaySelection{RunID: "attachments", Scope: "whole_run"}
			want := 2
			switch mode {
			case "attachment":
				selection.ExcludeAttachments = []string{ref}
				want = 1
			case "record":
				selection.ExcludeRecords = []string{"entry/" + page.Entries[2].ID}
				want = 1
			case "tools":
				selection.ExcludeCategories = []string{"tools"}
				want = 0
			}
			prepared, err := (Server{DB: db}).PrepareOfflineReplaySet(ctx, []ReplaySelection{selection})
			if err != nil {
				t.Fatal(err)
			}
			defer prepared.Close()
			files, _ := replayZIPData(t, prepared)
			found := map[string]bool{}
			for _, raw := range files {
				var p provenance.AttachmentPage
				if json.Unmarshal(raw, &p) == nil && p.SchemaVersion == provenance.AttachmentSchema && p.Encoding == "base64" {
					if len(p.Data) == 0 {
						t.Fatal("empty attachment shard")
					}
					found[p.Ref] = true
				}
			}
			if len(found) != want || mode != "full" && found[ref] || prepared.Inventory.Contents.AttachmentRefs != want {
				t.Fatalf("selection %s: %v %+v", mode, found, prepared.Inventory.Contents)
			}
			if mode == "attachment" && prepared.Inventory.Contents.ContextEntries != 3 {
				t.Fatal("excluding an image removed its text record")
			}
		})
	}
	if _, err := (Server{DB: db}).PrepareOfflineReplaySet(ctx, []ReplaySelection{{RunID: "attachments", Scope: "whole_run", ExcludeAttachments: []string{"sha256:" + strings.Repeat("0", 64)}}}); err == nil {
		t.Fatal("foreign attachment exclusion silently ignored")
	}
	for _, body := range []string{
		fmt.Sprintf(`{"run":"attachments","scope":"whole_run","exclude_attachments":[%q]}`, ref),
		fmt.Sprintf(`{"selections":[{"run_id":"attachments","scope":"whole_run","exclude_attachments":[%q]}]}`, ref),
	} {
		t.Run("http-preview", func(t *testing.T) {
			manager := NewReplayExports(Server{DB: db})
			defer manager.Close()
			handler := (Server{DB: db, ReplayExports: manager}).Handler()
			response := previewCall(handler, "POST", "/api/replay/previews", body)
			var preview replayPreview
			if response.Code != 201 || json.Unmarshal(response.Body.Bytes(), &preview) != nil || preview.Inventory.Contents.AttachmentRefs != 1 {
				t.Fatalf("HTTP attachment selection: %d %s", response.Code, response.Body.String())
			}
		})
	}
}
