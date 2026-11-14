package agentcontext

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func notebookPNG(t *testing.T) []byte {
	t.Helper()
	im := image.NewNRGBA(image.Rect(0, 0, 8, 5))
	im.Set(3, 2, color.NRGBA{R: 20, G: 150, B: 230, A: 255})
	var b bytes.Buffer
	if err := png.Encode(&b, im); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestNotebookAttachmentRetentionAndHTTP(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString(notebookPNG(t))
	p := parseNotebook(t, notebookHeader("kernel"), notebookMessage("iopub", "receive", "kernel", "chart", "display_data", "client", "request",
		map[string]any{"data": map[string]any{"image/png": encoded, "text/html": "<script>window.evidenceExecuted=1</script>"}}))
	for _, preset := range []string{"basic", "detailed", "detailed-no-attachments", "basic-with-attachments"} {
		t.Run(preset, func(t *testing.T) {
			svc := testService(t)
			policy, _ := NewCapturePolicy(strings.Split(preset, "-")[0], nil)
			if strings.Contains(preset, "no-") {
				v := false
				policy.Attachments = &v
			}
			if strings.Contains(preset, "with-") {
				v := true
				policy.Attachments = &v
			}
			svc.CapturePolicy = &policy
			for i := 0; i < 2; i++ {
				r, err := svc.Save(context.Background(), "run", p.Source, p.Records, p.Coverage)
				if err != nil || i == 1 && r.Duplicates != 2 {
					t.Fatalf("save: %+v %v", r, err)
				}
			}
			page, err := svc.Entries(context.Background(), PageOptions{RunID: "run"})
			if err != nil {
				t.Fatal(err)
			}
			a := page.Entries[1].Attachments[0]
			var count int
			if err := svc.DB.QueryRow(`SELECT COUNT(*) FROM provenance_objects WHERE object_type='attachment_content'`).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if !policy.RetainAttachments() {
				if a.State != "omitted" || a.Reason != "capture_policy" || count != 0 || a.SourceSHA256 == "" {
					t.Fatalf("omission: %+v %d", a, count)
				}
				return
			}
			if a.State != "stored" || count != 1 || a.Privacy != "visual_content_unredacted" {
				t.Fatalf("stored: %+v %d", a, count)
			}
			for _, query := range []struct {
				rangeQuery string
				code       int
			}{{"&limit=7", 200}, {"&offset=-1", 400}, {"&offset=999999", 400}, {"&limit=262145", 400}} {
				w := httptest.NewRecorder()
				svc.ReadHandler().ServeHTTP(w, httptest.NewRequest("GET", "/context/attachment?run=run&ref="+url.QueryEscape(a.Ref)+query.rangeQuery, nil))
				if w.Code != query.code {
					t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
				}
				if query.code == 200 {
					var body provenance.AttachmentPage
					if json.Unmarshal(w.Body.Bytes(), &body) != nil || len(body.Data) != 7 || body.MediaType != "image/png" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
						t.Fatal("invalid attachment API page")
					}
				}
			}
			if err := provenance.VerifyAttachment(context.Background(), svc.DB, "run", a.Ref); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNotebookRasterAttachmentFlow(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString(notebookPNG(t))
	p := parseNotebook(t, notebookHeader("kernel"), notebookMessage("iopub", "receive", "kernel", "chart",
		"display_data", "client", "request", map[string]any{"data": map[string]any{"image/png": encoded, "text/plain": "chart"}}))
	svc := testService(t)
	if _, err := svc.Save(context.Background(), "run", p.Source, p.Records, p.Coverage); err != nil {
		t.Fatal(err)
	}
	page, err := svc.Entries(context.Background(), PageOptions{RunID: "run"})
	if err != nil || len(page.Entries) != 2 {
		t.Fatalf("entries: %+v %v", page, err)
	}
	raw, _ := json.Marshal(page.Entries[1])
	var entry struct {
		Attachments []struct {
			State     string `json:"state"`
			Ref       string `json:"ref"`
			MediaType string `json:"media_type"`
		} `json:"attachments"`
	}
	if err := json.Unmarshal(raw, &entry); err != nil {
		t.Fatal(err)
	}
	if len(entry.Attachments) != 1 || entry.Attachments[0].State != "stored" || entry.Attachments[0].MediaType != "image/png" || entry.Attachments[0].Ref == "" {
		t.Fatalf("native image output lacks a typed retained attachment: %s", raw)
	}
	if strings.Contains(string(raw), encoded) || strings.Contains(*p.Records[1].Body, encoded) || strings.Contains(*p.Records[1].RawBody, encoded) {
		t.Fatal("binary data embedded in the conversation index or text")
	}
}

func TestNotebookAttachmentBudgetAcrossImports(t *testing.T) {
	ctx := context.Background()
	lines := []map[string]any{notebookHeader("kernel")}
	for i := 0; i <= provenance.MaxAttachmentCount; i++ {
		im := image.NewNRGBA(image.Rect(0, 0, 2, 2))
		im.Set(0, 0, color.NRGBA{R: byte(i), G: byte(i >> 8), A: 255})
		var data bytes.Buffer
		if err := png.Encode(&data, im); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, notebookMessage("iopub", "receive", "kernel", fmt.Sprintf("chart-%d", i), "display_data", "client", "request",
			map[string]any{"data": map[string]any{"image/png": base64.StdEncoding.EncodeToString(data.Bytes())}}))
	}
	p := parseNotebook(t, lines...)
	svc := testService(t)
	for _, records := range [][]Record{p.Records[:129], p.Records[129:]} {
		if _, err := svc.Save(ctx, "run", p.Source, records, p.Coverage); err != nil {
			t.Fatal(err)
		}
	}
	var stored int
	if err := svc.DB.QueryRow(`SELECT COUNT(*) FROM provenance_objects WHERE run_id='run' AND object_type='attachment_content'`).Scan(&stored); err != nil || stored != provenance.MaxAttachmentCount {
		t.Fatalf("persistent count budget: %d %v", stored, err)
	}
	var entries []Entry
	for cursor := ""; ; {
		page, err := svc.Entries(ctx, PageOptions{RunID: "run", Limit: 200, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, page.Entries...)
		if !page.HasMore {
			break
		}
		cursor = page.NextCursor
	}
	if len(entries) != len(p.Records) {
		t.Fatalf("entries: %d", len(entries))
	}
	last := entries[len(entries)-1].Attachments[0]
	if last.State != "omitted" || last.Reason != "run_attachment_budget" || last.Ref != "" || last.SourceSHA256 == "" {
		t.Fatalf("count limit omission: %+v", last)
	}
	if result, err := svc.Save(ctx, "run", p.Source, p.Records, p.Coverage); err != nil || result.Duplicates != len(p.Records) {
		t.Fatalf("quota changed duplicate identity: %+v %v", result, err)
	}
	input := notebookAttachment("image/png", json.RawMessage(fmt.Sprintf("%q", base64.StdEncoding.EncodeToString(notebookPNG(t)))))
	budget := attachmentBudget{known: map[string]bool{}, bytes: provenance.MaxRunAttachmentBytes - 1}
	omitted, err := budget.save(ctx, provenance.ObjectStore{DB: svc.DB, Paths: svc.Paths}, "byte-budget", input, true)
	if err != nil || omitted.Reason != "run_attachment_budget" || omitted.Ref != "" {
		t.Fatalf("byte budget: %+v %v", omitted, err)
	}
}

func TestNotebookAttachmentReferenceIntegrity(t *testing.T) {
	svc := testService(t)
	ctx := context.Background()
	p := parseNotebook(t, notebookHeader("kernel"), notebookMessage("iopub", "receive", "kernel", "chart", "display_data", "client", "request",
		map[string]any{"data": map[string]any{"image/png": base64.StdEncoding.EncodeToString(notebookPNG(t))}}))
	if _, err := svc.Save(ctx, "run", p.Source, p.Records, p.Coverage); err != nil {
		t.Fatal(err)
	}
	page, err := svc.Entries(ctx, PageOptions{RunID: "run"})
	if err != nil {
		t.Fatal(err)
	}
	entry := page.Entries[1]
	entry.Attachments[0].Width++
	payload, err := entryPayload(entry)
	if err != nil {
		t.Fatal(err)
	}
	payload["id"] = entry.ID
	object, err := (provenance.ObjectStore{DB: svc.DB, Paths: svc.Paths}).PutExternalObject(provenance.ExternalObjectInput{
		RunID: "run", Type: "agent_context", SourceID: entry.ID, Payload: payload, Parents: []string{entry.Attachments[0].Ref},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DB.Exec(`UPDATE agent_context_entries SET object_hash=? WHERE id=?`, object.Hash, entry.ID); err != nil {
		t.Fatal(err)
	}
	result, err := provenance.Verify(svc.DB, "run")
	if err != nil {
		t.Fatal(err)
	}
	for _, issue := range result.Issues {
		if issue.Kind == "context_attachment_invalid" {
			return
		}
	}
	t.Fatalf("inconsistent attachment reference was accepted: %+v", result)
}
