package dashboard

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
)

func TestReplayHARRequestExclusion(t *testing.T) {
	ctx := context.Background()
	paths, db, _ := artifactStore(t)
	scope := map[string]any{"producer_id": "lab", "namespace": "team", "instance_id": "vm", "generation": "g1", "browser_id": "browser", "context_id": "context"}
	header := map[string]any{"schema_version": agentcontext.BrowserCaptureVersion, "type": "browser_session"}
	for k, v := range scope {
		header[k] = v
	}
	request := map[string]any{"schema_version": agentcontext.BrowserCaptureVersion, "type": "browser_event", "kind": "request", "event_id": "req", "context_id": "context",
		"target_id": "page", "target_type": "page", "cdp_session_id": "cdp", "request_id": "native", "redirect_index": 0, "payload": map[string]any{"url": "https://example.test/private", "method": "GET"}}
	archive := map[string]any{"schema_version": agentcontext.BrowserCaptureVersion, "type": "browser_event", "kind": "har", "event_id": "har", "context_id": "context",
		"har": map[string]any{"log": map[string]any{"version": "1.2", "_agentprovenance": map[string]any{"scope": scope, "capture_state": "closed", "omitted_entries": 0},
			"entries": []any{map[string]any{"startedDateTime": "2026-11-15T10:00:00Z", "request": map[string]any{"url": "https://example.test/private", "method": "GET"},
				"_agentprovenance": map[string]any{"target_id": "page", "target_type": "page", "cdp_session_id": "cdp", "request_id": "native", "redirect_index": 0, "outcome": "pending"}}}}}}
	var input strings.Builder
	for _, v := range []map[string]any{header, request, archive} {
		raw, _ := json.Marshal(v)
		input.Write(raw)
		input.WriteByte('\n')
	}
	parsed, err := agentcontext.Parse(ctx, strings.NewReader(input.String()), agentcontext.ParseOptions{Harness: "browser", Binding: "explicit"})
	if err != nil {
		t.Fatal(err)
	}
	svc := agentcontext.Service{DB: db, Paths: paths}
	if _, err := svc.Save(ctx, "har", parsed.Source, parsed.Records, parsed.Coverage); err != nil {
		t.Fatal(err)
	}
	entries, err := svc.Entries(ctx, agentcontext.PageOptions{RunID: "har"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries.Entries) != 3 || entries.Entries[2].Attachments[0].State != "stored" {
		t.Fatal("HAR fixture not retained")
	}
	for _, exclude := range []bool{false, true} {
		selection := ReplaySelection{RunID: "har", Scope: "whole_run"}
		want := 1
		if exclude {
			selection.ExcludeRecords = []string{"entry/" + entries.Entries[1].ID}
			want = 0
		}
		prepared, err := (Server{DB: db}).PrepareOfflineReplaySet(ctx, []ReplaySelection{selection})
		if err != nil {
			t.Fatal(err)
		}
		defer prepared.Close()
		if prepared.Inventory.Contents.AttachmentRefs != want {
			t.Fatalf("excluded=%v: HAR count=%d, want %d", exclude, prepared.Inventory.Contents.AttachmentRefs, want)
		}
		if exclude {
			files, _ := replayZIPData(t, prepared)
			for _, data := range files {
				if strings.Contains(string(data), `"media_type":"application/har+json","encoding":"base64"`) {
					t.Fatal("excluded request survived in HAR bytes")
				}
			}
		}
	}
}
