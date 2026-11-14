package agentcontext

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

func browserHARFixture() map[string]any {
	scope := map[string]any{}
	for _, key := range []string{"producer_id", "namespace", "instance_id", "generation", "browser_id", "context_id"} {
		scope[key] = browserHeader()[key]
	}
	return map[string]any{"log": map[string]any{"version": "1.2", "creator": map[string]any{"name": "AgentProvenance", "version": "1"},
		"_agentprovenance": map[string]any{"scope": scope, "capture_state": "closed", "omitted_entries": 0},
		"entries": []any{map[string]any{
			"startedDateTime": "2026-11-15T10:00:01Z", "time": 999,
			"request": map[string]any{"method": "GET", "url": "https://user:PRIVATE@example.test/data?token=PRIVATE#PRIVATE",
				"headers": []any{map[string]string{"name": "Authorization", "value": "PRIVATE"}}, "postData": map[string]string{"text": "PRIVATE"}},
			"response": map[string]any{"status": 200, "httpVersion": "h2", "content": map[string]any{"size": -1, "mimeType": "text/plain", "text": "PRIVATE"}},
			"timings":  map[string]any{"blocked": -1, "dns": -1, "connect": -1, "ssl": -1, "send": 1, "wait": 2, "receive": 3},
			"_agentprovenance": map[string]any{"target_id": "page-a", "target_type": "page", "cdp_session_id": "cdp-page-a",
				"request_id": "request-1", "redirect_index": 0, "outcome": "finished", "observed_duration_ms": 7},
		}}}}
}

func TestBrowserHARAttachmentRetention(t *testing.T) {
	event := map[string]any{"type": "browser_event", "schema_version": BrowserCaptureVersion, "event_id": "har",
		"kind": "har", "context_id": "context-1", "har": browserHARFixture()}
	p := parseBrowser(t, browserHeader(), browserEvent("request", "request", "page-a", "request-1"), event)
	if len(p.Records) != 3 || len(p.Records[2].Attachments) != 1 {
		t.Fatalf("HAR attachment missing: records=%d", len(p.Records))
	}
	for _, preset := range []string{"basic", "detailed"} {
		t.Run(preset, func(t *testing.T) {
			svc := testService(t)
			policy, _ := NewCapturePolicy(preset, nil)
			svc.CapturePolicy = &policy
			if _, err := svc.Save(context.Background(), "run", p.Source, p.Records, p.Coverage); err != nil {
				t.Fatal(err)
			}
			page, err := svc.Entries(context.Background(), PageOptions{RunID: "run"})
			if err != nil {
				t.Fatal(err)
			}
			a := page.Entries[2].Attachments[0]
			if preset == "basic" {
				if a.State != "omitted" || a.Reason != "capture_policy" {
					t.Fatalf("basic: %+v", a)
				}
				return
			}
			if a.State != "stored" || a.MediaType != "application/har+json" {
				t.Fatalf("detailed: %+v", a)
			}
			if err := provenance.VerifyAttachment(context.Background(), svc.DB, "run", a.Ref); err != nil {
				t.Fatal(err)
			}
			var body bytes.Buffer
			for offset := int64(0); ; {
				part, err := provenance.ReadAttachmentPage(context.Background(), svc.DB, "run", a.Ref, offset, 13)
				if err != nil {
					t.Fatal(err)
				}
				body.Write(part.Data)
				if part.SchemaVersion != provenance.HARAttachmentSchema || part.MediaType != a.MediaType {
					t.Fatal("wrong HAR page contract")
				}
				if !part.HasMore {
					break
				}
				offset = part.NextOffset
			}
			if strings.Contains(body.String(), "PRIVATE") {
				t.Fatal("HAR transport secrets persisted")
			}
			var h provenance.HAR
			if json.Unmarshal(body.Bytes(), &h) != nil || len(h.Log.Entries) != 1 || h.Log.Entries[0].Time != 6 || h.Log.Entries[0].Native.Request != "request-1" {
				t.Fatal("HAR projection changed native evidence")
			}
			if strings.Contains(*p.Records[2].RawBody, "PRIVATE") {
				t.Fatal("HAR leaked into raw text")
			}
			encoded, _ := json.Marshal(page)
			if strings.Contains(string(encoded), "PRIVATE") {
				t.Fatal("HAR leaked into entry metadata")
			}
		})
	}
}

func TestBrowserHARValidation(t *testing.T) {
	for _, mode := range []string{"scope", "unobserved", "frame", "duplicate", "negative_time", "overflow", "no_entries", "missing_timing", "disabled", "incomplete"} {
		t.Run(mode, func(t *testing.T) {
			doc := browserHARFixture()
			log := doc["log"].(map[string]any)
			entry := log["entries"].([]any)[0].(map[string]any)
			meta := log["_agentprovenance"].(map[string]any)
			switch mode {
			case "scope":
				meta["scope"].(map[string]any)["generation"] = "other"
			case "unobserved":
				entry["_agentprovenance"].(map[string]any)["request_id"] = "unobserved"
			case "frame":
				entry["_agentprovenance"].(map[string]any)["frame_id"] = "another-frame"
			case "duplicate":
				log["entries"] = []any{entry, entry}
			case "negative_time":
				entry["timings"].(map[string]any)["send"] = -.5
			case "overflow":
				log["entries"] = make([]any, 4097)
			case "no_entries":
				delete(log, "entries")
			case "missing_timing":
				delete(entry, "timings")
			case "incomplete":
				meta["capture_state"] = "incomplete"
				meta["omitted_entries"] = 3
			}
			event := map[string]any{"type": "browser_event", "schema_version": BrowserCaptureVersion, "event_id": "har", "kind": "har", "context_id": "context-1", "har": doc}
			if mode == "disabled" {
				event["har"] = nil
				event["payload"] = map[string]string{"reason": "capture_policy"}
			}
			p := parseBrowser(t, browserHeader(), browserEvent("req", "request", "page-a", "request-1"), event)
			if len(p.Records) != 3 {
				t.Fatal("invalid archive removed unrelated native records")
			}
			a := p.Records[2].Attachments[0]
			switch mode {
			case "disabled":
				if a.Reason != "capture_policy" || p.Coverage.Status != OK {
					t.Fatalf("disabled: %+v", p.Coverage)
				}
			case "missing_timing":
				h, _, err := provenance.ProjectHAR(context.Background(), a.Data)
				if err != nil || h.Log.Entries[0].Timings.Wait != -1 || h.Log.Entries[0].Time != 0 {
					t.Fatal("unmeasured timings became measured zero", err)
				}
			case "incomplete":
				if p.Coverage.Status != Partial || *p.Coverage.Counts.Truncated != 1 {
					t.Fatal("HAR truncation hidden")
				}
			default:
				if a.Reason == "" || a.Data != nil || *p.Coverage.Counts.Failed != 1 {
					t.Fatal("invalid HAR accepted", mode)
				}
			}
		})
	}
}

func TestBrowserHARRequestIdentityConflict(t *testing.T) {
	first := browserEvent("first", "request", "page-a", "request-1")
	second := browserEvent("second", "request", "page-a", "request-1")
	second["frame_id"] = "other-frame"
	p := parseBrowser(t, browserHeader(), first, second)
	for _, issue := range p.Coverage.Issues {
		if issue.Code == "browser_native_identity_conflict" {
			return
		}
	}
	t.Fatal("conflicting native request identity was accepted")
}
