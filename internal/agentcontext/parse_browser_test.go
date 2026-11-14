package agentcontext

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func browserHeader() map[string]any {
	return map[string]any{"type": "browser_session", "schema_version": "agentprovenance.browser_capture/v1",
		"producer_id": "lab", "namespace": "team", "instance_id": "vm", "generation": "g1",
		"browser_id": "browser-1", "context_id": "context-1", "browser_version": "Chromium/159",
		"playwright_version": "1.65.2", "timestamp": "2026-11-15T10:00:00Z"}
}

func browserEvent(id, kind, target, request string) map[string]any {
	return map[string]any{"type": "browser_event", "schema_version": "agentprovenance.browser_capture/v1",
		"event_id": id, "kind": kind, "target_id": target, "target_type": "page", "cdp_session_id": "cdp-" + target,
		"context_id": "context-1", "request_id": request, "timestamp": "2026-11-15T10:00:01Z",
		"payload": map[string]any{"url": "http://example.test/data", "method": "GET"}}
}

func parseBrowser(t *testing.T, values ...map[string]any) Parsed {
	t.Helper()
	var b strings.Builder
	for _, value := range values {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(raw)
		b.WriteByte('\n')
	}
	p, err := Parse(context.Background(), strings.NewReader(b.String()), ParseOptions{Harness: "browser", Binding: "explicit"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBrowserCaptureImport(t *testing.T) {
	p := parseBrowser(t, browserHeader(), browserEvent("event-1", "request", "page-a", "request-1"))
	if p.Coverage.Status != OK || len(p.Records) != 2 || p.Source.Channel != "chromium_cdp" {
		t.Fatalf("browser capture unavailable: %+v", p)
	}
}

func TestBrowserNativeIdentityRetentionAndPrivacy(t *testing.T) {
	a := browserEvent("a", "request", "page-a", "same-id")
	b := browserEvent("b", "request", "page-b", "same-id")
	redirect := browserEvent("redirect", "request", "page-a", "same-id")
	redirect["redirect_index"] = 1
	response := browserEvent("response", "response", "page-a", "same-id")
	response["redirect_index"] = 1
	a["operation_id"] = "DO_NOT_BORROW_NEARBY_CLICK"
	a["payload"] = map[string]any{"url": "https://user:PASSWORD@example.test/file?TOKEN=QUERY_SECRET#FRAGMENT_SECRET",
		"headers": map[string]string{"authorization": "HEADER_SECRET", "cookie": "COOKIE_SECRET"}, "postData": "BODY_SECRET", "method": "GET"}
	p := parseBrowser(t, browserHeader(), a, b, redirect, response)
	keys := []string{}
	for _, r := range p.Records[1:] {
		if r.ToolCallID != "" || r.Browser.OperationID != "" || r.Browser.Association != "native_request" {
			t.Fatal("network observation became a tool execution")
		}
		keys = append(keys, r.Browser.RequestKey)
	}
	if keys[0] == keys[1] || keys[0] == keys[2] || keys[2] != keys[3] {
		t.Fatalf("page or redirect identity collision: %v", keys)
	}
	for _, r := range p.Records[1:] {
		if strings.Contains(*r.RawBody, "SECRET") || strings.Contains(*r.Body, "SECRET") || strings.Contains(*r.RawBody, "PASSWORD") {
			t.Fatal("browser projection retained private transport fields")
		}
	}
	var previous []Entry
	for _, preset := range []string{"basic", "detailed"} {
		svc := testService(t)
		policy, _ := NewCapturePolicy(preset, nil)
		svc.CapturePolicy = &policy
		for i := 0; i < 2; i++ {
			saved, err := svc.Save(context.Background(), "run", p.Source, p.Records, p.Coverage)
			if err != nil || i == 0 && saved.Stored != 5 || i == 1 && saved.Duplicates != 5 {
				t.Fatalf("save: %+v %v", saved, err)
			}
		}
		page, err := svc.Entries(context.Background(), PageOptions{RunID: "run"})
		if err != nil || len(page.Entries) != 5 {
			t.Fatalf("entries: %+v %v", page, err)
		}
		for i, e := range page.Entries {
			if !reflect.DeepEqual(e.Source.Browser, p.Source.Browser) || !reflect.DeepEqual(e.Browser, p.Records[i].Browser) {
				t.Fatal("native browser identity changed")
			}
			if previous != nil && !reflect.DeepEqual(previous[i].Browser, e.Browser) {
				t.Fatal("retention changed browser identity")
			}
		}
		if preset == "basic" && page.Entries[1].RawContent.State != "omitted" {
			t.Fatal("basic retained full browser record")
		}
		previous = page.Entries
	}
}

func TestBrowserScopeConflictsAndWorker(t *testing.T) {
	base := parseBrowser(t, browserHeader())
	for _, field := range []string{"producer_id", "namespace", "instance_id", "generation", "browser_id", "context_id"} {
		header := browserHeader()
		header[field] = "another"
		if parseBrowser(t, header).Source.SessionID == base.Source.SessionID {
			t.Fatal("browser scope field ignored: " + field)
		}
		delete(header, field)
		if p := parseBrowser(t, header); p.Coverage.Status != Failed || len(p.Records) != 0 {
			t.Fatal("missing scope accepted: " + field)
		}
	}
	a := browserEvent("same", "request", "worker", "request-1")
	a["target_type"] = "service_worker"
	p := parseBrowser(t, browserHeader(), a)
	if p.Coverage.Status != OK || p.Records[1].Browser.FrameID != "" || p.Records[1].ToolCallID != "" {
		t.Fatal("worker required a frame or borrowed an action")
	}
	b := browserEvent("same", "request", "page", "another-request")
	for _, values := range [][]map[string]any{{browserHeader(), a, b}, {browserHeader(), a, browserHeaderWithContext("another")}} {
		p := parseBrowser(t, values...)
		if p.Coverage.Status != Ambiguous || len(p.Records) != 0 {
			t.Fatal("conflicting browser source accepted")
		}
	}
	b["context_id"] = "another"
	if p := parseBrowser(t, browserHeader(), b); p.Coverage.Status != Ambiguous || len(p.Records) != 0 {
		t.Fatal("cross-context event accepted")
	}
	gap := map[string]any{"type": "browser_event", "schema_version": BrowserCaptureVersion, "event_id": "gap", "kind": "gap", "context_id": "context-1", "payload": map[string]any{"reason": "capture_budget_exceeded"}}
	if p := parseBrowser(t, browserHeader(), gap); p.Coverage.Status != Partial || *p.Coverage.Counts.Truncated != 1 {
		t.Fatal("capture gap not reported")
	}
}

func browserHeaderWithContext(id string) map[string]any {
	h := browserHeader()
	h["context_id"] = id
	return h
}

func TestBrowserConflictingNativeOwner(t *testing.T) {
	for _, mode := range []string{"operation", "cdp_session"} {
		t.Run(mode, func(t *testing.T) {
			a := browserEvent("first", "request", "page-a", "req-a")
			b := browserEvent("second", "request", "page-b", "req-b")
			if mode == "operation" {
				a["kind"], b["kind"] = "action_start", "action_end"
				a["operation_id"], b["operation_id"] = "same-operation", "same-operation"
				a["operation"], b["operation"] = "navigate", "navigate"
			} else {
				b["cdp_session_id"] = a["cdp_session_id"]
			}
			p := parseBrowser(t, browserHeader(), a, b)
			if p.Coverage.Status != Ambiguous || len(p.Records) != 0 {
				t.Fatalf("conflicting native owner accepted: %+v", p)
			}
		})
	}
}

func TestBrowserTargetTypeIsExact(t *testing.T) {
	event := browserEvent("bad-target", "request", "page-a", "req-a")
	event["target_type"] = "page|iframe"
	p := parseBrowser(t, browserHeader(), event)
	if len(p.Records) != 1 || *p.Coverage.Counts.Failed != 1 {
		t.Fatal("composite target type accepted")
	}
}
