package dashboard

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/browserlink"
	"github.com/byteyellow/agentprovenance/internal/hooksbridge"
)

func TestReplayBrowserLayersRecomputeAfterAnchorExclusion(t *testing.T) {
	paths, db, _ := artifactStore(t)
	ctx := context.Background()
	input := `{"type":"browser_session","schema_version":"agentprovenance.browser_capture/v1","producer_id":"p","namespace":"n","instance_id":"i","generation":"g","browser_id":"b","context_id":"c"}
{"type":"browser_event","schema_version":"agentprovenance.browser_capture/v1","context_id":"c","event_id":"start","kind":"action_start","target_id":"page","target_type":"page","cdp_session_id":"cdp","operation_id":"op","operation":"navigate","payload":{"url":"https://example.test/"}}
{"type":"browser_event","schema_version":"agentprovenance.browser_capture/v1","context_id":"c","event_id":"end","kind":"action_end","target_id":"page","target_type":"page","cdp_session_id":"cdp","operation_id":"op","operation":"navigate","request_id":"req","payload":{"url":"https://example.test/EXCLUDED_ANCHOR_BODY"}}
{"type":"browser_event","schema_version":"agentprovenance.browser_capture/v1","context_id":"c","event_id":"request","kind":"request","target_id":"page","target_type":"page","cdp_session_id":"cdp","request_id":"req","payload":{"url":"https://example.test/","method":"GET"}}
{"type":"browser_event","schema_version":"agentprovenance.browser_capture/v1","context_id":"c","event_id":"response","kind":"response","target_id":"page","target_type":"page","cdp_session_id":"cdp","request_id":"req","payload":{"status":200}}
`
	parsed, err := agentcontext.Parse(ctx, strings.NewReader(input), agentcontext.ParseOptions{Harness: "browser", Binding: "explicit"})
	if err != nil {
		t.Fatal(err)
	}
	svc := agentcontext.Service{DB: db, Paths: paths}
	if _, err := svc.Save(ctx, "browser-layers", parsed.Source, parsed.Records, parsed.Coverage); err != nil {
		t.Fatal(err)
	}
	if _, err := hooksbridge.IngestContext(ctx, db, paths, "browser-layers"); err != nil {
		t.Fatal(err)
	}
	page, err := svc.Entries(ctx, agentcontext.PageOptions{RunID: "browser-layers"})
	if err != nil {
		t.Fatal(err)
	}
	var anchor, request agentcontext.Entry
	for _, e := range page.Entries {
		if e.Browser != nil && e.Browser.EventID == "end" {
			anchor = e
		}
		if e.Browser != nil && e.Browser.EventID == "request" {
			request = e
		}
	}
	if anchor.ID == "" || request.ID == "" {
		t.Fatal("missing explicit anchor fixture")
	}
	for _, tc := range []struct {
		name                                 string
		excluded                             agentcontext.Entry
		action, lifecycle, unresolved, start bool
	}{
		{"complete", agentcontext.Entry{}, true, true, false, true},
		{"exclude_operation_result", anchor, false, true, false, false},
		{"exclude_request_support", request, false, false, true, true},
	} {
		selection := ReplaySelection{RunID: "browser-layers", Scope: "whole_run"}
		if tc.excluded.ID != "" {
			selection.ExcludeRecords = []string{"entry/" + tc.excluded.ID}
		}
		prepared, err := (Server{DB: db}).PrepareOfflineReplaySet(ctx, []ReplaySelection{selection})
		if err != nil {
			t.Fatal(err)
		}
		files, all := replayZIPData(t, prepared)
		prepared.Close()
		if tc.excluded.ID == anchor.ID && strings.Contains(all, "EXCLUDED_ANCHOR_BODY") {
			t.Fatal("excluded anchor body leaked")
		}
		foundAction, foundLifecycle, foundUnresolved, foundStart := false, false, false, false
		var walk func(any)
		walk = func(v any) {
			switch x := v.(type) {
			case map[string]any:
				if x["derivation_rule"] == browserlink.NativeRule {
					if x["edge_type"] == "browser_action_request" {
						foundAction = true
					}
					if x["edge_type"] == "browser_request_lifecycle" {
						foundLifecycle = true
					}
					if tc.excluded.ID != "" {
						for _, ref := range x["evidence_refs"].([]any) {
							if ref == tc.excluded.ObjectHash {
								t.Fatal("removed support retained in derived edge")
							}
						}
					}
				}
				if x["reason"] == "action_effect_requires_explicit_native_reference" {
					foundUnresolved = true
				}
				for _, nested := range x {
					walk(nested)
				}
			case []any:
				for _, nested := range x {
					walk(nested)
				}
			}
		}
		for _, raw := range files {
			var v any
			if json.Unmarshal(raw, &v) == nil {
				walk(v)
			}
			var data replayContext
			if json.Unmarshal(raw, &data) == nil {
				for _, e := range data.Entries {
					if e.ID == tc.excluded.ID {
						t.Fatal("excluded source record retained")
					}
					if e.Browser != nil && e.Browser.Kind == "action_start" {
						foundStart = true
					}
				}
			}
		}
		if foundAction != tc.action || foundLifecycle != tc.lifecycle || foundUnresolved != tc.unresolved || foundStart != tc.start {
			t.Fatalf("selected layers %s action=%v lifecycle=%v unresolved=%v start=%v", tc.name, foundAction, foundLifecycle, foundUnresolved, foundStart)
		}
	}
}
