package dashboard

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/hooksbridge"
)

func TestReplayBrowserOperationSelection(t *testing.T) {
	paths, db, _ := artifactStore(t)
	ctx := context.Background()
	svc := agentcontext.Service{DB: db, Paths: paths}
	scope := `"producer_id":"p","namespace":"n","instance_id":"i","generation":"g","browser_id":"b","context_id":"c"`
	inputs := map[string]string{
		"browser": `{"type":"browser_session","schema_version":"agentprovenance.browser_capture/v1",` + scope + `}` + "\n" +
			`{"type":"browser_event","schema_version":"agentprovenance.browser_capture/v1","context_id":"c","event_id":"start","kind":"action_start","target_id":"page","target_type":"page","cdp_session_id":"cdp","operation_id":"op","operation":"navigate","payload":{"url":"https://example.test/PRIVATE_BROWSER_BODY"}}` + "\n",
		"claude": `{"session_id":"agent","hook_event_name":"PreToolUse","tool_use_id":"call","tool_name":"mcp__browser__browser_execute","tool_input":{"action":"navigate"}}` + "\n" +
			`{"session_id":"agent","hook_event_name":"PostToolUse","tool_use_id":"call","tool_name":"mcp__browser__browser_execute","tool_response":{"schema_version":"agentprovenance.browser_tool_result/v1","operation":"execute","browser_operation":{"scope":{` + scope + `},"target_id":"page","operation_id":"op","operation":"navigate"}}}` + "\n",
	}
	for harness, raw := range inputs {
		parsed, err := agentcontext.Parse(ctx, strings.NewReader(raw), agentcontext.ParseOptions{Harness: harness, Binding: "explicit"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Save(ctx, "browser", parsed.Source, parsed.Records, parsed.Coverage); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := hooksbridge.IngestContext(ctx, db, paths, "browser"); err != nil {
		t.Fatal(err)
	}
	page, err := svc.Entries(ctx, agentcontext.PageOptions{RunID: "browser"})
	if err != nil {
		t.Fatal(err)
	}
	var operation, caller agentcontext.Entry
	for _, e := range page.Entries {
		if e.Kind == "tool_call" && e.Source.Harness == "browser" {
			operation = e
		}
		if e.BrowserOperation != nil {
			caller = e
		}
	}
	if operation.ID == "" || caller.ID == "" {
		t.Fatal("missing fixture entries")
	}
	for _, excluded := range []bool{false, true} {
		selection := ReplaySelection{RunID: "browser", Scope: "whole_run"}
		if excluded {
			selection.ExcludeRecords = []string{"entry/" + operation.ID}
		}
		prepared, err := (Server{DB: db}).PrepareOfflineReplaySet(ctx, []ReplaySelection{selection})
		if err != nil {
			t.Fatal(err)
		}
		defer prepared.Close()
		files, _ := replayZIPData(t, prepared)
		found := false
		for _, raw := range files {
			if excluded && strings.Contains(string(raw), "PRIVATE_BROWSER_BODY") {
				t.Fatal("excluded Browser body leaked")
			}
			var contextData replayContext
			if json.Unmarshal(raw, &contextData) != nil || contextData.Links == nil {
				continue
			}
			links, exists := contextData.Links[caller.ID]
			if !exists {
				continue
			}
			found = true
			count := 0
			for _, link := range links.Links {
				if link.Relation == "context_browser_operation" {
					count++
				}
			}
			if excluded && (count != 0 || links.Reason != "browser_operation_unresolved") || !excluded && count != 1 {
				t.Fatalf("selected links: excluded=%v %+v", excluded, links)
			}
		}
		if !found {
			t.Fatal("exported context link index missing")
		}
	}
}
