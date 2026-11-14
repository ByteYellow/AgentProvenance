package dashboard

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/hooksbridge"
)

func TestReplayNotebookRequestSelection(t *testing.T) {
	paths, db, _ := artifactStore(t)
	ctx := context.Background()
	svc := agentcontext.Service{DB: db, Paths: paths}
	scope := `"producer_id":"p","namespace":"n","instance_id":"i","generation":"g","notebook_id":"nb","kernel_id":"k","kernel_session_id":"ks"`
	inputs := map[string]string{
		"jupyter": `{"type":"notebook_session","schema_version":"agentprovenance.jupyter_capture/v1",` + scope + `}` + "\n" +
			`{"type":"notebook_message","schema_version":"agentprovenance.jupyter_capture/v1","channel":"shell","direction":"send","message":{"header":{"version":"5.3","msg_type":"execute_request","session":"front","msg_id":"req"},"parent_header":{},"content":{"code":"PRIVATE_KERNEL_BODY"}}}` + "\n",
		"claude": `{"session_id":"agent","hook_event_name":"PreToolUse","tool_use_id":"call","tool_name":"mcp__notebook__notebook_execute","tool_input":{"code":"execute notebook"}}` + "\n" +
			`{"session_id":"agent","hook_event_name":"PostToolUse","tool_use_id":"call","tool_name":"mcp__notebook__notebook_execute","tool_response":{"schema_version":"agentprovenance.notebook_tool_result/v1","operation":"execute","notebook_request":{"scope":{` + scope + `},"message_session":"front","message_id":"req"}}}` + "\n",
	}
	for harness, raw := range inputs {
		parsed, err := agentcontext.Parse(ctx, strings.NewReader(raw), agentcontext.ParseOptions{Harness: harness, Binding: "explicit"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Save(ctx, "notebook", parsed.Source, parsed.Records, parsed.Coverage); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := hooksbridge.IngestContext(ctx, db, paths, "notebook"); err != nil {
		t.Fatal(err)
	}
	page, err := svc.Entries(ctx, agentcontext.PageOptions{RunID: "notebook"})
	if err != nil {
		t.Fatal(err)
	}
	var request, caller agentcontext.Entry
	for _, e := range page.Entries {
		if e.Kind == "tool_call" && e.Source.Harness == "jupyter" {
			request = e
		}
		if e.NotebookRequest != nil {
			caller = e
		}
	}
	if request.ID == "" || caller.ID == "" {
		t.Fatal("missing fixture entries")
	}
	for _, excluded := range []bool{false, true} {
		selection := ReplaySelection{RunID: "notebook", Scope: "whole_run"}
		if excluded {
			selection.ExcludeRecords = []string{"entry/" + request.ID}
		}
		prepared, err := (Server{DB: db}).PrepareOfflineReplaySet(ctx, []ReplaySelection{selection})
		if err != nil {
			t.Fatal(err)
		}
		defer prepared.Close()
		files, _ := replayZIPData(t, prepared)
		found := false
		for _, raw := range files {
			if excluded && strings.Contains(string(raw), "PRIVATE_KERNEL_BODY") {
				t.Fatal("excluded Notebook body leaked")
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
				if link.Relation == "context_notebook_request" {
					count++
				}
			}
			if excluded && (count != 0 || links.Reason != "notebook_request_unresolved") || !excluded && count != 1 {
				t.Fatalf("selected links: excluded=%v %+v", excluded, links)
			}
		}
		if !found {
			t.Fatal("exported context link index missing")
		}
	}
}
