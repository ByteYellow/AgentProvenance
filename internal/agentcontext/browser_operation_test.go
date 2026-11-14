package agentcontext

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const browserToolResultFixture = `{"schema_version":"agentprovenance.browser_tool_result/v1","operation":"execute","browser_operation":{"scope":{"producer_id":"p","namespace":"n","instance_id":"i","generation":"g","browser_id":"b","context_id":"c"},"target_id":"page","operation_id":"op","operation":"navigate"},"execution_status":"ok","output":{"text":"PRIVATE-OUTPUT"}}`

func TestBrowserMCPReferenceSurvivesBasicHookRetention(t *testing.T) {
	for _, preset := range []string{"basic", "detailed"} {
		t.Run(preset, func(t *testing.T) {
			s := testService(t)
			s.CapturePolicy = capturePreset(t, preset, nil)
			hook := `{"session_id":"s","hook_event_name":"PostToolUse","tool_use_id":"call","tool_name":"mcp__browser__browser_execute","tool_response":{"structuredContent":` + browserToolResultFixture + `}}`
			retained, err := RetainHookEvent([]byte(hook), *s.CapturePolicy)
			if err != nil {
				t.Fatal(err)
			}
			if preset == "basic" && strings.Contains(string(retained), "PRIVATE-OUTPUT") {
				t.Fatal("basic retained output")
			}
			p := parseFixture(t, "claude", string(retained)+"\n")
			if _, err := s.Save(context.Background(), "run", p.Source, p.Records, p.Coverage); err != nil {
				t.Fatal(err)
			}
			page, err := s.Entries(context.Background(), PageOptions{RunID: "run"})
			if err != nil || len(page.Entries) != 1 {
				t.Fatalf("entries: %+v %v", page, err)
			}
			raw, _ := json.Marshal(page.Entries[0])
			var entry map[string]json.RawMessage
			_ = json.Unmarshal(raw, &entry)
			if !strings.Contains(string(entry["browser_operation"]), `"operation_id":"op"`) {
				t.Fatalf("native Browser operation reference missing: %s", raw)
			}
			if preset == "basic" && page.Entries[0].Content.State != "omitted" {
				t.Fatal("basic result body retained")
			}
		})
	}
}

func TestBrowserOperationExactScopeAndConflicts(t *testing.T) {
	ref := browserResultReference([]byte(browserToolResultFixture))
	caller := Entry{ID: "caller", RunID: "run", Kind: "tool_result", ToolCallID: "native-call",
		ToolName: "mcp__browser__browser_execute", BrowserOperation: ref,
		Source: Source{Harness: "claude", SessionID: "agent"}}
	operation := Entry{ID: "operation", RunID: "run", Kind: "tool_call", ToolCallID: "browser-call",
		Source:  Source{Harness: "browser", SessionID: "context", Browser: &ref.Scope},
		Browser: &BrowserEvent{Kind: "action_start", TargetID: ref.TargetID, OperationID: ref.OperationID, Operation: ref.Operation}}
	if got := BrowserAssociations([]Entry{caller, operation, caller, operation}); len(got) != 1 || got[0].Operation.ID != operation.ID {
		t.Fatalf("native association: %+v", got)
	}
	for _, field := range []string{"ProducerID", "Namespace", "InstanceID", "Generation", "BrowserID", "ContextID"} {
		t.Run(field, func(t *testing.T) {
			other, scope := operation, ref.Scope
			reflect.ValueOf(&scope).Elem().FieldByName(field).SetString("different")
			other.Source.Browser = &scope
			if len(BrowserAssociations([]Entry{caller, other})) != 0 {
				t.Fatal("joined another browser identity")
			}
		})
	}
	for _, mutate := range []func(*Entry){
		func(e *Entry) { e.RunID = "other-run" },
		func(e *Entry) { e.ExecutionScope = PriorContext },
		func(e *Entry) { e.Browser.TargetID = "other-page" },
		func(e *Entry) { e.Browser.OperationID = "other-operation" },
		func(e *Entry) { e.Browser.Operation = "click" },
		func(e *Entry) { e.Browser.Kind = "request" },
	} {
		other, event := operation, *operation.Browser
		other.Browser = &event
		mutate(&other)
		if len(BrowserAssociations([]Entry{caller, other})) != 0 {
			t.Fatal("joined unrelated operation or background request")
		}
	}
	competing := caller
	competing.ToolCallID = "other-call"
	if len(BrowserAssociations([]Entry{caller, competing, operation})) != 0 {
		t.Fatal("multiple callers silently resolved")
	}
	conflicting, otherRef := caller, *ref
	otherRef.OperationID = "other-operation"
	conflicting.ID, conflicting.BrowserOperation = "conflicting-observation", &otherRef
	if len(BrowserAssociations([]Entry{caller, conflicting, operation})) != 0 {
		t.Fatal("conflicting observations silently resolved")
	}
}

func TestBrowserOperationConflictAcrossImportedCaptures(t *testing.T) {
	ref := browserResultReference([]byte(browserToolResultFixture))
	caller := Entry{ID: "caller", RunID: "run", Kind: "tool_result", ToolCallID: "native-call",
		ToolName: "browser_execute", BrowserOperation: ref, Source: Source{Harness: "claude", SessionID: "agent"}}
	operation := Entry{ID: "first-import", RunID: "run", Kind: "tool_call", ToolCallID: "browser-call",
		Source:  Source{Harness: "browser", SessionID: "context", Browser: &ref.Scope},
		Browser: &BrowserEvent{Kind: "action_start", TargetID: ref.TargetID, CDPSessionID: "cdp", OperationID: ref.OperationID, Operation: ref.Operation}}
	for _, field := range []string{"TargetID", "CDPSessionID", "Operation"} {
		t.Run(field, func(t *testing.T) {
			other, event := operation, *operation.Browser
			other.ID, other.Browser = "second-import", &event
			value := "different"
			if field == "Operation" {
				value = "click"
			}
			reflect.ValueOf(other.Browser).Elem().FieldByName(field).SetString(value)
			if len(BrowserAssociations([]Entry{caller, operation, other})) != 0 {
				t.Fatal("conflicting native operation in separate imports silently resolved")
			}
		})
	}
}

func TestBrowserReferenceMCPEnvelopesBeforeRetention(t *testing.T) {
	encoded, _ := json.Marshal(browserToolResultFixture)
	blocks, _ := json.Marshal([]map[string]any{{"type": "text", "text": browserToolResultFixture}})
	for _, body := range []string{browserToolResultFixture, string(encoded), string(blocks),
		`{"structuredContent":` + browserToolResultFixture + `}`, `{"content":` + string(blocks) + `}`} {
		for _, preset := range []string{"basic", "detailed"} {
			hook := `{"session_id":"s","hook_event_name":"PostToolUse","tool_use_id":"call","tool_name":"mcp__browser__browser_execute","tool_response":` + body + `}`
			retained, err := RetainHookEvent([]byte(hook), *capturePreset(t, preset, nil))
			if err != nil {
				t.Fatal(err)
			}
			parsed := parseFixture(t, "claude", string(retained)+"\n")
			if len(parsed.Records) != 1 || parsed.Records[0].BrowserOperation == nil || parsed.Records[0].BrowserOperation.OperationID != "op" {
				t.Fatal("MCP result lost native operation reference")
			}
			if preset == "basic" && strings.Contains(string(retained), "PRIVATE-OUTPUT") {
				t.Fatal("basic retained output")
			}
		}
	}
	for _, invalid := range []string{
		strings.ReplaceAll(browserToolResultFixture, `"execute"`, `"read"`),
		strings.ReplaceAll(browserToolResultFixture, `/v1`, `/future`),
		strings.ReplaceAll(browserToolResultFixture, `"generation":"g"`, `"generation":""`),
		`{"unrelated":` + browserToolResultFixture + `}`,
	} {
		if browserResultReference([]byte(invalid)) != nil {
			t.Fatal("read or invalid result became an execution reference")
		}
	}
}
