package agentcontext

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const notebookToolResultFixture = `{"schema_version":"agentprovenance.notebook_tool_result/v1","operation":"execute","notebook_request":{"scope":{"producer_id":"p","namespace":"n","instance_id":"i","generation":"g","notebook_id":"nb","kernel_id":"k","kernel_session_id":"ks"},"message_session":"frontend","message_id":"request"},"execution_status":"ok","outputs":[{"text":"PRIVATE-OUTPUT"}]}`

func TestNotebookMCPReferenceSurvivesBasicHookRetention(t *testing.T) {
	for _, preset := range []string{"basic", "detailed"} {
		t.Run(preset, func(t *testing.T) {
			s := testService(t)
			s.CapturePolicy = capturePreset(t, preset, nil)
			hook := `{"session_id":"s","hook_event_name":"PostToolUse","tool_use_id":"native-call","tool_name":"mcp__notebook__notebook_execute","tool_response":{"structuredContent":` + notebookToolResultFixture + `}}`
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
			if !strings.Contains(string(entry["notebook_request"]), `"message_id":"request"`) {
				t.Fatalf("native MCP request reference missing: %s", raw)
			}
			if preset == "basic" && page.Entries[0].Content.State != "omitted" {
				t.Fatal("basic result body retained")
			}
		})
	}
}

func TestNotebookRequestExactScopeAndAmbiguity(t *testing.T) {
	ref := notebookResultPayload([]byte(notebookToolResultFixture))
	caller := Entry{ID: "caller-result", RunID: "run", Kind: "tool_result", ToolCallID: "native-call",
		ToolName: "mcp__notebook__notebook_execute", NotebookRequest: ref,
		Source: Source{Harness: "claude", SessionID: "agent-session"}}
	request := Entry{ID: "request", RunID: "run", Kind: "tool_call", ToolCallID: "notebook-call",
		Source: Source{Harness: "jupyter", SessionID: "notebook-session", Notebook: &ref.Scope},
		Notebook: &NotebookMessage{MessageID: ref.MessageID, MessageSession: ref.MessageSession,
			MessageType: "execute_request", Channel: "shell", Direction: "send"}}
	if got := NotebookAssociations([]Entry{caller, request, caller, request}); len(got) != 1 || got[0].Request.ID != request.ID {
		t.Fatalf("native association: %+v", got)
	}
	for _, field := range []string{"ProducerID", "Namespace", "InstanceID", "Generation", "NotebookID", "KernelID", "KernelSessionID"} {
		t.Run(field, func(t *testing.T) {
			other := request
			scope := ref.Scope
			reflect.ValueOf(&scope).Elem().FieldByName(field).SetString("different")
			other.Source.Notebook = &scope
			if len(NotebookAssociations([]Entry{caller, other})) != 0 {
				t.Fatal("joined another notebook identity")
			}
		})
	}
	for _, mutate := range []func(*Entry){
		func(e *Entry) { e.RunID = "another-run" },
		func(e *Entry) { e.ExecutionScope = PriorContext },
		func(e *Entry) {
			e.Notebook = &NotebookMessage{MessageID: ref.MessageID, MessageSession: "another-frontend", MessageType: "execute_request", Channel: "shell", Direction: "send"}
		},
	} {
		other := request
		mutate(&other)
		if len(NotebookAssociations([]Entry{caller, other})) != 0 {
			t.Fatal("joined an unrelated request")
		}
	}
	otherCaller := caller
	otherCaller.ToolCallID = "competing-native-call"
	if len(NotebookAssociations([]Entry{caller, otherCaller, request})) != 0 {
		t.Fatal("multiple caller claims silently resolved")
	}
	conflicting := caller
	otherRef := *ref
	otherRef.MessageID = "another-request"
	conflicting.ID, conflicting.NotebookRequest = "conflicting-observation", &otherRef
	if len(NotebookAssociations([]Entry{caller, conflicting, request})) != 0 {
		t.Fatal("conflicting observations of one invocation silently resolved")
	}
}

func TestNotebookReferenceOnlyRecognizesVersionedExecutionResults(t *testing.T) {
	for _, invalid := range []string{
		strings.ReplaceAll(notebookToolResultFixture, `"execute"`, `"read"`),
		strings.ReplaceAll(notebookToolResultFixture, `/v1`, `/future`),
		strings.ReplaceAll(notebookToolResultFixture, `"generation":"g"`, `"generation":""`),
		`{"arbitrary_nested":` + notebookToolResultFixture + `}`,
	} {
		if notebookResultReference([]byte(invalid)) != nil {
			t.Fatal("read, invalid, or arbitrary nested text became an execution reference")
		}
	}
	block, _ := json.Marshal([]map[string]any{{"type": "text", "text": notebookToolResultFixture}})
	if got := notebookResultReference(block); got == nil || got.MessageID != "request" {
		t.Fatal("MCP text-only compatible result missing")
	}
}

func TestNotebookMCPStringReferenceBeforeRetention(t *testing.T) {
	encoded, _ := json.Marshal(notebookToolResultFixture)
	hook := `{"session_id":"s","hook_event_name":"PostToolUse","tool_use_id":"call","tool_name":"mcp__notebook__notebook_execute","tool_response":` + string(encoded) + `}`
	for _, preset := range []string{"basic", "detailed"} {
		t.Run(preset, func(t *testing.T) {
			s := testService(t)
			s.CapturePolicy = capturePreset(t, preset, nil)
			retained, err := RetainHookEvent([]byte(hook), *s.CapturePolicy)
			if err != nil {
				t.Fatal(err)
			}
			parsed := parseFixture(t, "claude", string(retained)+"\n")
			if len(parsed.Records) != 1 || parsed.Records[0].NotebookRequest == nil || parsed.Records[0].NotebookRequest.MessageID != "request" {
				t.Fatal("Claude string result lost the native reference")
			}
			if preset == "basic" && strings.Contains(string(retained), "PRIVATE-OUTPUT") {
				t.Fatal("basic retained output")
			}
		})
	}
}
