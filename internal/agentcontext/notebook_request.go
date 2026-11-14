package agentcontext

import (
	"encoding/json"
	"sort"
	"strings"
)

const NotebookToolResultVersion = "agentprovenance.notebook_tool_result/v1"

// NotebookRequest is a tool-result assertion of the native request sent by the
// selected Notebook entry point. It survives optional result-body retention.
type NotebookRequest struct {
	Scope          NotebookScope `json:"scope"`
	MessageSession string        `json:"message_session"`
	MessageID      string        `json:"message_id"`
}

func (r NotebookRequest) valid() bool {
	return r.Scope.valid() && notebookIDValid(r.MessageSession) && notebookIDValid(r.MessageID)
}

func (r NotebookRequest) Key() string { return digest(r) }

func notebookTool(name string) bool {
	return name == "notebook_execute" || strings.HasSuffix(name, "__notebook_execute")
}

func notebookResultReference(raw json.RawMessage) *NotebookRequest {
	var encoded string
	if json.Unmarshal(raw, &encoded) == nil {
		return notebookResultPayload([]byte(encoded))
	}
	var value row
	if json.Unmarshal(raw, &value) == nil && value != nil {
		if text(value, "schema_version") == NotebookToolResultVersion {
			var ref NotebookRequest
			if text(value, "operation") == "execute" && json.Unmarshal(value["notebook_request"], &ref) == nil && ref.valid() {
				return &ref
			}
			return nil
		}
		// MCP uses structuredContent on the wire. The Python SDK exposes its
		// snake_case equivalent; accept that envelope when importing SDK logs.
		for _, key := range []string{"structuredContent", "structured_content"} {
			if nested, ok := value[key]; ok {
				return notebookResultPayload(nested)
			}
		}
		raw = value["content"]
	}
	var blocks []row
	if json.Unmarshal(raw, &blocks) != nil || len(blocks) != 1 || text(blocks[0], "type") != "text" {
		return nil
	}
	return notebookResultPayload([]byte(text(blocks[0], "text")))
}

func notebookResultPayload(raw json.RawMessage) *NotebookRequest {
	var value struct {
		SchemaVersion string           `json:"schema_version"`
		Operation     string           `json:"operation"`
		Request       *NotebookRequest `json:"notebook_request"`
	}
	if json.Unmarshal(raw, &value) == nil && value.SchemaVersion == NotebookToolResultVersion &&
		value.Operation == "execute" && value.Request != nil && value.Request.valid() {
		return value.Request
	}
	return nil
}

type NotebookAssociation struct {
	Caller  Entry
	Request Entry
}

// NotebookAssociations resolves full native identities within one Run. Multiple
// distinct callers claiming one request remain unresolved, regardless of order.
func NotebookAssociations(entries []Entry) []NotebookAssociation {
	callers, requests := map[string]map[string]Entry{}, map[string]map[string]Entry{}
	claims := map[string]map[string]bool{}
	add := func(index map[string]map[string]Entry, key string, e Entry) {
		key = e.RunID + ":" + key
		if index[key] == nil {
			index[key] = map[string]Entry{}
		}
		id := ToolNodeID(e)
		if previous, ok := index[key][id]; !ok || e.ID < previous.ID {
			index[key][id] = e
		}
	}
	for _, e := range entries {
		if e.ExecutionScope == PriorContext || e.ToolCallID == "" {
			continue
		}
		if e.Kind == "tool_result" && e.NotebookRequest != nil && e.NotebookRequest.valid() && notebookTool(e.ToolName) {
			add(callers, e.NotebookRequest.Key(), e)
			id := ToolNodeID(e)
			if claims[id] == nil {
				claims[id] = map[string]bool{}
			}
			claims[id][e.NotebookRequest.Key()] = true
		}
		if e.Kind == "tool_call" && e.Source.Harness == "jupyter" && e.Source.Notebook != nil && e.Notebook != nil &&
			e.Notebook.MessageType == "execute_request" && e.Notebook.Channel == "shell" && e.Notebook.Direction == "send" {
			ref := NotebookRequest{Scope: *e.Source.Notebook, MessageSession: e.Notebook.MessageSession, MessageID: e.Notebook.MessageID}
			if ref.valid() {
				add(requests, ref.Key(), e)
			}
		}
	}
	keys := make([]string, 0, len(callers))
	for key := range callers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var matches []NotebookAssociation
	for _, key := range keys {
		if len(callers[key]) != 1 || len(requests[key]) != 1 {
			continue
		}
		for _, caller := range callers[key] {
			if len(claims[ToolNodeID(caller)]) != 1 {
				continue
			}
			for _, request := range requests[key] {
				matches = append(matches, NotebookAssociation{Caller: caller, Request: request})
			}
		}
	}
	return matches
}
