package agentcontext

import (
	"encoding/json"
	"sort"
	"strings"
)

const BrowserToolResultVersion = "agentprovenance.browser_tool_result/v1"

// BrowserOperation references an explicit operation, not all nearby traffic.
// It is structural context retained independently of optional result bodies.
type BrowserOperation struct {
	Scope       BrowserScope `json:"scope"`
	TargetID    string       `json:"target_id"`
	OperationID string       `json:"operation_id"`
	Operation   string       `json:"operation"`
}

func (r BrowserOperation) valid() bool {
	if !r.Scope.valid() || !notebookIDValid(r.TargetID) || !notebookIDValid(r.OperationID) {
		return false
	}
	switch r.Operation {
	case "navigate", "click", "read_text", "screenshot":
		return true
	}
	return false
}

func (r BrowserOperation) Key() string { return digest(r) }

func browserTool(name string) bool {
	return name == "browser_execute" || strings.HasSuffix(name, "__browser_execute")
}

func browserResultReference(raw json.RawMessage) *BrowserOperation {
	var value struct {
		SchemaVersion string            `json:"schema_version"`
		Operation     string            `json:"operation"`
		Reference     *BrowserOperation `json:"browser_operation"`
	}
	if json.Unmarshal(nativeToolResult(raw), &value) == nil && value.SchemaVersion == BrowserToolResultVersion &&
		value.Operation == "execute" && value.Reference != nil && value.Reference.valid() {
		return value.Reference
	}
	return nil
}

type BrowserAssociation struct {
	Caller    Entry
	Operation Entry
}

func BrowserAssociations(entries []Entry) []BrowserAssociation {
	callers, operations := map[string]map[string]Entry{}, map[string]map[string]Entry{}
	claims := map[string]map[string]bool{}
	operationClaims := map[string]map[string]bool{}
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
		if e.Kind == "tool_result" && e.BrowserOperation != nil && e.BrowserOperation.valid() && browserTool(e.ToolName) {
			add(callers, e.BrowserOperation.Key(), e)
			id := ToolNodeID(e)
			if claims[id] == nil {
				claims[id] = map[string]bool{}
			}
			claims[id][e.BrowserOperation.Key()] = true
		}
		if e.Kind == "tool_call" && e.Source.Harness == "browser" && e.Source.Browser != nil && e.Browser != nil && e.Browser.Kind == "action_start" {
			ref := BrowserOperation{Scope: *e.Source.Browser, TargetID: e.Browser.TargetID, OperationID: e.Browser.OperationID, Operation: e.Browser.Operation}
			if ref.valid() {
				add(operations, ref.Key(), e)
				id := ToolNodeID(e)
				if operationClaims[id] == nil {
					operationClaims[id] = map[string]bool{}
				}
				operationClaims[id][digest([]string{ref.Key(), e.Browser.CDPSessionID})] = true
			}
		}
	}
	keys := make([]string, 0, len(callers))
	for key := range callers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var matches []BrowserAssociation
	for _, key := range keys {
		if len(callers[key]) != 1 || len(operations[key]) != 1 {
			continue
		}
		for _, caller := range callers[key] {
			if len(claims[ToolNodeID(caller)]) != 1 {
				continue
			}
			for _, operation := range operations[key] {
				if len(operationClaims[ToolNodeID(operation)]) == 1 {
					matches = append(matches, BrowserAssociation{Caller: caller, Operation: operation})
				}
			}
		}
	}
	return matches
}
