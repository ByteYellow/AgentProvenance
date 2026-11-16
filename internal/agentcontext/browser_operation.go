package agentcontext

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

const BrowserToolResultVersion = "agentprovenance.browser_tool_result/v1"

// BrowserOperation references an explicit operation, not all nearby traffic.
// It is structural context retained independently of optional result bodies.
type BrowserOperation struct {
	Scope           BrowserScope               `json:"scope"`
	TargetID        string                     `json:"target_id"`
	OperationID     string                     `json:"operation_id"`
	Operation       string                     `json:"operation"`
	ResultOperation string                     `json:"result_operation,omitempty"`
	Receipt         *BrowserReceiptObservation `json:"receipt,omitempty"`
}

func (r *BrowserOperation) UnmarshalJSON(raw []byte) error {
	if !nativeResultJSON(raw) {
		return errors.New("invalid browser operation reference")
	}
	type reference BrowserOperation
	var value reference
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	if value.Receipt != nil {
		// Hook metadata and saved tool responses remain transcript observations;
		// their caller-provided trust fields never acquire importer authority.
		value.Receipt.Origin, value.Receipt.Authentication = "transcript", "unverified"
		value.Receipt.DigestStatus = "source_asserted"
	}
	*r = BrowserOperation(value)
	return nil
}

func (r BrowserOperation) valid() bool {
	if !r.Scope.valid() || !notebookIDValid(r.TargetID) || !notebookIDValid(r.OperationID) {
		return false
	}
	if r.ResultOperation != "" && r.ResultOperation != "execute" && r.ResultOperation != "read" {
		return false
	}
	if r.Receipt != nil {
		observation := r.Receipt
		if observation.Phase != "result" || observation.Origin != "transcript" || observation.Authentication != "unverified" ||
			observation.DigestStatus != "source_asserted" || !observation.Receipt.valid("result") || observation.Receipt.reference().Key() != r.Key() {
			return false
		}
	} else if r.ResultOperation == "read" {
		return false
	}
	switch r.Operation {
	case "navigate", "click", "read_text", "screenshot":
		return true
	}
	return false
}

func (r BrowserOperation) Key() string {
	// Preserve the original v1 identity independently of query mode and receipt.
	return digest(struct {
		Scope       BrowserScope `json:"scope"`
		TargetID    string       `json:"target_id"`
		OperationID string       `json:"operation_id"`
		Operation   string       `json:"operation"`
	}{r.Scope, r.TargetID, r.OperationID, r.Operation})
}

func browserExecuteTool(name string) bool {
	return name == "browser_execute" || strings.HasSuffix(name, "__browser_execute")
}

func browserTool(name string) bool {
	return browserExecuteTool(name) || name == "browser_result" || strings.HasSuffix(name, "__browser_result")
}

func browserResultReference(raw json.RawMessage) *BrowserOperation {
	var value struct {
		SchemaVersion string            `json:"schema_version"`
		Operation     string            `json:"operation"`
		Reference     *BrowserOperation `json:"browser_operation"`
		Receipt       json.RawMessage   `json:"browser_receipt"`
		Outcome       string            `json:"execution_status"`
	}
	if json.Unmarshal(nativeToolResult(raw), &value) == nil && value.SchemaVersion == BrowserToolResultVersion &&
		(value.Operation == "execute" || value.Operation == "read") && value.Reference != nil {
		value.Reference.Receipt = nil
		value.Reference.ResultOperation = value.Operation
		if len(value.Receipt) > 0 {
			value.Reference.Receipt = parseBrowserReceipt(value.Receipt, "transcript")
			if value.Reference.Receipt == nil || value.Reference.Receipt.Receipt.Outcome != value.Outcome {
				return nil
			}
		}
		if !value.Reference.valid() {
			return nil
		}
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
		if e.Kind == "tool_result" && e.BrowserOperation != nil && e.BrowserOperation.valid() &&
			browserExecuteTool(e.ToolName) && e.BrowserOperation.ResultOperation != "read" {
			if e.BrowserOperation.Receipt != nil && e.BrowserOperation.Receipt.Receipt.RunID != nil && *e.BrowserOperation.Receipt.Receipt.RunID != e.RunID {
				continue
			}
			if e.BrowserOperation.Receipt != nil {
				receipt := e.BrowserOperation.Receipt.Receipt
				if receipt.CallerSessionID != nil && *receipt.CallerSessionID != e.Source.SessionID ||
					receipt.CallerToolCallID != nil && *receipt.CallerToolCallID != e.ToolCallID {
					continue
				}
			}
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
