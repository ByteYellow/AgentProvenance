package agentcontext

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"unicode/utf8"
)

type ownedBrowserAction struct {
	event   BrowserEvent
	at      string
	status  string
	payload row
	ref     BrowserReceiptSourceRef
	line    int64
}

type ownedBrowserOperation struct{ accept, start, end *ownedBrowserAction }

type ownedBrowserJournal struct {
	file       BrowserOwnedLog
	data       []byte
	operations map[string]*ownedBrowserOperation
	gap        bool
}

func readOwnedBrowserJournal(ctx context.Context, file BrowserOwnedLog, data []byte) (*ownedBrowserJournal, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return nil, browserImportError("partial_log_prefix")
	}
	log := &ownedBrowserJournal{file: file, data: data, operations: map[string]*ownedBrowserOperation{}}
	reader := bufio.NewReader(bytes.NewReader(data))
	events := map[string]bool{}
	for line := int64(0); ; line++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		raw, err := reader.ReadBytes('\n')
		if len(raw) == 0 {
			break
		}
		if err != nil || line >= MaxRecords || len(raw) > 12<<20 || !nativeResultJSON(raw) {
			return nil, browserImportError("invalid_journal")
		}
		var top row
		if json.Unmarshal(raw, &top) != nil || text(top, "schema_version") != BrowserCaptureVersion || normalizedTime(text(top, "timestamp")) == "" {
			return nil, browserImportError("invalid_journal")
		}
		if line == 0 {
			var scope BrowserScope
			if text(top, "type") != "browser_session" || json.Unmarshal(raw, &scope) != nil || scope != file.Scope {
				return nil, browserImportError("journal_scope_mismatch")
			}
			continue
		}
		var event BrowserEvent
		if text(top, "type") != "browser_event" || text(top, "context_id") != file.Scope.ContextID ||
			json.Unmarshal(raw, &event) != nil || !notebookIDValid(event.EventID) || events[event.EventID] {
			return nil, browserImportError("journal_identity_conflict")
		}
		events[event.EventID] = true
		log.gap = log.gap || event.Kind == "gap"
		if event.Kind != "action_accept" && event.Kind != "action_start" && event.Kind != "action_end" {
			continue
		}
		ref := BrowserOperation{Scope: file.Scope, TargetID: event.TargetID, OperationID: event.OperationID, Operation: event.Operation}
		payload := obj(top["payload"])
		if !ref.valid() || payload == nil {
			return nil, browserImportError("invalid_action")
		}
		action := &ownedBrowserAction{event: event, at: text(top, "timestamp"), status: text(top, "status"), payload: payload, line: line,
			ref: BrowserReceiptSourceRef{Log: file.Name, EventID: event.EventID, SHA256: strings.TrimPrefix(browserBytesDigest(raw), "sha256:")}}
		op := log.operations[event.OperationID]
		if op == nil {
			op = &ownedBrowserOperation{}
			log.operations[event.OperationID] = op
		}
		for _, previous := range []*ownedBrowserAction{op.accept, op.start, op.end} {
			if previous != nil && (previous.event.TargetID != event.TargetID || previous.event.Operation != event.Operation) {
				return nil, browserImportError("operation_identity_conflict")
			}
		}
		switch event.Kind {
		case "action_accept":
			if op.accept != nil || op.start != nil || op.end != nil {
				return nil, browserImportError("action_order_conflict")
			}
			op.accept = action
		case "action_start":
			if op.start != nil || op.end != nil {
				return nil, browserImportError("action_order_conflict")
			}
			op.start = action
		case "action_end":
			if op.start == nil || op.end != nil || (action.status != "" && action.status != "ok" && action.status != "unknown" && action.status != "error") {
				return nil, browserImportError("action_order_conflict")
			}
			op.end = action
		}
	}
	return log, nil
}

// Journal URLs have already passed Python's privacy projection. Do not decode
// paths or re-encode Unicode/percent escapes while recomputing their digest.
func browserProjectedURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && len(raw) <= 16384 && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" &&
		u.User == nil && u.Fragment == "" && (u.RawQuery == "" || u.RawQuery == "__redacted__")
}

func browserJournalOutput(payload row) (map[string]any, bool, error) {
	output := map[string]any{}
	truncated := false
	for _, key := range []string{"url", "text", "sha256", "reason"} {
		raw, exists := payload[key]
		if !exists {
			continue
		}
		var value string
		if bytes.Equal(raw, []byte("null")) || json.Unmarshal(raw, &value) != nil {
			return nil, false, browserImportError("invalid_result_projection")
		}
		if key == "url" && !browserProjectedURL(value) || key == "sha256" && !browserSHA256(value, false) ||
			key == "reason" && value != "capture_policy" && value != "operation_incomplete" {
			return nil, false, browserImportError("invalid_result_projection")
		}
		if key == "text" && len(value) > 32<<10 {
			value, truncated = value[:32<<10], true
			for !utf8.ValidString(value) {
				value = value[:len(value)-1]
			}
		}
		output[key] = value
	}
	for key, maximum := range map[string]int64{"status": 999, "bytes": 8 << 20} {
		raw, exists := payload[key]
		if !exists {
			continue
		}
		var value int64
		if bytes.Equal(raw, []byte("null")) || json.Unmarshal(raw, &value) != nil || value < 0 || value > maximum {
			return nil, false, browserImportError("invalid_result_projection")
		}
		output[key] = value
	}
	return output, truncated, nil
}

func (c *OwnedBrowserCapture) journalReceipt(log *ownedBrowserJournal, op *ownedBrowserOperation, pending bool) (BrowserReceipt, error) {
	if op.accept == nil {
		return BrowserReceipt{}, browserImportError("admission_missing")
	}
	a := op.accept
	var receipt BrowserReceipt
	if json.Unmarshal(whole(a.payload), &receipt) != nil {
		return receipt, browserImportError("invalid_admission")
	}
	receipt.Scope, receipt.TargetID, receipt.OperationID, receipt.Action = log.file.Scope, a.event.TargetID, a.event.OperationID, a.event.Operation
	receipt.AcceptedAt, receipt.Outcome, receipt.Digest = a.at, "unknown", ""
	receipt.StartedAt, receipt.EndedAt, receipt.ResultDigest, receipt.BridgeIdentity = nil, nil, nil, nil
	receipt.SourceRefs = map[string]BrowserReceiptSourceRef{"accept": a.ref}
	receipt.GapRefs = []string{}
	if !receipt.valid("accept") || receipt.Sequence != a.line || (receipt.RunID != nil && *receipt.RunID != c.config.RunID) {
		return receipt, browserImportError("invalid_admission")
	}
	input := map[string]any{"action": receipt.Action}
	switch receipt.Action {
	case "navigate":
		if op.start == nil || !browserProjectedURL(text(op.start.payload, "url")) {
			return receipt, browserImportError("input_projection_unavailable")
		}
		input["url"] = text(op.start.payload, "url")
	case "click":
		input["selector"] = "__redacted__"
	}
	digest, err := browserValueDigest(input)
	if err != nil || receipt.NormalizedInputDigest != digest {
		return receipt, browserImportError("input_digest_mismatch")
	}
	if op.start != nil {
		receipt.StartedAt = &op.start.at
		receipt.SourceRefs["start"] = op.start.ref
	}
	if op.end != nil {
		receipt.EndedAt = &op.end.at
		receipt.SourceRefs["end"] = op.end.ref
		if op.end.status == "" || op.end.status == "ok" {
			output, truncated, err := browserJournalOutput(op.end.payload)
			if err != nil {
				return receipt, err
			}
			digest, err := browserValueDigest(map[string]any{"output": output, "output_truncated": truncated})
			if err != nil {
				return receipt, err
			}
			receipt.Outcome, receipt.ResultDigest = "ok", &digest
		} else {
			receipt.GapRefs = append(receipt.GapRefs, "operation_incomplete")
		}
	} else if !pending {
		receipt.GapRefs = append(receipt.GapRefs, "result_not_recorded")
	}
	if log.gap {
		receipt.GapRefs = append(receipt.GapRefs, "browser_capture_gap")
	}
	receipt.BridgeIdentity = &BrowserBridgeIdentity{Source: "local_bridge_configuration", Authentication: "unverified",
		TranscriptIdentity: "source_asserted_only", Identity: c.config.Placement}
	receipt.Digest, err = browserValueDigest(receipt)
	return receipt, err
}

func (c *OwnedBrowserCapture) VerifyReceipt(raw json.RawMessage) (*VerifiedBrowserReceipt, error) {
	if c == nil || len(c.logs) == 0 {
		return nil, browserImportError("capture_not_verified")
	}
	if len(raw) > 64<<10 {
		return nil, browserImportError("receipt_budget_exceeded")
	}
	observation := parseBrowserReceipt(raw, "transcript")
	if observation == nil {
		return nil, browserImportError("invalid_receipt")
	}
	receipt := observation.Receipt
	var fields row
	_ = json.Unmarshal(raw, &fields)
	delete(fields, "digest")
	digest, err := browserValueDigest(fields)
	if err != nil || digest != receipt.Digest {
		return nil, browserImportError("receipt_digest_mismatch")
	}
	var selected *ownedBrowserJournal
	var operation *ownedBrowserOperation
	for _, log := range c.logs {
		if op := log.operations[receipt.OperationID]; op != nil {
			if selected != nil {
				return nil, browserImportError("ambiguous_operation")
			}
			selected, operation = log, op
		}
	}
	if selected == nil || selected.file.Scope != receipt.Scope {
		return nil, browserImportError("receipt_scope_mismatch")
	}
	pending := true
	for _, gap := range receipt.GapRefs {
		pending = pending && gap != "result_not_recorded"
	}
	expected, err := c.journalReceipt(selected, operation, pending)
	if err != nil {
		return nil, err
	}
	if expected.Digest != receipt.Digest {
		return nil, browserImportError("receipt_journal_mismatch")
	}
	bound := &BrowserReceiptBinding{SchemaVersion: BrowserReceiptBindingVersion, Authentication: "verified", Basis: "local_operator_pinned_capture",
		RunID: c.config.RunID, Scope: expected.Scope, TargetID: expected.TargetID, OperationID: expected.OperationID, Action: expected.Action,
		ReceiptDigest: expected.Digest, ManifestSHA256: c.config.ManifestSHA256, BridgeID: c.config.BridgeID,
		BridgeConfigDigest: c.config.BridgeConfigDigest, VerifiedSourceRefs: expected.SourceRefs}
	return &VerifiedBrowserReceipt{bound: bound, raw: append(json.RawMessage(nil), raw...)}, nil
}
