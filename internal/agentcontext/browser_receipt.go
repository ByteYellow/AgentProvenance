package agentcontext

import (
	"encoding/hex"
	"encoding/json"
	"path"
	"strings"
)

const BrowserReceiptVersion = "agentprovenance.browser_operation_receipt/v1"

// BrowserLocalOperatorEvidence is an out-of-band importer assertion, not a
// credential. Only ParseOptions.BindingEvidence can select this origin.
const BrowserLocalOperatorEvidence = "browser_local_operator"

type BrowserReceiptSourceRef struct {
	Log     string `json:"log"`
	EventID string `json:"event_id"`
	SHA256  string `json:"sha256"`
}

type BrowserBridgePlacement struct {
	ProducerID string `json:"producer_id"`
	Namespace  string `json:"namespace"`
	InstanceID string `json:"instance_id"`
	Generation string `json:"generation"`
}

// BrowserBridgeIdentity contains the receipt author's claims. Effective trust
// belongs to BrowserReceiptObservation, even when a claim says "verified".
type BrowserBridgeIdentity struct {
	Source             string                 `json:"source"`
	Authentication     string                 `json:"authentication"`
	TranscriptIdentity string                 `json:"transcript_identity"`
	Identity           BrowserBridgePlacement `json:"identity"`
}

type BrowserReceipt struct {
	SchemaVersion         string                             `json:"schema_version"`
	Scope                 BrowserScope                       `json:"scope"`
	TargetID              string                             `json:"target_id"`
	OperationID           string                             `json:"operation_id"`
	Action                string                             `json:"action"`
	NormalizedInputDigest string                             `json:"normalized_input_digest"`
	InputDigestBasis      string                             `json:"input_digest_basis"`
	InputRedactions       []string                           `json:"input_redactions"`
	AcceptedAt            string                             `json:"accepted_at"`
	StartedAt             *string                            `json:"started_at"`
	EndedAt               *string                            `json:"ended_at"`
	Sequence              int64                              `json:"sequence"`
	RunID                 *string                            `json:"run_id"`
	CallerSessionID       *string                            `json:"caller_session_id"`
	CallerToolCallID      *string                            `json:"caller_tool_call_id"`
	CaptureEpoch          string                             `json:"capture_epoch"`
	Outcome               string                             `json:"outcome"`
	GapRefs               []string                           `json:"gap_refs"`
	SourceRefs            map[string]BrowserReceiptSourceRef `json:"source_refs"`
	ResultDigest          *string                            `json:"result_digest"`
	BridgeIdentity        *BrowserBridgeIdentity             `json:"bridge_identity,omitempty"`
	Digest                string                             `json:"digest,omitempty"`
}

// Accept observations project the admission plus its enclosing journal scope;
// result observations preserve the complete source receipt and its original refs.
// Hashes are retained claims, not checks performed against the original files.
type BrowserReceiptObservation struct {
	Phase          string         `json:"phase"`
	Origin         string         `json:"origin"`
	Authentication string         `json:"authentication"`
	DigestStatus   string         `json:"digest_status"`
	Receipt        BrowserReceipt `json:"receipt"`
}

func browserSHA256(value string, prefixed bool) bool {
	if prefixed {
		if !strings.HasPrefix(value, "sha256:") {
			return false
		}
		value = strings.TrimPrefix(value, "sha256:")
	}
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && value == strings.ToLower(value)
}

func (r BrowserReceipt) reference() BrowserOperation {
	return BrowserOperation{Scope: r.Scope, TargetID: r.TargetID, OperationID: r.OperationID, Operation: r.Action}
}

func (r BrowserReceipt) valid(phase string) bool {
	if r.SchemaVersion != BrowserReceiptVersion || !r.reference().valid() ||
		!browserSHA256(r.NormalizedInputDigest, true) || r.InputDigestBasis != "privacy_projected_input/v1" ||
		r.CaptureEpoch != r.Scope.BrowserID || r.Sequence < 1 || r.Sequence > MaxRecords || normalizedTime(r.AcceptedAt) == "" {
		return false
	}
	expectedRedactions := ""
	switch r.Action {
	case "navigate":
		expectedRedactions = "url.userinfo,url.query,url.fragment"
	case "click":
		expectedRedactions = "selector"
	}
	if strings.Join(r.InputRedactions, ",") != expectedRedactions || len(r.InputRedactions) > 3 {
		return false
	}
	for _, id := range []*string{r.RunID, r.CallerSessionID, r.CallerToolCallID} {
		if id != nil && !notebookIDValid(*id) {
			return false
		}
	}
	if phase == "accept" {
		return r.Digest == "" && r.Outcome == "unknown" && r.StartedAt == nil && r.EndedAt == nil
	}
	if phase != "result" || !browserSHA256(r.Digest, true) || (r.Outcome != "ok" && r.Outcome != "unknown") ||
		len(r.SourceRefs) < 1 || len(r.SourceRefs) > 3 || len(r.GapRefs) > 16 || r.BridgeIdentity == nil {
		return false
	}
	for _, timestamp := range []*string{r.StartedAt, r.EndedAt} {
		if timestamp != nil && normalizedTime(*timestamp) == "" {
			return false
		}
	}
	for key, ref := range r.SourceRefs {
		if (key != "accept" && key != "start" && key != "end") || !notebookIDValid(ref.EventID) ||
			!browserSHA256(ref.SHA256, false) || !notebookIDValid(ref.Log) || path.Base(ref.Log) != ref.Log ||
			strings.Contains(ref.Log, "\\") || !strings.HasSuffix(ref.Log, ".jsonl") {
			return false
		}
	}
	if _, ok := r.SourceRefs["accept"]; !ok {
		return false
	}
	if r.StartedAt != nil && r.SourceRefs["start"].EventID == "" || r.EndedAt != nil && (r.StartedAt == nil || r.SourceRefs["end"].EventID == "") {
		return false
	}
	if r.Outcome == "ok" && (r.StartedAt == nil || r.EndedAt == nil || r.ResultDigest == nil) {
		return false
	}
	if r.ResultDigest != nil && !browserSHA256(*r.ResultDigest, true) {
		return false
	}
	for _, gap := range r.GapRefs {
		if len(gap) == 0 || len(gap) > 128 || strings.Trim(gap, "abcdefghijklmnopqrstuvwxyz0123456789_") != "" {
			return false
		}
	}
	bridge := r.BridgeIdentity
	if bridge.Source != "local_bridge_configuration" || bridge.TranscriptIdentity != "source_asserted_only" ||
		(bridge.Authentication != "unverified" && bridge.Authentication != "verified") {
		return false
	}
	return bridge.Identity == (BrowserBridgePlacement{r.Scope.ProducerID, r.Scope.Namespace, r.Scope.InstanceID, r.Scope.Generation})
}

func observeBrowserReceipt(receipt BrowserReceipt, phase, origin string) *BrowserReceiptObservation {
	if !receipt.valid(phase) {
		return nil
	}
	status := "source_asserted"
	if phase == "accept" {
		status = "not_recorded"
	}
	return &BrowserReceiptObservation{Phase: phase, Origin: origin, Authentication: "unverified", DigestStatus: status, Receipt: receipt}
}

func parseBrowserReceipt(raw json.RawMessage, origin string) *BrowserReceiptObservation {
	var receipt BrowserReceipt
	if !nativeResultJSON(raw) || json.Unmarshal(raw, &receipt) != nil {
		return nil
	}
	return observeBrowserReceipt(receipt, "result", origin)
}

func (p *parser) browserReceiptOrigin() string {
	if p.opts.Binding == "explicit" || p.opts.Binding == "exact" {
		for _, evidence := range p.opts.BindingEvidence {
			if evidence == BrowserLocalOperatorEvidence {
				return "local_operator"
			}
		}
	}
	return "external_file"
}

func (p *parser) browserAdmission(event BrowserEvent, top, payload row) *BrowserReceiptObservation {
	var receipt BrowserReceipt
	if json.Unmarshal(whole(payload), &receipt) != nil {
		return nil
	}
	// Admission fields cannot supply a different scope or a completed result.
	receipt.Scope, receipt.TargetID = *p.Source.Browser, event.TargetID
	receipt.OperationID, receipt.Action = event.OperationID, event.Operation
	receipt.AcceptedAt, receipt.Outcome = eventTime(top), "unknown"
	receipt.StartedAt, receipt.EndedAt, receipt.ResultDigest, receipt.BridgeIdentity = nil, nil, nil, nil
	receipt.SourceRefs, receipt.GapRefs, receipt.Digest = nil, nil, ""
	return observeBrowserReceipt(receipt, "accept", p.browserReceiptOrigin())
}

func (p *parser) browserStoredReceipt(payload row) *BrowserReceiptObservation {
	if text(payload, "schema_version") == BrowserReceiptVersion {
		return parseBrowserReceipt(whole(payload), p.browserReceiptOrigin())
	}
	if text(payload, "schema_version") == BrowserToolResultVersion {
		ref := browserResultReference(whole(payload))
		if ref == nil || ref.Receipt == nil {
			return nil
		}
		return observeBrowserReceipt(ref.Receipt.Receipt, "result", p.browserReceiptOrigin())
	}
	if text(payload, "schema_version") != "" {
		return nil
	}
	if _, a := payload["browser_receipt"]; a {
		if _, b := payload["receipt"]; b {
			return nil
		}
		return parseBrowserReceipt(payload["browser_receipt"], p.browserReceiptOrigin())
	}
	return parseBrowserReceipt(payload["receipt"], p.browserReceiptOrigin())
}

func (p *parser) browserTerminal(event *BrowserEvent, payload row, kind, status *string) bool {
	key := event.OperationID
	switch event.Kind {
	case "action_accept":
		if p.browserOwners["accepted:"+key] != "" || p.browserOwners["started:"+key] != "" || p.browserOwners["terminal:"+key] != "" {
			p.identityConflict = true
			p.issue("browser_accept_identity_conflict", "operation_id")
			return false
		}
		p.browserOwners["accepted:"+key] = event.EventID
	case "action_start":
		if p.browserOwners["started:"+key] != "" || p.browserOwners["terminal:"+key] != "" {
			p.identityConflict = true
			p.issue("browser_start_identity_conflict", "operation_id")
			return false
		}
		p.browserOwners["started:"+key] = event.EventID
	case "screenshot":
		if p.browserOwners["accepted:"+key] != "" || p.browserOwners["terminal:"+key] != "" {
			*kind, *status = "session", "attachment_observed"
		} else {
			// Legacy images are already terminal. Do not change their record kind
			// on a later import, which would leave a second persisted terminal.
			p.browserOwners["terminal:"+key] = "ok"
		}
	case "action_end", "action_result":
		outcome := "ok"
		if *status == "error" || *status == "unknown" {
			outcome = "unknown"
		}
		if previous := p.browserOwners["terminal:"+key]; previous != "" {
			if previous != outcome {
				p.identityConflict = true
				p.issue("browser_terminal_conflict", "operation_id")
				return false
			}
			*kind, *status = "session", "terminal_observed"
		}
		if event.Kind == "action_end" {
			fingerprint := digest(payload)
			if previous := p.browserOwners["result_payload:"+key]; previous != "" && previous != fingerprint {
				p.identityConflict = true
				p.issue("browser_terminal_conflict", "payload")
				return false
			}
			p.browserOwners["result_payload:"+key] = fingerprint
		}
		p.browserOwners["terminal:"+key] = outcome
	}
	return true
}
