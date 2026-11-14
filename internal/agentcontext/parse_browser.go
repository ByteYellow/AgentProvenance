package agentcontext

import (
	"encoding/json"
	"net/url"
)

const BrowserCaptureVersion = "agentprovenance.browser_capture/v1"

// BrowserScope identifies one captured Chromium context in one owned lifetime.
// Placement is asserted by the local entry point; browser/context IDs are native.
type BrowserScope struct {
	ProducerID string `json:"producer_id"`
	Namespace  string `json:"namespace"`
	InstanceID string `json:"instance_id"`
	Generation string `json:"generation"`
	BrowserID  string `json:"browser_id"`
	ContextID  string `json:"context_id"`
}

func (s BrowserScope) valid() bool {
	for _, id := range []string{s.ProducerID, s.Namespace, s.InstanceID, s.Generation, s.BrowserID, s.ContextID} {
		if !notebookIDValid(id) {
			return false
		}
	}
	return true
}

// Requests are qualified by CDP session and redirect hop, not URL or time.
// OperationID is present only for explicit tool observations. A page's unrelated
// requests keep their native identity without borrowing the last tool call.
type BrowserEvent struct {
	EventID            string `json:"event_id"`
	Kind               string `json:"kind"`
	TargetID           string `json:"target_id,omitempty"`
	TargetType         string `json:"target_type,omitempty"`
	CDPSessionID       string `json:"cdp_session_id,omitempty"`
	FrameID            string `json:"frame_id,omitempty"`
	LoaderID           string `json:"loader_id,omitempty"`
	RequestID          string `json:"request_id,omitempty"`
	RedirectIndex      int    `json:"redirect_index"`
	RequestKey         string `json:"request_key,omitempty"`
	InitiatorRequestID string `json:"initiator_request_id,omitempty"`
	OperationID        string `json:"operation_id,omitempty"`
	Operation          string `json:"operation,omitempty"`
	DownloadID         string `json:"download_id,omitempty"`
	Association        string `json:"association"`
	URL                string `json:"url,omitempty"`
	Method             string `json:"method,omitempty"`
	HTTPStatus         int    `json:"http_status,omitempty"`
}

func browserURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 16384 || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return ""
	}
	u.User, u.Fragment, u.RawFragment = nil, "", ""
	if u.RawQuery != "" || u.ForceQuery {
		u.RawQuery, u.ForceQuery = "__redacted__", false
	}
	return u.String()
}

func (p *parser) browser(top row) bool {
	if text(top, "schema_version") != BrowserCaptureVersion {
		p.unsupported = true
		p.issue("unsupported_format_version", "schema_version")
		return false
	}
	if text(top, "type") == "browser_session" {
		var scope BrowserScope
		if json.Unmarshal(whole(top), &scope) != nil || !scope.valid() {
			p.unsupported = true
			p.issue("browser_scope_invalid", "browser_session")
			return false
		}
		p.identify("browser-" + digest(scope))
		p.Source.Browser = &scope
		p.Source.Channel, p.Source.ParserVersion = "chromium_cdp", "chromium-cdp/v1"
		p.Source.FormatVersion = BrowserCaptureVersion
		p.Source.ApplicationVersion = text(top, "browser_version")
		p.add("session", "browser_session", "", "", "", "context_observed", eventTime(top), nil)
		return true
	}
	if p.Source.Browser == nil {
		p.unsupported = true
		p.issue("format_header_missing", "browser_session")
		return false
	}
	if text(top, "type") != "browser_event" {
		return false
	}
	var event BrowserEvent
	if json.Unmarshal(whole(top), &event) != nil || !notebookIDValid(event.EventID) || event.RedirectIndex < 0 || event.RedirectIndex > MaxRecords {
		p.issue("browser_event_invalid", "event_id")
		*p.counts().Failed++
		return true
	}
	if text(top, "context_id") != p.Source.Browser.ContextID {
		p.identityConflict = true
		p.issue("browser_context_changed", "context_id")
		return true
	}
	for _, id := range []string{event.TargetID, event.CDPSessionID, event.FrameID, event.LoaderID,
		event.RequestID, event.InitiatorRequestID, event.OperationID, event.DownloadID} {
		if id != "" && !notebookIDValid(id) {
			p.issue("browser_event_invalid", "native_identity")
			*p.counts().Failed++
			return true
		}
	}
	// Ignore incoming derived keys, association claims and unselected protocol
	// fields. RawContent is this privacy projection, never the unfiltered row.
	event.RequestKey, event.Association, event.URL, event.Method, event.HTTPStatus = "", "browser_target", "", "", 0
	payload := obj(top["payload"])
	projected := row{}
	for _, field := range []string{"url", "initiator_url", "redirect_url"} {
		if value := browserURL(text(payload, field)); value != "" {
			projected[field], _ = json.Marshal(value)
		}
	}
	for _, field := range []string{"method", "resource_type", "mime_type", "initiator_type", "error_code", "text", "reason", "sha256", "suggested_filename"} {
		if value := text(payload, field); value != "" {
			projected[field], _ = json.Marshal(value)
		}
	}
	for _, field := range []string{"status", "encoded_bytes", "bytes"} {
		var n int64
		if json.Unmarshal(payload[field], &n) == nil && n >= 0 {
			projected[field], _ = json.Marshal(n)
		}
	}
	var worker bool
	if json.Unmarshal(payload["from_service_worker"], &worker) == nil {
		projected["from_service_worker"], _ = json.Marshal(worker)
	}
	event.URL, event.Method = text(projected, "url"), text(projected, "method")
	_ = json.Unmarshal(projected["status"], &event.HTTPStatus)
	kind, status, callID, tool := "session", "observed", "", ""
	switch event.Kind {
	case "gap":
		p.issue("browser_capture_gap", "capture")
		*p.counts().Truncated++
		status, event.Association = "capture_incomplete", "browser_context"
	case "closed":
		status, event.Association = "context_closed", "browser_context"
	case "action_start", "action_end", "screenshot":
		if !notebookIDValid(event.OperationID) || !notebookIDValid(event.Operation) {
			p.issue("browser_operation_invalid", "operation_id")
			*p.counts().Failed++
			return true
		}
		callID, tool = "browser-call-"+digest([]string{p.Source.SessionID, event.OperationID}), "browser."+event.Operation
		event.Association = "tool_operation"
		kind, status = "tool_result", "returned"
		if event.Kind == "action_start" {
			kind, status = "tool_call", "started"
		} else if text(top, "status") == "error" || text(top, "status") == "unknown" {
			status = text(top, "status")
		}
	case "request", "response", "request_finished", "request_failed":
		if !notebookIDValid(event.RequestID) || !notebookIDValid(event.CDPSessionID) {
			p.issue("browser_request_invalid", "request_id")
			*p.counts().Failed++
			return true
		}
		event.RequestKey = "browser-request-" + digest([]any{p.Source.SessionID, event.CDPSessionID, event.RequestID, event.RedirectIndex})
		event.Association = "native_request"
		event.OperationID, event.Operation = "", ""
	case "target", "frame", "download", "download_finished":
		event.OperationID, event.Operation = "", ""
		if event.DownloadID != "" {
			event.Association = "native_download"
		}
	default:
		return false
	}
	validTarget := event.TargetType == "page" || event.TargetType == "iframe" || event.TargetType == "worker" || event.TargetType == "service_worker"
	if event.Kind != "gap" && event.Kind != "closed" && (!notebookIDValid(event.TargetID) || !validTarget || !notebookIDValid(event.CDPSessionID)) {
		p.issue("browser_target_invalid", "target_id")
		*p.counts().Failed++
		return true
	}
	if p.browserOwners == nil {
		p.browserOwners = map[string]string{}
	}
	owners := map[string]string{}
	if event.CDPSessionID != "" {
		owners["session:"+event.CDPSessionID] = digest([]string{event.TargetID, event.TargetType})
	}
	if event.OperationID != "" {
		owners["operation:"+event.OperationID] = digest([]string{event.TargetID, event.CDPSessionID, event.Operation})
	}
	for id, owner := range owners {
		if previous, exists := p.browserOwners[id]; exists && previous != owner {
			p.identityConflict = true
			p.issue("browser_native_identity_conflict", "native_identity")
			return true
		}
		p.browserOwners[id] = owner
	}
	key := "browser-event-" + digest(event.EventID)
	if p.browserEvents == nil {
		p.browserEvents = map[string]string{}
	}
	fingerprint := digest(top)
	if previous, exists := p.browserEvents[key]; exists && previous != fingerprint {
		p.identityConflict = true
		p.issue("browser_event_identity_conflict", "event_id")
		return true
	}
	p.browserEvents[key] = fingerprint
	before := len(p.Records)
	p.add(kind, key, "", callID, tool, status, eventTime(top), whole(projected))
	if len(p.Records) == before {
		return true
	}
	r := &p.Records[len(p.Records)-1]
	r.Browser = &event
	if event.Kind == "screenshot" {
		r.Attachments = []AttachmentInput{notebookAttachment("image/png", top["image"])}
	}
	projection := map[string]any{"schema_version": BrowserCaptureVersion, "browser": event, "payload": projected}
	raw, _ := json.Marshal(projection)
	value := string(raw)
	r.RawBody, r.rawProjection = &value, "browser_privacy_projection"
	return true
}
