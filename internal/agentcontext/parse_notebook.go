package agentcontext

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const NotebookCaptureVersion = "agentprovenance.jupyter_capture/v1"

// NotebookScope is asserted by the explicitly selected local capture. Generation
// comes from the launcher; KernelSessionID is observed in kernel_info_reply.
// These names follow the execution handoff contract, without granting a remote
// principal or mapping a shared kernel process to an individual request.
type NotebookScope struct {
	ProducerID      string `json:"producer_id"`
	Namespace       string `json:"namespace"`
	InstanceID      string `json:"instance_id"`
	Generation      string `json:"generation"`
	NotebookID      string `json:"notebook_id"`
	KernelID        string `json:"kernel_id"`
	KernelSessionID string `json:"kernel_session_id"`
}

type NotebookOmission struct {
	MediaType string `json:"media_type"`
	Bytes     int64  `json:"bytes"`
	SHA256    string `json:"sha256"`
	Reason    string `json:"reason"`
}

// NotebookMessage is independent of body retention. Native parent identity
// describes a protocol relationship, including late output, not a syscall claim.
type NotebookMessage struct {
	MessageID       string             `json:"message_id"`
	MessageSession  string             `json:"message_session"`
	MessageType     string             `json:"message_type"`
	ParentMessageID string             `json:"parent_message_id,omitempty"`
	ParentSession   string             `json:"parent_session,omitempty"`
	Channel         string             `json:"channel"`
	Direction       string             `json:"direction"`
	Association     string             `json:"association"`
	ObservedAt      string             `json:"observed_at,omitempty"`
	ExecutionCount  *int64             `json:"execution_count,omitempty"`
	OmittedContent  []NotebookOmission `json:"omitted_content,omitempty"`
}

func notebookIDValid(s string) bool {
	return s != "" && len(s) <= 512 && strings.TrimSpace(s) == s && utf8.ValidString(s) &&
		strings.IndexFunc(s, unicode.IsControl) < 0
}

func (s NotebookScope) valid() bool {
	for _, id := range []string{s.ProducerID, s.Namespace, s.InstanceID, s.Generation,
		s.NotebookID, s.KernelID, s.KernelSessionID} {
		if !notebookIDValid(id) {
			return false
		}
	}
	return true
}

func (p *parser) notebook(top row) bool {
	if text(top, "schema_version") != NotebookCaptureVersion {
		p.unsupported = true
		p.issue("unsupported_format_version", "schema_version")
		return false
	}
	if text(top, "type") == "notebook_session" {
		var scope NotebookScope
		if json.Unmarshal(whole(top), &scope) != nil || !scope.valid() {
			p.unsupported = true
			p.issue("notebook_scope_invalid", "notebook_session")
			return false
		}
		p.identify("notebook-" + digest(scope))
		p.Source.Notebook = &scope
		p.Source.Channel, p.Source.ParserVersion = "jupyter_protocol", "jupyter-messaging/v1"
		p.Source.FormatVersion = NotebookCaptureVersion
		p.Source.ApplicationVersion = text(top, "jupyter_client_version")
		p.add("session", "notebook_session", "", "", "", "kernel_observed", eventTime(top), nil)
		return true
	}
	if p.Source.Notebook == nil {
		p.unsupported = true
		p.issue("format_header_missing", "notebook_session")
		return false
	}
	if text(top, "type") == "notebook_gap" {
		p.issue("notebook_capture_gap", "capture")
		*p.counts().Truncated++
		p.add("session", p.positionKey("gap"), "", "", "", "capture_incomplete", eventTime(top), whole(top))
		return true
	}
	if text(top, "type") != "notebook_message" {
		return false
	}
	msg := obj(top["message"])
	h, parent, content := obj(msg["header"]), obj(msg["parent_header"]), obj(msg["content"])
	m := NotebookMessage{MessageID: text(h, "msg_id"), MessageSession: text(h, "session"),
		MessageType: text(h, "msg_type"), ParentMessageID: text(parent, "msg_id"), ParentSession: text(parent, "session"),
		Channel: text(top, "channel"), Direction: text(top, "direction"), Association: "kernel_session",
		ObservedAt: normalizedTime(text(top, "observed_at"))}
	if !notebookIDValid(m.MessageID) || !notebookIDValid(m.MessageSession) || !notebookIDValid(m.MessageType) ||
		(m.Channel != "shell" && m.Channel != "iopub" && m.Channel != "control") ||
		(m.Direction != "send" && m.Direction != "receive") || content == nil ||
		(m.Channel == "iopub" && m.Direction == "send") {
		p.issue("notebook_message_invalid", "message")
		*p.counts().Failed++
		return true
	}
	version := strings.Split(text(h, "version"), ".")
	minor := -1
	if len(version) == 2 {
		minor, _ = strconv.Atoi(version[1])
	}
	if len(version) != 2 || version[0] != "5" || minor < 0 || version[1] != strconv.Itoa(minor) {
		p.issue("notebook_protocol_unsupported", "header.version")
		*p.counts().Failed++
		return true
	}
	if m.Direction == "receive" && m.MessageSession != p.Source.Notebook.KernelSessionID {
		p.identityConflict = true
		p.issue("notebook_kernel_identity_changed", "header.session")
		return true
	}
	key := "notebook-message-" + digest([]string{m.Direction, m.Channel, m.MessageSession, m.MessageID})
	if p.notebookMessages == nil {
		p.notebookMessages = map[string]string{}
	}
	fingerprint := digest(msg)
	if previous, ok := p.notebookMessages[key]; ok && previous != fingerprint {
		p.identityConflict = true
		p.issue("notebook_message_identity_conflict", "header.msg_id")
		return true
	}
	p.notebookMessages[key] = fingerprint
	var count int64
	if raw, ok := content["execution_count"]; ok && json.Unmarshal(raw, &count) == nil && string(raw) != "null" && count >= 0 {
		m.ExecutionCount = &count
	}
	callID := ""
	call := func(session, id string) string {
		return "notebook-call-" + digest([]string{p.Source.SessionID, session, id})
	}
	kind, status := "session", "observed"
	switch {
	case m.Direction == "send" && m.Channel == "shell" && m.MessageType == "execute_request":
		kind, status, callID, m.Association = "tool_call", "sent", call(m.MessageSession, m.MessageID), "native_request"
	case m.Direction == "receive" && m.Channel == "shell" && m.MessageType == "execute_reply":
		kind, status = "tool_result", "outcome_unknown"
		switch text(content, "status") {
		case "ok":
			status = "returned"
		case "error", "aborted":
			status = text(content, "status")
		default:
			p.issue("notebook_outcome_missing", "content.status")
		}
	case m.Direction == "receive" && m.Channel == "iopub":
		switch m.MessageType {
		case "stream", "error", "execute_result", "display_data", "update_display_data", "clear_output":
			kind, status = "tool_result", "output_observed"
		case "execute_input":
			status = "execution_observed"
		case "status":
			status = "kernel_status"
		}
	}
	if m.Direction == "receive" && text(parent, "msg_type") == "execute_request" &&
		notebookIDValid(m.ParentSession) && notebookIDValid(m.ParentMessageID) {
		callID, m.Association = call(m.ParentSession, m.ParentMessageID), "native_parent_header"
	}
	// Preserve safe text as inert JSON. Binary MIME values stay out of both the
	// normalized body and its source projection until attachment retention is used.
	projected := notebookContent(content, &m)
	if buffers := msg["buffers"]; len(buffers) > 0 && string(buffers) != "[]" && string(buffers) != "null" {
		sum := sha256.Sum256(buffers)
		m.OmittedContent = append(m.OmittedContent, NotebookOmission{MediaType: "application/vnd.jupyter.buffers+json",
			Bytes: int64(len(buffers)), SHA256: hex.EncodeToString(sum[:]), Reason: "attachment_not_retained"})
	}
	if len(m.OmittedContent) > 0 {
		p.issue("notebook_nontext_content_omitted", "content.data")
	}
	before := len(p.Records)
	name := ""
	if kind == "tool_call" || kind == "tool_result" {
		name = "jupyter.execute"
	}
	p.add(kind, key,
		"", callID, name, status, normalizedTime(text(h, "date")), whole(projected))
	if len(p.Records) == before {
		return true
	}
	r := &p.Records[len(p.Records)-1]
	r.Notebook = &m
	projection := map[string]any{"schema_version": NotebookCaptureVersion, "channel": m.Channel,
		"direction": m.Direction, "header": h, "parent_header": parent, "content": projected,
		"omitted_content": m.OmittedContent}
	raw, _ := json.Marshal(projection)
	value := string(raw)
	r.RawBody, r.rawProjection = &value, "notebook_protocol_projection"
	return true
}

func notebookContent(content row, message *NotebookMessage) row {
	projected := row{}
	for k, v := range content {
		projected[k] = v
	}
	if data := obj(content["data"]); data != nil {
		kept := row{}
		mediaTypes := make([]string, 0, len(data))
		for media := range data {
			mediaTypes = append(mediaTypes, media)
		}
		sort.Strings(mediaTypes)
		for _, media := range mediaTypes {
			value := data[media]
			switch media {
			case "text/plain", "text/html", "text/markdown", "application/json":
				kept[media] = value
			default:
				sum := sha256.Sum256(value)
				message.OmittedContent = append(message.OmittedContent, NotebookOmission{MediaType: media,
					Bytes: int64(len(value)), SHA256: hex.EncodeToString(sum[:]), Reason: "attachment_not_retained"})
			}
		}
		projected["data"] = whole(kept)
	}
	return projected
}
