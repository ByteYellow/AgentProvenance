package agentcontext

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

const hookCaptureVersion = "agentprovenance.hook_retention/v1"

var ErrHookCaptureLimit = errors.New("normalized hook exceeds capture limit")

type hookCaptureMetadata struct {
	Version        string        `json:"version"`
	Policy         CapturePolicy `json:"policy"`
	Raw            *ContentRef   `json:"raw,omitempty"`
	ToolResult     *ContentRef   `json:"tool_result,omitempty"`
	Approval       *ContentRef   `json:"approval,omitempty"`
	Permission     *ContentRef   `json:"permission,omitempty"`
	Redacted       bool          `json:"redacted,omitempty"`
	RedactedBodies []string      `json:"redacted_bodies,omitempty"`
}

// RetainHookEvent applies the run's policy before the hook sidecar is written.
// Filtered rows carry omission metadata, never a reference to discarded bytes.
func RetainHookEvent(data []byte, policy CapturePolicy) ([]byte, error) {
	if err := policy.validate(); err != nil {
		return nil, err
	}
	var top row
	if !utf8.Valid(data) || json.Unmarshal(data, &top) != nil || top == nil || text(top, "hook_event_name") == "" {
		return nil, fmt.Errorf("invalid hook JSON object")
	}
	// The writer owns this namespace; stdin cannot supply retention claims.
	delete(top, "_agentprov_capture")
	meta := hookCaptureMetadata{Version: hookCaptureVersion, Policy: policy}
	if !policy.SourceRecords {
		original := string(whole(top))
		if len(original) > MaxLineBytes {
			return nil, ErrHookCaptureLimit
		}
		raw := omittedContent(&original, "application/json", "capture_policy", "hook_record")
		meta.Raw = &raw
		keys := []string{"hook_event_name", "session_id", "agent_id", "parent_agent_id", "agent_type",
			"agentId", "parentAgentId", "agentType", "tool_use_id", "tool_name", "ts", "_ts", "timestamp",
			"cwd", "version", "transcript_path", "agent_transcript_path"}
		event := text(top, "hook_event_name")
		switch event {
		case "PreToolUse":
			keys = append(keys, "tool_input")
		case "PostToolUse", "PostToolUseFailure":
			if policy.ToolResults {
				keys = append(keys, "tool_response", "error")
			} else {
				meta.ToolResult = omittedHookValue(content(top, "tool_response", "error"))
			}
		case "UserPromptSubmit":
			keys = append(keys, "prompt")
		case "PermissionRequest":
			if policy.Configuration {
				keys = append(keys, "tool_input", "permission_suggestions")
			} else {
				meta.Approval = omittedHookValue(whole(top))
			}
		case "Stop", "StopFailure", "SubagentStop":
			keys = append(keys, "last_assistant_message")
		}
		if policy.Configuration {
			keys = append(keys, "permission_mode")
		} else if raw, ok := top["permission_mode"]; ok {
			meta.Permission = omittedHookValue(whole(row{"permission_mode": raw}))
		}
		retained := row{}
		for _, key := range keys {
			if value, ok := top[key]; ok {
				retained[key] = value
			}
		}
		top = retained
	}
	retained, changed := provenance.RedactText(string(whole(top)))
	if changed {
		meta.Redacted = true
		for _, item := range []struct {
			kind string
			body json.RawMessage
		}{
			{"tool_call", top["tool_input"]}, {"tool_result", content(top, "tool_response", "error")},
			{"message", top["prompt"]}, {"configuration", whole(row{"permission_mode": top["permission_mode"], "cwd": top["cwd"], "version": top["version"]})},
			{"session", whole(top)}, {"approval", whole(top)},
		} {
			if _, redacted := provenance.RedactText(string(item.body)); redacted {
				meta.RedactedBodies = append(meta.RedactedBodies, item.kind)
			}
		}
	}
	if policy.SourceRecords && !changed {
		return []byte(retained), nil
	}
	var result row
	if err := json.Unmarshal([]byte(retained), &result); err != nil {
		return nil, fmt.Errorf("hook redaction produced invalid JSON")
	}
	result["_agentprov_capture"], _ = json.Marshal(meta)
	return whole(result), nil
}

func omittedHookValue(raw json.RawMessage) *ContentRef {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	body, media := string(raw), "application/json"
	if json.Unmarshal(raw, &body) == nil {
		media = "text/plain"
	}
	c := omittedContent(&body, media, "capture_policy", "parsed_content")
	return &c
}

func parseHookCapture(top row) (*hookCaptureMetadata, error) {
	raw, ok := top["_agentprov_capture"]
	if !ok {
		return nil, nil
	}
	var meta hookCaptureMetadata
	if json.Unmarshal(raw, &meta) != nil || meta.Version != hookCaptureVersion ||
		meta.Policy.validate() != nil || (!meta.Policy.SourceRecords && meta.Raw == nil) || (meta.Policy.SourceRecords && meta.Raw != nil) {
		return nil, fmt.Errorf("invalid hook retention metadata")
	}
	for _, item := range []struct {
		ref   *ContentRef
		scope string
	}{{meta.Raw, "hook_record"}, {meta.ToolResult, "parsed_content"}, {meta.Approval, "parsed_content"}, {meta.Permission, "parsed_content"}} {
		if item.ref == nil {
			continue
		}
		ref := item.ref
		hash, err := hex.DecodeString(ref.SHA256)
		if err != nil || len(hash) != 32 || ref.Ref != "" || ref.State != "omitted" || ref.Reason != "capture_policy" ||
			ref.DigestScope != item.scope || ref.Bytes == nil || *ref.Bytes < 0 || *ref.Bytes > MaxLineBytes {
			return nil, fmt.Errorf("invalid hook omission descriptor")
		}
	}
	if (meta.ToolResult != nil && meta.Policy.ToolResults) || ((meta.Approval != nil || meta.Permission != nil) && meta.Policy.Configuration) {
		return nil, fmt.Errorf("hook omission conflicts with retention policy")
	}
	if len(meta.RedactedBodies) > 6 || (len(meta.RedactedBodies) > 0 && !meta.Redacted) {
		return nil, fmt.Errorf("invalid hook redaction metadata")
	}
	for _, kind := range meta.RedactedBodies {
		if kind != "tool_call" && kind != "tool_result" && kind != "message" && kind != "configuration" && kind != "session" && kind != "approval" {
			return nil, fmt.Errorf("invalid hook redaction kind")
		}
	}
	return &meta, nil
}

func (m *hookCaptureMetadata) bodyRedacted(kind string) bool {
	if m == nil || !m.Redacted {
		return false
	}
	for _, body := range m.RedactedBodies {
		if body == kind {
			return true
		}
	}
	return false
}

func (m *hookCaptureMetadata) omittedBody(r Record) *ContentRef {
	switch r.Kind {
	case "tool_result":
		return m.ToolResult
	case "approval":
		return m.Approval
	case "configuration":
		if strings.HasSuffix(r.Key, ":permissions") {
			return m.Permission
		}
	}
	return nil
}

// HookCaptureDiagnostic contains only a fixed code; source input is never logged
// on malformed or oversized hooks. Parse records it as a collection failure.
func HookCaptureDiagnostic(code string) []byte {
	switch code {
	case "hook_input_limit", "hook_input_invalid", "hook_input_read_failed", "hook_log_limit":
	default:
		code = "hook_capture_failed"
	}
	return whole(row{"type": quoted("agentprov_hook_diagnostic"), "code": quoted(code)})
}
