package agentcontext

import (
	"encoding/json"
	"fmt"
)

func (p *parser) claude(top row) bool {
	p.identify(text(top, "sessionId", "session_id"))
	ts := eventTime(top)
	changes := row{}
	if raw, exists := top["cwd"]; exists {
		cwd := text(top, "cwd")
		if cwd != p.Source.Workdir {
			changes["cwd"] = raw
		}
		p.Source.Workdir = cwd
	}
	if raw, exists := top["version"]; exists {
		version := text(top, "version")
		if version != p.Source.ApplicationVersion {
			changes["application_version"] = raw
		}
		p.Source.ApplicationVersion = version
	}
	if text(top, "type") == "system" && text(top, "subtype") == "init" {
		if _, exists := top["claude_code_version"]; exists {
			p.Source.ApplicationVersion = text(top, "claude_code_version")
		}
	}
	if len(changes) > 0 {
		p.add("configuration", p.positionKey("source-config"), "", "", "", "source_metadata", ts, whole(changes))
	}
	if event := text(top, "hook_event_name"); event != "" {
		p.Source.Channel = "hooks"
		start := len(p.Records)
		known := p.claudeHook(top, event, ts)
		for i := start; i < len(p.Records); i++ {
			p.Records[i].AgentID = text(top, "agent_id")
		}
		return known
	}
	if agent := text(top, "agentId", "agent_id"); agent != "" {
		if p.Source.AgentID != "" && p.Source.AgentID != agent {
			p.identityConflict = true
			p.issue("agent_identity_conflict", "agent_id")
		} else {
			p.Source.AgentID = agent
		}
	}
	switch text(top, "type") {
	case "user", "assistant":
		message := obj(top["message"])
		role := text(message, "role")
		if role == "" {
			role = text(top, "type")
		}
		id := text(top, "uuid")
		key := p.sourceKey("message", id)
		if model := text(message, "model"); model != "" {
			p.add("configuration", key+":model", "", "", "", "observed", ts, whole(row{"model": quoted(model)}))
		}
		var blocks []row
		if json.Unmarshal(message["content"], &blocks) != nil {
			p.add("message", key, role, "", "", "observed", ts, message["content"])
			return true
		}
		var ordinary []row
		for i, block := range blocks {
			switch text(block, "type") {
			case "tool_use":
				call := text(block, "id")
				p.add("tool_call", p.sourceKey("call", call), "assistant", call, text(block, "name"), "proposed", ts, block["input"])
			case "tool_result":
				call, status := text(block, "tool_use_id"), "returned"
				if flag(block, "is_error") {
					status = "error"
				}
				p.add("tool_result", p.sourceKey("result", call), "tool", call, "", status, ts, block["content"])
			case "text", "thinking", "redacted_thinking", "image", "document":
				ordinary = append(ordinary, block)
			default:
				ordinary = append(ordinary, block)
				p.issue("unrecognized_content_block", fmt.Sprintf("content.%d", i))
				*p.counts().Unrecognized++
			}
		}
		if len(ordinary) > 0 {
			body, _ := json.Marshal(ordinary)
			p.add("message", key, role, "", "", "observed", ts, body)
		}
		return true
	case "system":
		kind, status := "session", text(top, "subtype")
		if status == "init" {
			kind, status = "configuration", "initialization"
		}
		p.add(kind, p.positionKey("system"), "system", "", "", status, ts, whole(top))
		return true
	case "permission-mode", "mode":
		p.add("configuration", p.positionKey("permission-mode"), "", "", "", "permission_mode", ts, whole(top))
		return true
	case "attachment":
		// Native context attachments are source state, not new conversation
		// turns or proof that a tool action was authorized.
		p.add("session", p.positionKey("attachment"), "system", "", "", "source_attachment", ts, whole(top))
		return true
	case "atis-latch", "last-prompt", "cost-state":
		p.add("session", p.positionKey("native-state"), "", "", "", "source_"+text(top, "type"), ts, whole(top))
		return true
	case "summary":
		p.add("message", p.positionKey("summary"), "assistant", "", "", "summary", ts, top["summary"])
		return true
	case "queue-operation", "file-history-snapshot", "progress":
		return true
	}
	return false
}

func (p *parser) claudeHook(top row, event, ts string) bool {
	id, name := text(top, "tool_use_id"), text(top, "tool_name")
	key := p.positionKey("hook")
	switch event {
	case "PreToolUse":
		p.add("tool_call", p.sourceKey("call", id), "assistant", id, name, "proposed", ts, top["tool_input"])
	case "PostToolUse", "PostToolUseFailure":
		status := "returned"
		if event == "PostToolUseFailure" {
			status = "error"
		}
		p.add("tool_result", p.sourceKey("result", id), "tool", id, name, status, ts, content(top, "tool_response", "error"))
	case "UserPromptSubmit":
		p.add("message", key, "user", "", "", "observed", ts, top["prompt"])
	case "PermissionRequest":
		// A permission request is not evidence that the action was authorized.
		p.add("approval", key, "", id, name, "requested", ts, whole(top))
	case "SessionStart", "SessionEnd", "SubagentStart", "SubagentStop", "Stop", "StopFailure":
		p.add("session", key, "", id, name, event, ts, whole(top))
	default:
		return false
	}
	if len(top["permission_mode"]) > 0 {
		p.add("configuration", key+":permissions", "", "", "", "observed", ts,
			whole(row{"permission_mode": top["permission_mode"]}))
	}
	return true
}
