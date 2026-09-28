package agentcontext

import (
	"encoding/json"
	"fmt"
)

func (p *parser) codex(top row) bool {
	v, ts := obj(top["payload"]), eventTime(top)
	switch text(top, "type") {
	case "session_meta":
		p.identify(text(v, "id", "session_id"))
		p.Source.Workdir, p.Source.ApplicationVersion = text(v, "cwd"), text(v, "cli_version")
		spawn := obj(obj(obj(v["source"])["subagent"])["thread_spawn"])
		p.Source.ParentSessionID = text(spawn, "parent_thread_id")
		if p.Source.ParentSessionID != "" {
			p.Source.AgentID = p.Source.SessionID
		}
		p.add("configuration", stableKey("session", p.Source.SessionID, p.line), "", "", "", "session_metadata", ts, whole(v))
		return true
	case "turn_context":
		if _, exists := v["cwd"]; exists {
			p.Source.Workdir = text(v, "cwd")
		}
		p.add("configuration", fmt.Sprintf("configuration:%d", p.line), "", "", "", "observed", ts, whole(v))
		return true
	case "response_item":
		id := text(v, "call_id", "id")
		switch text(v, "type") {
		case "message":
			p.add("message", stableKey("message", text(v, "id"), p.line), text(v, "role"), "", "", "observed", ts, v["content"])
		case "function_call", "custom_tool_call", "local_shell_call":
			name := text(v, "name")
			if text(v, "type") == "local_shell_call" {
				name = "local_shell"
			}
			p.add("tool_call", stableKey("call", id, p.line), "assistant", id, name, "proposed", ts, content(v, "arguments", "input", "action"))
		case "function_call_output", "custom_tool_call_output", "local_shell_call_output":
			status := codexResultStatus(v)
			p.add("tool_result", stableKey("result", id, p.line), "tool", id, "", status, ts, v["output"])
			// Spawn returns a child identity, not the end of its execution. The
			// child transcript remains a separate source with parent metadata.
			if isSpawn(p.callNames[id]) {
				result := obj(v["output"])
				if result == nil {
					result = obj(json.RawMessage(text(v, "output")))
				}
				if child := text(result, "agent_id", "thread_id"); child != "" {
					p.add("session", stableKey("child", child, p.line), "", id, "spawn_agent", "started", ts,
						whole(row{"session_id": quoted(child), "parent_session_id": quoted(p.Source.SessionID)}))
				}
			}
		case "reasoning":
			p.add("message", stableKey("reasoning", text(v, "id"), p.line), "assistant", "", "", "source_reasoning", ts, whole(v))
		default:
			return false
		}
		return true
	case "event_msg":
		switch text(v, "type") {
		case "user_message", "agent_message":
			// A truncated or event-only source may never contain response_item.
			// Preserve both source forms; equal text does not prove shared identity.
			role := "assistant"
			if text(v, "type") == "user_message" {
				role = "user"
			}
			p.add("message", fmt.Sprintf("message-event:%d", p.line), role, "", "", "source_message_event", ts, v["message"])
			return true
		case "task_started", "task_complete", "turn_aborted", "context_compacted":
			p.add("session", fmt.Sprintf("lifecycle:%d", p.line), "", "", "", text(v, "type"), ts, whole(v))
			return true
		case "agent_reasoning", "agent_reasoning_raw_content":
			p.add("message", fmt.Sprintf("reasoning-event:%d", p.line), "assistant", "", "", "source_reasoning_event", ts, v["text"])
			return true
		case "token_count":
			return true
		default:
			return false
		}
	case "compacted":
		p.add("session", fmt.Sprintf("compaction:%d", p.line), "", "", "", "compacted", ts, whole(v))
		return true
	}
	return false
}

// Interpret typed result envelopes, not words in stdout or arbitrary nested
// JSON from a file/API response. "returned" deliberately does not claim success.
func codexResultStatus(v row) string {
	if flag(v, "is_error") || flag(v, "isError") || nonzeroExit(v) {
		return "error"
	}
	switch text(v, "status") {
	case "error", "failed", "cancelled":
		return "error"
	}
	output := obj(v["output"])
	if output == nil {
		output = obj(json.RawMessage(text(v, "output")))
	}
	if _, present := output["content"]; present && (flag(output, "isError") || flag(output, "is_error")) {
		return "error"
	}
	if _, present := output["output"]; present && nonzeroExit(obj(output["metadata"])) {
		return "error"
	}
	return "returned"
}

func nonzeroExit(v row) bool {
	var code int64
	return json.Unmarshal(v["exit_code"], &code) == nil && code != 0
}

func isSpawn(name string) bool {
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '.' {
			name = name[i+1:]
			break
		}
	}
	return name == "spawn_agent"
}

func quoted(s string) json.RawMessage { b, _ := json.Marshal(s); return b }
