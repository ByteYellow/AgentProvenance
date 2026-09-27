package agentcontext

import (
	"encoding/json"
	"fmt"
)

func (p *parser) kimi(top row) bool {
	p.identify(text(top, "session_id", "sessionId"))
	ts, v := eventTime(top), top
	if text(top, "type") == "context.append_loop_event" {
		v = obj(top["event"])
	}
	key := fmt.Sprintf("line:%d", p.line)
	switch text(v, "type") {
	case "metadata":
		p.Source.FormatVersion = text(v, "protocol_version")
		p.add("session", key, "", "", "", "observed", ts, whole(v))
	case "config.update":
		p.add("configuration", key, "", "", "", "observed", ts, whole(v))
	case "turn.prompt":
		p.add("message", key, "user", "", "", "observed", ts, content(v, "input", "content"))
	case "tool.call":
		id := text(v, "toolCallId")
		p.add("tool_call", stableKey("call", id, p.line), "assistant", id, text(v, "name"), "proposed", ts, v["args"])
	case "tool.result":
		id, status := text(v, "toolCallId"), "returned"
		if flag(v, "isError") || flag(obj(v["result"]), "is_error") {
			status = "error"
		}
		p.add("tool_result", stableKey("result", id, p.line), "tool", id, "", status, ts, v["result"])
	case "content.text", "content.thinking":
		p.add("message", key, "assistant", "", "", text(v, "type"), ts, content(v, "text", "content"))
	case "turn.begin", "turn.end", "step.begin", "step.end", "status.update":
		p.add("session", key, "", "", "", text(v, "type"), ts, whole(v))
	default:
		return false
	}
	return true
}

func (p *parser) grok(top row) bool {
	p.identify(text(top, "session_id", "sessionId"))
	ts := eventTime(top)
	key := stableKey("message", text(top, "id"), p.line)
	role := text(top, "role", "type")
	switch role {
	case "system", "user", "assistant":
		if len(top["content"]) > 0 {
			p.add("message", key, role, "", "", "observed", ts, top["content"])
		}
		var calls []row
		_ = json.Unmarshal(top["tool_calls"], &calls)
		for _, c := range calls {
			f, id := obj(c["function"]), text(c, "id")
			if f == nil {
				f = c
			}
			p.add("tool_call", stableKey("call", id, p.line), "assistant", id, text(f, "name"), "proposed", ts, content(f, "arguments", "input"))
		}
		if model := content(top, "model_id", "model"); len(model) > 0 {
			p.add("configuration", key+":model", "", "", "", "observed", ts, whole(row{"model": model}))
		}
	case "tool", "tool_result":
		id, status := text(top, "tool_call_id", "tool_use_id", "id"), "returned"
		if flag(top, "is_error") {
			status = "error"
		}
		p.add("tool_result", stableKey("result", id, p.line), "tool", id, text(top, "name"), status, ts, content(top, "content", "output", "result"))
	default:
		return false
	}
	return true
}
