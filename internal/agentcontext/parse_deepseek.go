package agentcontext

import (
	"fmt"
	"strconv"
)

func (p *parser) deepseek(top row) bool {
	typ, ts := text(top, "type"), eventTime(top)
	if typ == "session" {
		version, err := strconv.Atoi(string(top["version"]))
		if err != nil || (version != 3 && version != 4) {
			p.unsupported = true
			p.issue("unsupported_format_version", "version")
			return false
		}
		p.Source.FormatVersion = strconv.Itoa(version)
		p.identify(text(top, "id"))
		p.Source.ParentSessionID = text(top, "parentSession")
		if text(top, "origin") == "subagent" {
			p.Source.AgentID = p.Source.SessionID
		}
		p.Source.Workdir = text(top, "cwd")
		p.add("configuration", stableKey("session", p.Source.SessionID, p.line), "", "", "", "session_metadata", ts, whole(top))
		return true
	}
	if p.Source.FormatVersion == "" {
		p.unsupported = true
		p.issue("format_header_missing", "version")
		return false
	}
	v := obj(top["data"])
	if v == nil {
		return false
	}
	seq, err := strconv.ParseInt(string(top["seq"]), 10, 64)
	if err != nil || seq < 0 {
		p.issue("invalid_sequence", "seq")
		return false
	}
	key := fmt.Sprintf("event:%d", seq)
	msg := obj(v["message"])
	switch typ {
	case "user/message", "assistant/message", "system/message", "developer/message":
		if msg == nil && typ == "user/message" {
			msg = v
		}
		if msg == nil {
			p.issue("message_missing", "data.message")
			return false
		}
		status := "observed"
		if flag(v, "interrupted") {
			status = "source_truncated"
			*p.counts().Truncated++
		}
		p.add("message", key, text(msg, "role"), "", "", status, ts, msg["content"])
	case "tool/call":
		p.add("tool_call", key, "assistant", text(v, "callId"), text(v, "name"), "proposed", ts, v["arguments"])
	case "tool/result":
		if msg == nil {
			p.issue("tool_result_missing", "data.message")
			return false
		}
		status := "returned"
		if flag(msg, "isError") {
			status = "error"
		}
		// Preserve internal error reasons and result-time file diffs alongside
		// the model-facing result instead of discarding them during adaptation.
		p.add("tool_result", key, "tool", text(msg, "toolCallId"), "", status, ts, whole(v))
	case "request/header", "request/context", "model/selection", "sandbox/mode", "permission/preset", "approval/policy", "plan/mode", "agent-preset/selected", "subagent/model-selection-policy":
		p.add("configuration", key, "", "", "", typ, ts, whole(v))
	case "approval/asked":
		p.add("approval", key, "", text(v, "callId", "toolCallId"), "", "requested", ts, whole(v))
	case "approval/decided":
		p.add("approval", key, "", text(v, "callId", "toolCallId"), "", "decision_recorded", ts, whole(v))
	case "goal/change":
		p.add("task", key, "user", "", "", "changed", ts, whole(v))
	case "assistant/attempt":
		p.add("message", key, "assistant", "", "", "uncommitted_attempt", ts, whole(v))
	case "turn/start", "turn/end", "step/start", "step/end", "session/end-seed", "session/title",
		"compaction/start", "compaction/end", "compaction/prune", "compaction/summary", "image/offload",
		"llm/retry", "llm/retry-started", "hook/invoked", "hook/result",
		"subagent/descriptor", "subagent/catalog", "agent/inbox/spliced", "team/member",
		"team/message/delivered", "team/message/queued", "team/task", "workspace/changes",
		"todo/write", "deliverables/presented", "schedule/change", "command/run", "command/done",
		"tool/ptc-dispatch", "tool/ptc-dispatch-start", "tool-workflow/run-start", "tool-workflow/run-end",
		"tool-workflow/agent-start", "tool-workflow/agent-end", "session/title-llm-request",
		"session-log-deepseek/delivery-accepted", "web/deepseek-search-llm-request",
		"feedback/message-delete", "feedback/message-put", "feedback/record":
		p.add("session", key, "", "", "", typ, ts, whole(v))
	default:
		p.add("session", key, "", "", "", "unrecognized", ts, whole(top))
		return false
	}
	return true
}
