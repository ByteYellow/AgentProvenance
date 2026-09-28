package agentcontext

import (
	"encoding/json"
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
		if typ == "assistant/message" {
			var blocks []row
			_ = json.Unmarshal(msg["content"], &blocks)
			for i, block := range blocks {
				if text(block, "type") == "tool-call" {
					id := text(block, "id")
					callKey := stableKey("call", id, p.line)
					if id == "" {
						callKey += fmt.Sprintf(":block:%d", i)
					}
					p.add("tool_call", callKey, "assistant", id, text(block, "name"), "model_proposal", ts, block["arguments"])
				}
			}
		}
	case "tool/call":
		id := text(v, "callId")
		p.add("tool_call", stableKey("call", id, p.line), "assistant", id, text(v, "name"), "proposed", ts, v["arguments"])
		p.startedCalls[id] = true
	case "tool/result":
		if msg == nil {
			p.issue("tool_result_missing", "data.message")
			return false
		}
		id, sourceID := text(msg, "toolCallId"), text(obj(msg["source"]), "callId")
		if id != "" && sourceID != "" && id != sourceID {
			p.issue("tool_identity_conflict", "data.message.source.callId")
			p.add("session", key, "tool", "", "", "tool_identity_conflict", ts, whole(v))
			return true
		}
		if id == "" {
			id = sourceID
		}
		status := deepseekResultStatus(msg)
		if text(obj(top["surfaceOp"]), "op") == "replace" {
			status = "context_replacement"
		}
		// Preserve internal error reasons and result-time file diffs alongside
		// the model-facing result instead of discarding them during adaptation.
		p.add("tool_result", key, "tool", id, "", status, ts, whole(v))
	case "tool/ptc-dispatch-start", "tool/ptc-dispatch":
		id, name := text(v, "subCallId"), text(v, "name")
		if typ == "tool/ptc-dispatch-start" {
			p.add("tool_call", stableKey("call", id, p.line), "assistant", id, name, "proposed", ts, v["arguments"])
			p.startedCalls[id] = true
		} else {
			if id == "" || !p.startedCalls[id] {
				// A completion can report arguments without proving when the
				// invocation started. Do not create a runtime matching interval.
				before := len(p.Records)
				p.add("tool_call", stableKey("call", id, p.line), "assistant", id, name, "completion_only", ts, v["arguments"])
				if len(p.Records) > before {
					p.Records[len(p.Records)-1].MissingFields = append(p.Records[len(p.Records)-1].MissingFields, "tool_start_time")
				}
			}
			p.add("tool_result", key, "tool", id, name, deepseekResultStatus(v), ts, whole(v))
		}
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
		"tool-workflow/run-start", "tool-workflow/run-end",
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

func deepseekResultStatus(message row) string {
	if flag(message, "isError") {
		return "error"
	}
	// Older supported logs may wrap the outcome in a typed result block.
	// Arbitrary JSON fields and the words in tool output are not status signals.
	var blocks []row
	_ = json.Unmarshal(message["content"], &blocks)
	for _, block := range blocks {
		if text(block, "type") == "tool-result" && flag(block, "isError") {
			return "error"
		}
	}
	return "returned"
}
