package provenance

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/correlation"
)

const (
	llmCommandRule       = "agentprov.intent_command_scope/v2"
	llmCommandEdgePrefix = "llm-command-v2-"
	llmCommandConfidence = 0.8
	llmCommandWindow     = 2 * time.Minute
	maxLLMActions        = 200000
	maxLLMDecisions      = 10000
	maxLLMMatchBytes     = 64 << 20
	maxLLMComparisons    = 2000000
)

type llmQueryer interface {
	Query(string, ...any) (*sql.Rows, error)
}

type llmScope struct {
	source, origin, cgroup, container, session string
}

type llmDecision struct {
	node, sourceEvent, command string
	at                         time.Time
	scope                      llmScope
	transcript                 bool
	toolID, agentID, sessionID string
}

type llmToolAnchor struct {
	id, agentID, sessionID, command string
	start, end                      time.Time
}

type llmAction struct {
	id        string
	argv      []string
	at        time.Time
	scope     llmScope
	pid       int64
	truncated bool
	tools     []llmToolAnchor
}

// The two-sided uniqueness check is deliberately conservative: a repeated
// command is not resolved by choosing the closest timestamp or by input order.
func matchLLMDecisions(decisions []llmDecision, actions []llmAction) (map[int]string, error) {
	if len(decisions) > maxLLMDecisions {
		return nil, fmt.Errorf("model command correlation decision limit exceeded")
	}
	candidates := make([][]int, len(decisions))
	owners := make([]int, len(actions))
	comparisons := 0
	for i, d := range decisions {
		if d.at.IsZero() || strings.TrimSpace(d.command) == "" {
			continue
		}
		for j, a := range actions {
			comparisons++
			if comparisons > maxLLMComparisons {
				return nil, fmt.Errorf("model command correlation comparison limit exceeded")
			}
			if !a.at.After(d.at) || a.at.Sub(d.at) > llmCommandWindow || a.truncated || !llmActionMatches(a, d.command) {
				continue
			}
			if d.transcript {
				if !transcriptAnchorMatches(d, a) {
					continue
				}
			} else if !llmScopesMatch(d.scope, a.scope) {
				continue
			}
			candidates[i] = append(candidates[i], j)
			owners[j]++
		}
	}
	out := make(map[int]string)
	for i, matches := range candidates {
		if len(matches) == 1 && owners[matches[0]] == 1 {
			out[i] = "runtime_event/" + actions[matches[0]].id
		}
	}
	return out, nil
}

func llmScopesMatch(a, b llmScope) bool {
	// Cgroup IDs are kernel-local. A shared Run alone is not a capture origin.
	if a.origin == "" || a.origin != b.origin || a.source == "" || a.source != b.source {
		return false
	}
	if (a.session != "" && b.session != "" && a.session != b.session) ||
		(a.cgroup != "" && b.cgroup != "" && a.cgroup != b.cgroup) ||
		(a.container != "" && b.container != "" && a.container != b.container) {
		return false
	}
	return (a.cgroup != "" && a.cgroup == b.cgroup) || (a.container != "" && a.container == b.container)
}

func transcriptAnchorMatches(d llmDecision, a llmAction) bool {
	if d.toolID == "" {
		return false
	}
	for _, tool := range a.tools {
		if tool.id != d.toolID {
			return false
		}
	}
	for _, tool := range a.tools {
		if tool.id != d.toolID || strings.TrimSpace(tool.command) != strings.TrimSpace(d.command) ||
			(d.agentID != "" && d.agentID != tool.agentID) ||
			(d.sessionID != "" && tool.sessionID != "" && d.sessionID != tool.sessionID) {
			continue
		}
		if !tool.start.IsZero() && !tool.end.IsZero() && !tool.start.Before(d.at) &&
			!a.at.Before(tool.start) && !a.at.After(tool.end) {
			return true
		}
	}
	return false
}

func llmActionMatches(a llmAction, decided string) bool {
	if len(a.argv) > 0 {
		if args := plainCommandArgs(decided); len(args) > 0 {
			// Prefer the actual program argv for plain commands, not both its
			// shell launcher and the program as competing executions.
			return slices.Equal(a.argv, args)
		}
		// A complete shell -c argv preserves the exact script, including quotes,
		// expansions and whitespace. Do not unwrap scripts with extra arguments.
		if len(a.argv) == 3 && (a.argv[1] == "-c" || a.argv[1] == "-lc") {
			switch path.Base(a.argv[0]) {
			case "sh", "bash", "zsh":
				return a.argv[2] == decided
			}
		}
	}
	return false
}

// Only plain arguments are compared to argv without interpreting shell syntax.
// Complex commands require a complete shell -c script; joined command strings
// alone have lost their argument boundaries and are not execution anchors.
func plainCommandArgs(s string) []string {
	if strings.ContainsAny(s, "\"'\\$`|&;<>(){}[]*?~\n\r\x00") {
		return nil
	}
	return strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == '\t' })
}

func llmPayloadFields(payload string) []map[string]any {
	var outer map[string]any
	if json.Unmarshal([]byte(payload), &outer) != nil {
		return nil
	}
	inner, _ := outer["payload"].(map[string]any)
	raw, _ := inner["raw"].(map[string]any)
	flatRaw, _ := outer["raw"].(map[string]any)
	return []map[string]any{raw, inner, flatRaw, outer}
}

func llmOrigin(payload string, pid int64) string {
	fields := llmPayloadFields(payload)
	for _, m := range fields {
		instance, _ := m["process_instance_id"].(string)
		if boot := correlation.ProcessInstanceBootID(instance, pid); boot != "" {
			return "boot:" + boot
		}
	}
	for _, m := range fields {
		for _, k := range []string{"node_name", "node", "host_id", "hostname", "producer_id"} {
			if s, ok := m[k].(string); ok && s != "" {
				return "origin:" + s
			}
		}
	}
	return ""
}

func readLLMActions(db llmQueryer, runID string, withTools bool) ([]llmAction, error) {
	rows, err := db.Query(`SELECT id,created_at,source,COALESCE(session_id,''),cgroup_id,container_id,pid,substr(payload,1,65537)
		FROM events WHERE run_id=? AND event_type='execve' ORDER BY id LIMIT ?`, runID, maxLLMActions+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var actions []llmAction
	count, size := 0, 0
	for rows.Next() {
		var a llmAction
		var ts, payload string
		if err := rows.Scan(&a.id, &ts, &a.scope.source, &a.scope.session, &a.scope.cgroup, &a.scope.container, &a.pid, &payload); err != nil {
			return nil, err
		}
		count++
		size += len(payload)
		if count > maxLLMActions || size > maxLLMMatchBytes || len(payload) > 65536 {
			return nil, fmt.Errorf("model command correlation event-input limit exceeded")
		}
		a.at, err = time.Parse(time.RFC3339Nano, ts)
		if err != nil || a.pid <= 0 {
			continue
		}
		a.scope.origin = llmOrigin(payload, a.pid)
		for _, m := range llmPayloadFields(payload) {
			if truncated, _ := m["argv_truncated"].(bool); truncated {
				a.truncated = true
			}
			if raw, ok := m["argv"]; ok && a.argv == nil {
				items, ok := raw.([]any)
				if !ok || len(items) == 0 {
					a.truncated = true
				}
				for _, item := range items {
					arg, ok := item.(string)
					if !ok {
						a.truncated = true
					}
					a.argv = append(a.argv, arg)
				}
			}
		}
		actions = append(actions, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if !withTools {
		return actions, nil
	}
	// Only the current, direct exec anchor is reusable. Inherited child edges
	// and legacy unversioned command matches are not exact tool-use anchors.
	rows, err = db.Query(`SELECT g.to_id,t.id,t.agent_id,t.session_id,substr(t.command,1,65537),COALESCE(t.started_at,''),COALESCE(t.ended_at,'')
		FROM graph_edges g JOIN tool_calls t ON t.id=g.from_id AND t.run_id=g.run_id
		WHERE g.run_id=? AND g.edge_type='agent_syscall' AND g.id LIKE ?
		AND g.to_id='runtime_event/' || g.source_event_id ORDER BY g.id LIMIT ?`,
		runID, correlation.AppProcessEdgePrefix+"%", maxLLMActions+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byID := make(map[string]int, len(actions))
	for i, a := range actions {
		byID["runtime_event/"+a.id] = i
	}
	count = 0
	for rows.Next() {
		var node, start, end string
		var tool llmToolAnchor
		if err := rows.Scan(&node, &tool.id, &tool.agentID, &tool.sessionID, &tool.command, &start, &end); err != nil {
			return nil, err
		}
		count++
		size += len(tool.command)
		if count > maxLLMActions || size > maxLLMMatchBytes || len(tool.command) > 65536 {
			return nil, fmt.Errorf("model command correlation tool-input limit exceeded")
		}
		tool.start, _ = time.Parse(time.RFC3339Nano, start)
		tool.end, _ = time.Parse(time.RFC3339Nano, end)
		if i, ok := byID[node]; ok {
			actions[i].tools = append(actions[i].tools, tool)
		}
	}
	return actions, rows.Err()
}
