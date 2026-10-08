package hooksbridge

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
)

// IngestContext projects stored, redacted source records into the existing
// orchestration model. It never opens a current transcript or invents a child
// identity from a spawn call ID. The original context objects remain immutable.
func IngestContext(ctx context.Context, db *sql.DB, paths store.Paths, runID string) (Summary, error) {
	svc := agentcontext.Service{DB: db, Paths: paths}
	var entries []agentcontext.Entry
	cursor := ""
	for {
		page, err := svc.Entries(ctx, agentcontext.PageOptions{RunID: runID, Cursor: cursor, Limit: 200})
		if err != nil {
			return Summary{}, err
		}
		entries = append(entries, page.Entries...)
		if len(entries) > agentcontext.MaxRecords {
			return Summary{}, fmt.Errorf("context graph projection record limit exceeded")
		}
		if !page.HasMore {
			break
		}
		cursor = page.NextCursor
	}
	if len(entries) == 0 {
		return Summary{}, nil
	}
	rootSessions := map[string]bool{}
	for _, e := range entries {
		if e.Source.AgentID == "" && e.Source.ParentSessionID == "" {
			rootSessions[e.Source.SessionID] = true
		}
	}
	agent := func(e agentcontext.Entry) string {
		if e.AgentID != "" {
			return e.AgentID
		}
		return mainAgentID
	}
	var evs []hookEvent
	seenAgents, calls := map[string]bool{}, map[string]hookEvent{}
	observedParents := map[string]string{}
	observe := func(id, parent, ts string) error {
		if old := observedParents[id]; old != "" && old != parent {
			return fmt.Errorf("conflicting context agent parents")
		}
		observedParents[id] = parent
		if !seenAgents[id] {
			evs = append(evs, hookEvent{Event: "AgentObserved", AgentID: id, ParentAgentID: parent, TS: ts})
			seenAgents[id] = true
		}
		return nil
	}
	inputs := map[string]string{}
	results := map[string]hookEvent{}
	budget := int64(64 << 20)
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return Summary{}, err
		}
		if e.ExecutionScope == agentcontext.PriorContext {
			continue
		}
		actor := agent(e)
		if actor != mainAgentID && e.Source.ParentSessionID != "" {
			parent := e.Source.ParentSessionID
			if rootSessions[parent] {
				parent = mainAgentID
			}
			if err := observe(actor, parent, ""); err != nil {
				return Summary{}, err
			}
		}
		switch e.Kind {
		case "tool_call":
			if e.ToolCallID == "" || e.Status == "completion_only" {
				continue
			}
			body, err := contextBody(db, runID, e.Content, &budget)
			if err != nil {
				return Summary{}, err
			}
			var input map[string]any
			_ = json.Unmarshal([]byte(body), &input)
			if input == nil && body != "" {
				input = map[string]any{"raw_input": body}
			}
			name := e.ToolName
			if isCodexShellTool(name) || isGrokShellTool(name) || name == "Bash" {
				if command := firstStr(input, "command", "cmd"); command != "" {
					name = "Bash"
					input["command"] = command
				}
			}
			id := agentcontext.ToolNodeID(e)
			ev := hookEvent{Event: "PreToolUse", AgentID: actor, SessionID: e.Source.SessionID,
				ToolUseID: id, ToolName: name, ToolInput: input, TS: e.RecordedAt}
			canonical, _ := json.Marshal(input)
			if prior, exists := calls[id]; exists {
				if prior.ToolName != name || inputs[id] != string(canonical) {
					return Summary{}, fmt.Errorf("conflicting context tool inputs for %s", id)
				}
				continue
			}
			calls[id], inputs[id] = ev, string(canonical)
		case "tool_result":
			if e.ToolCallID == "" || e.Status == "context_replacement" {
				continue
			}
			id, event := agentcontext.ToolNodeID(e), "PostToolUse"
			if e.Status == "error" {
				event = "PostToolUseFailure"
			}
			if old, exists := results[id]; exists && old.Event != event {
				return Summary{}, fmt.Errorf("conflicting context tool outcomes for %s", id)
			}
			results[id] = hookEvent{Event: event, AgentID: actor, ToolUseID: id, TS: e.RecordedAt}
		case "session":
			if e.ToolName == "spawn_agent" && e.Status == "started" {
				body, err := contextBody(db, runID, e.Content, &budget)
				if err != nil {
					return Summary{}, err
				}
				var spawn struct {
					SessionID string `json:"session_id"`
				}
				if json.Unmarshal([]byte(body), &spawn) == nil && spawn.SessionID != "" {
					if err := observe(spawn.SessionID, actor, e.RecordedAt); err != nil {
						return Summary{}, err
					}
				}
			}
			if e.Source.Channel != "hooks" {
				continue
			}
			body, err := contextBody(db, runID, e.RawContent, &budget)
			if err != nil {
				return Summary{}, err
			}
			var raw map[string]any
			if json.Unmarshal([]byte(body), &raw) != nil {
				continue
			}
			ev := parseEvent(raw)
			ev.RefusalID = "context-refusal-" + e.ID
			switch ev.Event {
			case "SubagentStart", "SubagentStop", "Stop", "StopFailure":
				evs = append(evs, ev)
			}
		}
	}
	if len(evs) == 0 && len(calls) == 0 {
		return Summary{}, nil
	}
	// Conflicting explicit parents cannot be resolved by event iteration order.
	parents := map[string]string{}
	for _, ev := range evs {
		if (ev.Event != "SubagentStart" && ev.Event != "AgentObserved") || ev.ParentAgentID == "" {
			continue
		}
		if old := parents[ev.AgentID]; old != "" && old != ev.ParentAgentID {
			return Summary{}, fmt.Errorf("conflicting context agent parents")
		}
		parents[ev.AgentID] = ev.ParentAgentID
	}
	marks := map[string]int{}
	for id := range parents {
		var path []string
		for id != "" && marks[id] != 2 {
			if marks[id] == 1 {
				return Summary{}, fmt.Errorf("context agent parent cycle")
			}
			marks[id] = 1
			path = append(path, id)
			id = parents[id]
		}
		for _, id := range path {
			marks[id] = 2
		}
	}
	ids := make([]string, 0, len(calls))
	for id := range calls {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		evs = append(evs, calls[id])
		if result, ok := results[id]; ok {
			evs = append(evs, result)
		}
	}
	// Source timestamps order independent sessions; stable ordering keeps a call
	// before its result when source clocks are absent or equal.
	sort.SliceStable(evs, func(i, j int) bool {
		a, aerr := time.Parse(time.RFC3339Nano, evs[i].TS)
		b, berr := time.Parse(time.RFC3339Nano, evs[j].TS)
		if aerr != nil || berr != nil {
			return aerr != nil && berr == nil
		}
		return a.Before(b)
	})
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return Summary{}, err
	}
	defer tx.Rollback()
	sum, err := ingestEventRows(tx, evs, Options{RunID: runID, PostHoc: true, Objects: provenance.ObjectStore{DB: db, Paths: paths, Tx: tx}})
	if err != nil {
		return sum, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE graph_edges SET source_event_id='agent_context'
		WHERE run_id=? AND edge_type IN ('agent_spawn','agent_message','agent_tool_call')`, runID); err != nil {
		return sum, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM graph_edges WHERE run_id=? AND edge_type IN ('context_tool_call','context_tool_result')`, runID); err != nil {
		return sum, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM tool_calls WHERE run_id=? AND agent_id != ''`, runID)
	if err != nil {
		return sum, err
	}
	existing := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return sum, err
		}
		existing[id] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return sum, err
	}
	for _, e := range entries {
		if e.ExecutionScope == agentcontext.PriorContext {
			continue
		}
		if (e.Kind != "tool_call" && e.Kind != "tool_result") || e.ToolCallID == "" {
			continue
		}
		id := agentcontext.ToolNodeID(e)
		// Delegation and peer messages use their own orchestration edges. A late
		// result without this run's call must not invent an executed tool node.
		if existing[id] {
			if err := writeEdge(tx, runID, e.ObjectHash, id, "context_"+e.Kind, e.RecordedAt); err != nil {
				return sum, err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE graph_edges SET source_event_id='agent_context'
		WHERE run_id=? AND edge_type IN ('context_tool_call','context_tool_result')`, runID); err != nil {
		return sum, err
	}
	return sum, tx.Commit()
}

func contextBody(db *sql.DB, runID string, ref agentcontext.ContentRef, budget *int64) (string, error) {
	if ref.State != "stored" {
		return "", nil
	}
	var body strings.Builder
	var offset int64
	for {
		page, err := provenance.ReadTextContentPage(db, runID, ref.Ref, offset, 256<<10)
		if err != nil {
			return "", err
		}
		*budget -= int64(len(page.Content))
		if *budget < 0 {
			return "", fmt.Errorf("context graph projection content limit exceeded")
		}
		body.WriteString(page.Content)
		if !page.HasMore {
			return body.String(), nil
		}
		offset = page.NextOffset
	}
}
