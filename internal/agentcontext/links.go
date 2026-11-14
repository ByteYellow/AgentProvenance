package agentcontext

import "context"

// ToolNodeID namespaces a native call identity by run and actor. Transcript and
// hook channels can describe the same invocation, while separate runs cannot
// overwrite each other's graph nodes when a harness reuses a call ID.
func ToolNodeID(e Entry) string {
	return "context-tool-" + digest([]string{e.RunID, e.Source.Harness, e.Source.SessionID, e.AgentID, e.ToolCallID})
}

type GraphLink struct {
	NodeID   string `json:"node_id"`
	Relation string `json:"relation"`
	Basis    string `json:"basis,omitempty"`
	Rule     string `json:"rule,omitempty"`
}

type EntryLinks struct {
	SchemaVersion string      `json:"schema_version"`
	RunID         string      `json:"run_id"`
	EntryID       string      `json:"entry_id"`
	Basis         string      `json:"basis"`
	Links         []GraphLink `json:"links"`
	HasMore       bool        `json:"has_more"`
	Reason        string      `json:"reason,omitempty"`
}

// Links exposes existing graph relationships, never a new matching inference.
// A result without a projected call deliberately has no execution destination.
func (s Service) Links(ctx context.Context, runID, entryID string) (EntryLinks, error) {
	result := EntryLinks{SchemaVersion: SchemaVersion, RunID: runID, EntryID: entryID,
		Basis: "recorded_graph_edge", Links: []GraphLink{}}
	e, err := s.entry(ctx, runID, entryID)
	if err != nil {
		return result, err
	}
	if e.ExecutionScope == PriorContext {
		result.Reason = "prior_context_not_current_execution"
		return result, nil
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT DISTINCT g.to_id, g.edge_type FROM graph_edges g
		WHERE g.run_id=? AND g.from_id=? AND g.edge_type IN ('context_tool_call','context_tool_result','context_notebook_request','context_notebook_caller')
		AND (g.edge_type IN ('context_tool_call','context_tool_result') OR EXISTS (SELECT 1 FROM tool_calls t WHERE t.run_id=g.run_id AND t.id=g.to_id))
		ORDER BY g.to_id, g.edge_type LIMIT 201`, runID, e.ObjectHash)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var link GraphLink
		if err := rows.Scan(&link.NodeID, &link.Relation); err != nil {
			return result, err
		}
		if link.Relation == "context_notebook_request" || link.Relation == "context_notebook_caller" {
			link.Basis, link.Rule = "source_asserted_native_identity", "jupyter-mcp/v1"
		}
		result.Links = append(result.Links, link)
	}
	if err := rows.Err(); err != nil {
		return result, err
	}
	if len(result.Links) > 200 {
		result.HasMore, result.Links = true, result.Links[:200]
	}
	if len(result.Links) == 0 {
		result.Reason = "no_recorded_graph_link"
	}
	if e.NotebookRequest != nil {
		resolved := false
		for _, link := range result.Links {
			resolved = resolved || link.Relation == "context_notebook_request"
		}
		if !resolved {
			result.Reason = "notebook_request_unresolved"
		}
	}
	return result, nil
}
