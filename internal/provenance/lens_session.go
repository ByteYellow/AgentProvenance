package provenance

import (
	"errors"
	"strings"
)

var ErrSessionFocus = errors.New("focus is outside the recorded session graph")

// GraphSessionScope contains identifiers resolved from recorded native context
// and graph edges, not the older execution-scope sessions table.
type GraphSessionScope struct {
	Harness     string                          `json:"harness"`
	SessionID   string                          `json:"session_id"`
	SourceIDs   []string                        `json:"source_ids"`
	ToolIDs     []string                        `json:"tool_node_ids"`
	EventIDs    []string                        `json:"event_ids"`
	Audit       *SessionAuditScope              `json:"audit,omitempty"`
	AuditEvents map[string]SessionAuditRelation `json:"audit_events,omitempty"`
}

// These are reading-scope projections, never recorded Session assignments.
type SessionAuditRelation struct {
	Status       string   `json:"status"`
	Rule         string   `json:"rule"`
	Basis        string   `json:"basis"`
	Reason       string   `json:"reason,omitempty"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
}

type SessionAuditScope struct {
	Status       string   `json:"status"`
	Rule         string   `json:"rule"`
	RelatedCount int      `json:"related_count"`
	Issues       []string `json:"issues,omitempty"`
}

type GraphSessionQuery struct {
	Harness   string             `json:"harness"`
	SessionID string             `json:"session_id"`
	Basis     string             `json:"basis"`
	Sources   int                `json:"source_count"`
	Tools     int                `json:"tool_count"`
	Events    int                `json:"event_count"`
	Audit     *SessionAuditScope `json:"audit,omitempty"`
}

func (s *GraphSessionScope) query() *GraphSessionQuery {
	if s == nil {
		return nil
	}
	basis := "recorded_context_tool_runtime_edges"
	if len(s.AuditEvents) > 0 {
		basis = "recorded_context_tool_runtime_edges_and_audit_reading_scope"
	}
	return &GraphSessionQuery{Harness: s.Harness, SessionID: s.SessionID, Basis: basis, Sources: len(s.SourceIDs), Tools: len(s.ToolIDs), Events: len(s.EventIDs), Audit: s.Audit}
}

// Scope before aggregation so summary counts and derived edges use only the
// selected observations. Process, agent and file nodes are boundary context;
// reaching one never pulls in its other calls, events or sessions.
func sessionLensData(scope *GraphSessionScope, nodes map[string]GraphLensNode, events map[string]lensEvent, edges []GraphLensEdge) (map[string]GraphLensNode, map[string]lensEvent, []GraphLensEdge) {
	if scope == nil {
		return nodes, events, edges
	}
	used, tools := map[string]bool{}, map[string]bool{}
	scopedEvents := map[string]lensEvent{}
	for _, id := range scope.ToolIDs {
		used[id], tools[id] = true, true
	}
	for _, id := range scope.EventIDs {
		key := "runtime_event/" + id
		if ev, ok := events[key]; ok {
			used[key] = true
			scopedEvents[key] = ev
		}
	}
	for _, edge := range edges {
		_, eventFrom := scopedEvents[edge.FromID]
		_, eventTo := scopedEvents[edge.ToID]
		switch edge.EdgeType {
		case "runtime_process_event":
			if eventTo {
				used[edge.FromID] = true
			}
		case "agent_tool_call":
			if tools[edge.ToID] {
				used[edge.FromID] = true
			}
		case "runtime_event_file", "runtime_event_policy_decision":
			if eventFrom {
				used[edge.ToID] = true
			}
		}
	}
	for _, kind := range []string{"policy_decision_risk_signal", "risk_signal_response_action"} {
		for _, edge := range edges {
			if edge.EdgeType == kind && used[edge.FromID] {
				used[edge.ToID] = true
			}
		}
	}
	outNodes := map[string]GraphLensNode{}
	for id := range used {
		if n, ok := nodes[id]; ok {
			if relation, exists := scope.AuditEvents[strings.TrimPrefix(id, "runtime_event/")]; exists && n.Kind == "runtime_event" {
				data := make(map[string]any, len(n.Data)+1)
				for key, value := range n.Data {
					data[key] = value
				}
				data["session_association"] = relation
				n.Data = data
			}
			outNodes[id] = n
		} else {
			outNodes[id] = inferLensNode(id)
		}
	}
	outEdges := []GraphLensEdge{}
	for _, edge := range edges {
		if !used[edge.FromID] || !used[edge.ToID] {
			continue
		}
		if _, actualEvent := events["runtime_event/"+edge.SourceEventID]; actualEvent {
			if _, selected := scopedEvents["runtime_event/"+edge.SourceEventID]; !selected {
				continue
			}
		}
		outEdges = append(outEdges, edge)
	}
	return outNodes, scopedEvents, outEdges
}
