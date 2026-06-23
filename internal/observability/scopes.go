package observability

import (
	"database/sql"
	"sort"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

const ScopesSchemaVersion = "agentprovenance.observability_scopes/v1"

type ScopesOptions struct {
	RunID string
	Limit int
}

type ScopesReport struct {
	SchemaVersion string         `json:"schema_version"`
	RunID         string         `json:"run_id"`
	ResultSetID   string         `json:"result_set_id"`
	PageHash      string         `json:"page_hash"`
	ScopeCount    int            `json:"scope_count"`
	Scopes        []ScopeSummary `json:"scopes"`
}

type ScopeSummary struct {
	ToolCallID            string            `json:"tool_call_id"`
	SessionID             string            `json:"session_id,omitempty"`
	AttemptID             string            `json:"attempt_id,omitempty"`
	Command               string            `json:"command,omitempty"`
	Status                string            `json:"status,omitempty"`
	StartedAt             string            `json:"started_at,omitempty"`
	EndedAt               string            `json:"ended_at,omitempty"`
	ProcessCount          int               `json:"process_count"`
	RuntimeEvents         int               `json:"runtime_events"`
	RuntimeEventsByType   map[string]int    `json:"runtime_events_by_type,omitempty"`
	RiskSignals           int               `json:"risk_signals"`
	RiskBySeverity        map[string]int    `json:"risk_by_severity,omitempty"`
	PolicyDecisions       int               `json:"policy_decisions"`
	ResponseActions       int               `json:"response_actions"`
	ResponseByAction      map[string]int    `json:"response_by_action,omitempty"`
	EvidenceRefs          []EvidenceSummary `json:"evidence_refs,omitempty"`
	RecommendedDrilldowns []string          `json:"recommended_drilldowns"`
}

func BuildScopes(db *sql.DB, opts ScopesOptions) (ScopesReport, error) {
	manifest, err := provenance.BuildTimeline(db, provenance.TimelineOptions{RunID: opts.RunID})
	if err != nil {
		return ScopesReport{}, err
	}
	return BuildScopesFromTimeline(manifest, opts), nil
}

func BuildScopesFromTimeline(manifest provenance.TimelineManifest, opts ScopesOptions) ScopesReport {
	scopes := map[string]*ScopeSummary{}
	processes := map[string]map[string]bool{}
	processToToolCall := map[string]string{}
	eventToToolCall := map[string]string{}
	for _, event := range manifest.Events {
		if event.ProcessID != "" && event.ToolCallID != "" {
			processToToolCall[event.ProcessID] = event.ToolCallID
		}
		if event.ID != "" && event.ToolCallID != "" && isRuntimeEvent(event) {
			eventToToolCall[event.ID] = event.ToolCallID
		}
	}
	for _, event := range manifest.Events {
		toolCallID := event.ToolCallID
		if toolCallID == "" && event.Type == "tool_call_start" {
			toolCallID = event.ID
		}
		if toolCallID == "" && event.ProcessID != "" {
			toolCallID = processToToolCall[event.ProcessID]
		}
		if toolCallID == "" && event.Type == "policy_decision" {
			if eventID, ok := stringFromMap(event.Evidence, "event_id"); ok {
				toolCallID = eventToToolCall[eventID]
			}
		}
		if toolCallID == "" {
			continue
		}
		scope := scopes[toolCallID]
		if scope == nil {
			scope = &ScopeSummary{
				ToolCallID:          toolCallID,
				RuntimeEventsByType: map[string]int{},
				RiskBySeverity:      map[string]int{},
				ResponseByAction:    map[string]int{},
			}
			scopes[toolCallID] = scope
			processes[toolCallID] = map[string]bool{}
		}
		if scope.SessionID == "" {
			scope.SessionID = event.SessionID
		}
		if scope.AttemptID == "" {
			scope.AttemptID = event.AttemptID
		}
		if event.ProcessID != "" {
			processes[toolCallID][event.ProcessID] = true
		}
		switch event.Type {
		case "tool_call_start":
			scope.StartedAt = event.Time
			if command, ok := stringFromMap(event.Evidence, "command"); ok {
				scope.Command = command
			}
			if status, ok := stringFromMap(event.Evidence, "status"); ok {
				scope.Status = status
			}
		case "tool_call_end":
			scope.EndedAt = event.Time
		case "risk_signal":
			scope.RiskSignals++
			if severity, ok := stringFromMap(event.Risk, "severity"); ok {
				scope.RiskBySeverity[severity]++
			}
		case "policy_decision":
			scope.PolicyDecisions++
		case "response_action":
			scope.ResponseActions++
			if action, ok := stringFromMap(event.Risk, "action_type"); ok {
				scope.ResponseByAction[action]++
			}
		default:
			if isRuntimeEvent(event) {
				scope.RuntimeEvents++
				scope.RuntimeEventsByType[event.Type]++
			}
		}
		if event.ObjectRef != "" && len(scope.EvidenceRefs) < 6 {
			scope.EvidenceRefs = append(scope.EvidenceRefs, EvidenceSummary{
				Ref:     event.ObjectRef,
				Type:    event.Type,
				Source:  event.Source,
				Summary: event.Summary,
			})
		}
	}
	items := make([]ScopeSummary, 0, len(scopes))
	for _, scope := range scopes {
		scope.ProcessCount = len(processes[scope.ToolCallID])
		scope.RecommendedDrilldowns = scopeDrilldowns(manifest.RunID, *scope)
		items = append(items, *scope)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].StartedAt == items[j].StartedAt {
			return items[i].ToolCallID < items[j].ToolCallID
		}
		return items[i].StartedAt < items[j].StartedAt
	})
	allItems := append([]ScopeSummary(nil), items...)
	if opts.Limit > 0 && len(items) > opts.Limit {
		items = items[:opts.Limit]
	}
	resultSetID, pageHash, err := scopesIntegrity(manifest.RunID, allItems, items, opts.Limit)
	if err != nil {
		resultSetID = ""
		pageHash = ""
	}
	return ScopesReport{
		SchemaVersion: ScopesSchemaVersion,
		RunID:         manifest.RunID,
		ResultSetID:   resultSetID,
		PageHash:      pageHash,
		ScopeCount:    len(items),
		Scopes:        items,
	}
}

func scopesIntegrity(runID string, allScopes, pageScopes []ScopeSummary, limit int) (string, string, error) {
	resultSetID, err := digestObservation(map[string]any{
		"kind":   "observability_scopes_result_set",
		"run_id": runID,
		"scopes": scopesDigest(allScopes),
	})
	if err != nil {
		return "", "", err
	}
	pageHash, err := digestObservation(map[string]any{
		"kind":          "observability_scopes_page",
		"result_set_id": resultSetID,
		"limit":         limit,
		"scopes":        pageScopes,
	})
	if err != nil {
		return "", "", err
	}
	return resultSetID, pageHash, nil
}

func scopesDigest(scopes []ScopeSummary) []map[string]any {
	out := make([]map[string]any, 0, len(scopes))
	for _, scope := range scopes {
		out = append(out, map[string]any{
			"tool_call_id":           scope.ToolCallID,
			"session_id":             scope.SessionID,
			"attempt_id":             scope.AttemptID,
			"status":                 scope.Status,
			"process_count":          scope.ProcessCount,
			"runtime_events":         scope.RuntimeEvents,
			"runtime_events_by_type": scope.RuntimeEventsByType,
			"risk_signals":           scope.RiskSignals,
			"risk_by_severity":       scope.RiskBySeverity,
			"policy_decisions":       scope.PolicyDecisions,
			"response_actions":       scope.ResponseActions,
			"response_by_action":     scope.ResponseByAction,
		})
	}
	return out
}

func scopeDrilldowns(runID string, scope ScopeSummary) []string {
	views := []string{"timeline --run " + runID + " --tool-call " + scope.ToolCallID, "graph explain --tool-call " + scope.ToolCallID}
	if scope.RuntimeEvents > 0 {
		views = append(views, "telemetry list --run "+runID+" --tool-call "+scope.ToolCallID)
	}
	if scope.RiskSignals > 0 {
		views = append(views, "security risks --run "+runID)
	}
	return views
}
