package observability

import (
	"database/sql"
	"sort"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

const FlowSchemaVersion = "agentprovenance.observability_flow/v1"

type FlowOptions struct {
	RunID string
	Limit int
}

type FlowReport struct {
	SchemaVersion string     `json:"schema_version"`
	RunID         string     `json:"run_id"`
	FlowCount     int        `json:"flow_count"`
	Flows         []FlowItem `json:"flows"`
}

type FlowItem struct {
	Time            string   `json:"time"`
	ToolCallID      string   `json:"tool_call_id,omitempty"`
	ProcessID       string   `json:"process_id,omitempty"`
	EventID         string   `json:"event_id"`
	EventType       string   `json:"event_type"`
	EventSource     string   `json:"event_source"`
	RiskSignals     []string `json:"risk_signals,omitempty"`
	PolicyDecisions []string `json:"policy_decisions,omitempty"`
	ResponseActions []string `json:"response_actions,omitempty"`
	Summary         string   `json:"summary"`
	Drilldowns      []string `json:"drilldowns"`
}

func BuildFlow(db *sql.DB, opts FlowOptions) (FlowReport, error) {
	manifest, err := provenance.BuildTimeline(db, provenance.TimelineOptions{RunID: opts.RunID})
	if err != nil {
		return FlowReport{}, err
	}
	return BuildFlowFromTimeline(manifest, opts), nil
}

func BuildFlowFromTimeline(manifest provenance.TimelineManifest, opts FlowOptions) FlowReport {
	riskByEvent := map[string][]provenance.TimelineEvent{}
	policyByEvent := map[string][]provenance.TimelineEvent{}
	responsesByRisk := map[string][]provenance.TimelineEvent{}
	responsesByPolicy := map[string][]provenance.TimelineEvent{}
	for _, event := range manifest.Events {
		switch event.Type {
		case "risk_signal":
			if eventID := stringValue(event.Evidence, "event_id"); eventID != "" {
				riskByEvent[eventID] = append(riskByEvent[eventID], event)
			}
		case "policy_decision":
			if eventID := stringValue(event.Evidence, "event_id"); eventID != "" {
				policyByEvent[eventID] = append(policyByEvent[eventID], event)
			}
		case "response_action":
			if riskID := stringValue(event.Evidence, "risk_signal_id"); riskID != "" {
				responsesByRisk[riskID] = append(responsesByRisk[riskID], event)
			}
			if policyID := stringValue(event.Evidence, "policy_decision_id"); policyID != "" {
				responsesByPolicy[policyID] = append(responsesByPolicy[policyID], event)
			}
		}
	}
	flows := []FlowItem{}
	for _, event := range manifest.Events {
		if !isRuntimeEvent(event) {
			continue
		}
		item := FlowItem{
			Time:        event.Time,
			ToolCallID:  resolveToolCallForEvent(manifest.Events, event),
			ProcessID:   event.ProcessID,
			EventID:     event.ID,
			EventType:   event.Type,
			EventSource: event.Source,
			Summary:     event.Summary,
		}
		if item.ToolCallID == "" {
			item.ToolCallID = event.ToolCallID
		}
		for _, risk := range riskByEvent[event.ID] {
			item.RiskSignals = append(item.RiskSignals, risk.ID)
			for _, response := range responsesByRisk[risk.ID] {
				item.ResponseActions = append(item.ResponseActions, response.ID)
			}
		}
		for _, policy := range policyByEvent[event.ID] {
			item.PolicyDecisions = append(item.PolicyDecisions, policy.ID)
			for _, response := range responsesByPolicy[policy.ID] {
				item.ResponseActions = append(item.ResponseActions, response.ID)
			}
		}
		item.ResponseActions = uniqueStrings(item.ResponseActions)
		item.Drilldowns = flowDrilldowns(manifest.RunID, item)
		flows = append(flows, item)
	}
	sort.SliceStable(flows, func(i, j int) bool {
		if flows[i].Time == flows[j].Time {
			return flows[i].EventID < flows[j].EventID
		}
		return flows[i].Time < flows[j].Time
	})
	if opts.Limit > 0 && len(flows) > opts.Limit {
		flows = flows[:opts.Limit]
	}
	return FlowReport{
		SchemaVersion: FlowSchemaVersion,
		RunID:         manifest.RunID,
		FlowCount:     len(flows),
		Flows:         flows,
	}
}

func uniqueStrings(items []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, item := range items {
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func flowDrilldowns(runID string, item FlowItem) []string {
	views := []string{"observe event --run " + runID + " --event " + item.EventID, "graph explain --event " + item.EventID}
	if item.ProcessID != "" {
		views = append(views, "observe process --run "+runID+" --process "+item.ProcessID)
	}
	if item.ToolCallID != "" {
		views = append(views, "observe scopes --run "+runID, "timeline --run "+runID+" --tool-call "+item.ToolCallID)
	}
	return views
}
