package observability

import "github.com/byteyellow/agentprovenance/internal/provenance"

type QuerySurface struct {
	Lane              string   `json:"lane,omitempty"`
	CorrelationStatus string   `json:"correlation_status,omitempty"`
	Drilldowns        []string `json:"drilldowns,omitempty"`
}

func querySurface(runID string, event provenance.TimelineEvent) QuerySurface {
	lane := event.Lane
	if lane == "" {
		lane = inferredLane(event)
	}
	status := event.CorrelationStatus
	if status == "" {
		status = inferredCorrelationStatus(event, lane)
	}
	drilldowns := append([]string{}, event.Drilldowns...)
	if len(drilldowns) == 0 {
		drilldowns = timelineCompatibleDrilldowns(runID, event, lane)
	}
	return QuerySurface{
		Lane:              lane,
		CorrelationStatus: status,
		Drilldowns:        uniqueStrings(drilldowns),
	}
}

func inferredLane(event provenance.TimelineEvent) string {
	switch event.Source {
	case "application_context":
		return "agent_context"
	case "runtime":
		return "runtime_process"
	case "security":
		return "risk_policy"
	case "evidence":
		return "evidence"
	case "effect":
		return "external_effect"
	default:
		return "runtime_telemetry"
	}
}

func inferredCorrelationStatus(event provenance.TimelineEvent, lane string) string {
	if lane != "runtime_telemetry" && lane != "runtime_process" {
		return ""
	}
	hasToolCall := event.ToolCallID != ""
	hasProcess := event.ProcessID != ""
	switch {
	case hasToolCall && hasProcess:
		return "full"
	case hasToolCall || hasProcess:
		return "partial"
	default:
		return "gap"
	}
}

func timelineCompatibleDrilldowns(runID string, event provenance.TimelineEvent, lane string) []string {
	out := []string{}
	if event.ID != "" {
		switch lane {
		case "runtime_telemetry":
			out = append(out, "observe event --run "+runID+" --event "+event.ID, "graph explain --event "+event.ID)
		case "runtime_process":
			out = append(out, "observe process --run "+runID+" --process "+event.ProcessID, "graph explain --process "+event.ProcessID)
		}
	}
	if event.ProcessID != "" {
		out = append(out, "observe process --run "+runID+" --process "+event.ProcessID)
	}
	if event.ToolCallID != "" {
		out = append(out, "timeline --run "+runID+" --tool-call "+event.ToolCallID+" --view causality")
	}
	return out
}
