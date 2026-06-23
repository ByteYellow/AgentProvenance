package observability

import (
	"database/sql"
	"sort"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

const SummarySchemaVersion = "agentprovenance.observability_summary/v1"

type SummaryOptions struct {
	RunID string
	TopN  int
}

type Summary struct {
	SchemaVersion    string            `json:"schema_version"`
	RunID            string            `json:"run_id"`
	EventCount       int               `json:"event_count"`
	Application      ContextSummary    `json:"application"`
	Runtime          RuntimeSummary    `json:"runtime"`
	Risk             RiskSummary       `json:"risk"`
	Baseline         BaselineSummary   `json:"baseline"`
	Response         ResponseSummary   `json:"response"`
	EventTypes       map[string]int    `json:"event_types"`
	Sources          map[string]int    `json:"sources"`
	TopEvidenceRefs  []EvidenceSummary `json:"top_evidence_refs,omitempty"`
	RecommendedViews []string          `json:"recommended_views"`
}

type ContextSummary struct {
	Sessions  int `json:"sessions"`
	Attempts  int `json:"attempts"`
	ToolCalls int `json:"tool_calls"`
	Processes int `json:"processes"`
	Snapshots int `json:"snapshots"`
}

type RuntimeSummary struct {
	Events                int     `json:"events"`
	EventsWithSession     int     `json:"events_with_session"`
	EventsWithToolCall    int     `json:"events_with_tool_call"`
	EventsWithProcess     int     `json:"events_with_process"`
	ToolCallCoverageRatio float64 `json:"tool_call_coverage_ratio"`
	ProcessCoverageRatio  float64 `json:"process_coverage_ratio"`
}

type RiskSummary struct {
	Signals         int            `json:"signals"`
	PolicyDecisions int            `json:"policy_decisions"`
	BySeverity      map[string]int `json:"by_severity,omitempty"`
	ByDecision      map[string]int `json:"by_decision,omitempty"`
}

type BaselineSummary struct {
	Deviations int            `json:"deviations"`
	ByStatus   map[string]int `json:"by_status,omitempty"`
}

type ResponseSummary struct {
	Actions  int            `json:"actions"`
	ByAction map[string]int `json:"by_action,omitempty"`
	ByStatus map[string]int `json:"by_status,omitempty"`
}

type EvidenceSummary struct {
	Ref     string `json:"ref"`
	Type    string `json:"type"`
	Source  string `json:"source"`
	Summary string `json:"summary"`
}

func BuildSummary(db *sql.DB, opts SummaryOptions) (Summary, error) {
	manifest, err := provenance.BuildTimeline(db, provenance.TimelineOptions{RunID: opts.RunID})
	if err != nil {
		return Summary{}, err
	}
	return BuildSummaryFromTimeline(manifest, opts), nil
}

func BuildSummaryFromTimeline(manifest provenance.TimelineManifest, opts SummaryOptions) Summary {
	if opts.TopN <= 0 {
		opts.TopN = 8
	}
	summary := Summary{
		SchemaVersion: SummarySchemaVersion,
		RunID:         manifest.RunID,
		EventCount:    manifest.EventCount,
		EventTypes:    map[string]int{},
		Sources:       map[string]int{},
		Risk: RiskSummary{
			BySeverity: map[string]int{},
			ByDecision: map[string]int{},
		},
		Baseline: BaselineSummary{ByStatus: map[string]int{}},
		Response: ResponseSummary{
			ByAction: map[string]int{},
			ByStatus: map[string]int{},
		},
	}
	sessions := map[string]bool{}
	attempts := map[string]bool{}
	toolCalls := map[string]bool{}
	processes := map[string]bool{}
	snapshots := map[string]bool{}
	for _, event := range manifest.Events {
		summary.EventTypes[event.Type]++
		summary.Sources[event.Source]++
		addIfSet(sessions, event.SessionID)
		addIfSet(attempts, event.AttemptID)
		addIfSet(toolCalls, event.ToolCallID)
		addIfSet(processes, event.ProcessID)
		addIfSet(snapshots, event.SnapshotID)
		if isRuntimeEvent(event) {
			summary.Runtime.Events++
			if event.SessionID != "" {
				summary.Runtime.EventsWithSession++
			}
			if event.ToolCallID != "" {
				summary.Runtime.EventsWithToolCall++
			}
			if event.ProcessID != "" {
				summary.Runtime.EventsWithProcess++
			}
		}
		switch event.Type {
		case "risk_signal":
			summary.Risk.Signals++
			if severity, ok := stringFromMap(event.Risk, "severity"); ok {
				summary.Risk.BySeverity[severity]++
			}
		case "policy_decision":
			summary.Risk.PolicyDecisions++
			if decision, ok := stringFromMap(event.Risk, "decision"); ok {
				summary.Risk.ByDecision[decision]++
			}
		case "baseline_deviation":
			summary.Baseline.Deviations++
			if status, ok := stringFromMap(event.Risk, "status"); ok {
				summary.Baseline.ByStatus[status]++
			}
		case "response_action":
			summary.Response.Actions++
			if action, ok := stringFromMap(event.Risk, "action_type"); ok {
				summary.Response.ByAction[action]++
			}
			if status, ok := stringFromMap(event.Risk, "status"); ok {
				summary.Response.ByStatus[status]++
			}
		}
		if event.ObjectRef != "" && len(summary.TopEvidenceRefs) < opts.TopN {
			summary.TopEvidenceRefs = append(summary.TopEvidenceRefs, EvidenceSummary{
				Ref:     event.ObjectRef,
				Type:    event.Type,
				Source:  event.Source,
				Summary: event.Summary,
			})
		}
	}
	summary.Application = ContextSummary{
		Sessions:  len(sessions),
		Attempts:  len(attempts),
		ToolCalls: len(toolCalls),
		Processes: len(processes),
		Snapshots: len(snapshots),
	}
	if summary.Runtime.Events > 0 {
		summary.Runtime.ToolCallCoverageRatio = float64(summary.Runtime.EventsWithToolCall) / float64(summary.Runtime.Events)
		summary.Runtime.ProcessCoverageRatio = float64(summary.Runtime.EventsWithProcess) / float64(summary.Runtime.Events)
	}
	summary.RecommendedViews = recommendedViews(summary)
	return summary
}

func addIfSet(set map[string]bool, value string) {
	if value != "" {
		set[value] = true
	}
}

func isRuntimeEvent(event provenance.TimelineEvent) bool {
	return isRuntimeEventSource(event.Source)
}

func stringFromMap(values map[string]any, key string) (string, bool) {
	if values == nil {
		return "", false
	}
	value, ok := values[key]
	if !ok {
		return "", false
	}
	text, ok := value.(string)
	return text, ok && text != ""
}

func recommendedViews(summary Summary) []string {
	views := []string{"timeline --run " + summary.RunID, "graph verify --run " + summary.RunID}
	if summary.Runtime.Events > 0 {
		views = append(views, "telemetry list --run "+summary.RunID)
	}
	if summary.Runtime.Events > 0 && summary.Runtime.ToolCallCoverageRatio < 1 {
		views = append(views, "telemetry bindings --run "+summary.RunID)
	}
	if summary.Risk.Signals > 0 || summary.Risk.PolicyDecisions > 0 {
		views = append(views, "security risks --run "+summary.RunID, "policy decisions --run "+summary.RunID)
	}
	if summary.Baseline.Deviations > 0 {
		views = append(views, "security deviations --run "+summary.RunID)
	}
	if summary.Response.Actions > 0 {
		views = append(views, "security responses --run "+summary.RunID)
	}
	sort.Strings(views[1:])
	return views
}
