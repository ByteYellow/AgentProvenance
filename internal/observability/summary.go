package observability

import (
	"database/sql"
	"sort"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/signals"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

const SummarySchemaVersion = "agentprovenance.observability_summary/v1"

type SummaryOptions struct {
	RunID string
	TopN  int
}

type Summary struct {
	SchemaVersion    string            `json:"schema_version"`
	RunID            string            `json:"run_id"`
	ResultSetID      string            `json:"result_set_id"`
	PageHash         string            `json:"page_hash"`
	EventCount       int               `json:"event_count"`
	Application      ContextSummary    `json:"application"`
	Runtime          RuntimeSummary    `json:"runtime"`
	Windows          WindowSummary     `json:"windows"`
	Risk             RiskSummary       `json:"risk"`
	Baseline         BaselineSummary   `json:"baseline"`
	Response         ResponseSummary   `json:"response"`
	Signals          SignalSummary     `json:"signals"`
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

type WindowSummary struct {
	WindowCount       int            `json:"window_count"`
	WindowSeconds     []int          `json:"window_seconds,omitempty"`
	AggregateWindow   int            `json:"aggregate_window_seconds,omitempty"`
	EventCount        int            `json:"event_count"`
	ResolvedCount     int            `json:"resolved_count"`
	UnresolvedCount   int            `json:"unresolved_count"`
	HighRiskCount     int            `json:"high_risk_count"`
	ByType            map[string]int `json:"by_type,omitempty"`
	BySource          map[string]int `json:"by_source,omitempty"`
	LatestWindowStart string         `json:"latest_window_start,omitempty"`
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

// SignalSummary is the per-dimension rollup of the unified signal model
// (behavior/cost/quality/security), surfacing the two-pillars-plus-cost shape
// in the primary observability output.
type SignalSummary struct {
	Total       int            `json:"total"`
	ByDimension map[string]int `json:"by_dimension,omitempty"`
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
	summary := BuildSummaryFromTimeline(manifest, opts)
	windowSummary, err := BuildWindowSummary(db, opts.RunID)
	if err != nil {
		return Summary{}, err
	}
	summary.Windows = windowSummary
	signalCounts, err := signals.Counts(db, opts.RunID)
	if err != nil {
		return Summary{}, err
	}
	sigSummary := SignalSummary{ByDimension: map[string]int{}}
	for dim, n := range signalCounts {
		sigSummary.ByDimension[string(dim)] = n
		sigSummary.Total += n
	}
	summary.Signals = sigSummary
	summary.RecommendedViews = recommendedViews(summary)
	resultSetID, pageHash, err := summaryIntegrity(summary, opts.TopN)
	if err == nil {
		summary.ResultSetID = resultSetID
		summary.PageHash = pageHash
	}
	return summary, nil
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
		Windows: WindowSummary{
			ByType:   map[string]int{},
			BySource: map[string]int{},
		},
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
	resultSetID, pageHash, err := summaryIntegrity(summary, opts.TopN)
	if err == nil {
		summary.ResultSetID = resultSetID
		summary.PageHash = pageHash
	}
	return summary
}

func BuildWindowSummary(db *sql.DB, runID string) (WindowSummary, error) {
	result, err := telemetry.ListEventWindows(db, telemetry.EventWindowFilter{RunID: runID})
	if err != nil {
		return WindowSummary{}, err
	}
	summary := WindowSummary{
		WindowCount:     result.WindowCount,
		AggregateWindow: 60,
		ByType:          map[string]int{},
		BySource:        map[string]int{},
	}
	secondsSeen := map[int]bool{}
	for _, window := range result.Windows {
		secondsSeen[window.WindowSeconds] = true
		if window.WindowStart > summary.LatestWindowStart {
			summary.LatestWindowStart = window.WindowStart
		}
		if window.WindowSeconds != summary.AggregateWindow {
			continue
		}
		summary.EventCount += window.EventCount
		summary.ResolvedCount += window.ResolvedCount
		summary.UnresolvedCount += window.UnresolvedCount
		summary.HighRiskCount += window.HighRiskCount
		summary.ByType[window.EventType] += window.EventCount
		summary.BySource[window.Source] += window.EventCount
	}
	for seconds := range secondsSeen {
		summary.WindowSeconds = append(summary.WindowSeconds, seconds)
	}
	sort.Ints(summary.WindowSeconds)
	if summary.EventCount == 0 && len(result.Windows) > 0 {
		summary.AggregateWindow = 0
		for _, window := range result.Windows {
			summary.EventCount += window.EventCount
			summary.ResolvedCount += window.ResolvedCount
			summary.UnresolvedCount += window.UnresolvedCount
			summary.HighRiskCount += window.HighRiskCount
			summary.ByType[window.EventType] += window.EventCount
			summary.BySource[window.Source] += window.EventCount
		}
	}
	return summary, nil
}

func summaryIntegrity(summary Summary, topN int) (string, string, error) {
	resultSetID, err := digestObservation(map[string]any{
		"kind":        "observability_summary_result_set",
		"run_id":      summary.RunID,
		"event_count": summary.EventCount,
		"application": summary.Application,
		"runtime":     summary.Runtime,
		"windows":     summary.Windows,
		"risk":        summary.Risk,
		"baseline":    summary.Baseline,
		"response":    summary.Response,
		"event_types": summary.EventTypes,
		"sources":     summary.Sources,
	})
	if err != nil {
		return "", "", err
	}
	pageHash, err := digestObservation(map[string]any{
		"kind":              "observability_summary_page",
		"result_set_id":     resultSetID,
		"top":               topN,
		"top_evidence_refs": summary.TopEvidenceRefs,
		"recommended_views": summary.RecommendedViews,
	})
	if err != nil {
		return "", "", err
	}
	return resultSetID, pageHash, nil
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
	if summary.Windows.WindowCount > 0 {
		views = append(views, "telemetry windows --run "+summary.RunID+" --window 60 --json")
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
