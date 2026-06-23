package observability

import (
	"database/sql"
	"sort"

	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

const CoverageSchemaVersion = "agentprovenance.observability_coverage/v1"

type CoverageOptions struct {
	RunID string
	Limit int
}

type CoverageReport struct {
	SchemaVersion string           `json:"schema_version"`
	RunID         string           `json:"run_id"`
	Summary       CoverageSummary  `json:"summary"`
	MissingFields map[string]int   `json:"missing_fields"`
	BySource      map[string]int   `json:"by_source"`
	ByType        map[string]int   `json:"by_type"`
	Gaps          []CorrelationGap `json:"gaps,omitempty"`
	NextSteps     []string         `json:"next_steps"`
}

type CoverageSummary struct {
	RuntimeEvents         int     `json:"runtime_events"`
	FullyCorrelated       int     `json:"fully_correlated"`
	MissingSession        int     `json:"missing_session"`
	MissingToolCall       int     `json:"missing_tool_call"`
	MissingProcess        int     `json:"missing_process"`
	FullyCorrelatedRatio  float64 `json:"fully_correlated_ratio"`
	ToolCallCoverageRatio float64 `json:"tool_call_coverage_ratio"`
	ProcessCoverageRatio  float64 `json:"process_coverage_ratio"`
	CorrelationGapCount   int     `json:"correlation_gap_count"`
}

type CorrelationGap struct {
	EventID               string   `json:"event_id"`
	RawEventID            string   `json:"raw_event_id,omitempty"`
	Source                string   `json:"source"`
	Type                  string   `json:"type"`
	Missing               []string `json:"missing"`
	CorrelationMethod     string   `json:"correlation_method,omitempty"`
	CorrelationConfidence float64  `json:"correlation_confidence"`
	ContainerID           string   `json:"container_id,omitempty"`
	CgroupID              string   `json:"cgroup_id,omitempty"`
	PID                   int64    `json:"pid,omitempty"`
	PPID                  int64    `json:"ppid,omitempty"`
	CreatedAt             string   `json:"created_at"`
	SuggestedBinding      string   `json:"suggested_binding"`
}

func BuildCoverage(db *sql.DB, opts CoverageOptions) (CoverageReport, error) {
	events, err := telemetry.ListEventsFiltered(db, telemetry.Filter{RunID: opts.RunID})
	if err != nil {
		return CoverageReport{}, err
	}
	return BuildCoverageFromEvents(opts.RunID, events, opts), nil
}

func BuildCoverageFromEvents(runID string, events []telemetry.EventRecord, opts CoverageOptions) CoverageReport {
	report := CoverageReport{
		SchemaVersion: CoverageSchemaVersion,
		RunID:         runID,
		MissingFields: map[string]int{},
		BySource:      map[string]int{},
		ByType:        map[string]int{},
	}
	for _, event := range events {
		if !isTelemetrySource(event.Source) {
			continue
		}
		report.Summary.RuntimeEvents++
		report.BySource[event.Source]++
		report.ByType[event.EventType]++
		missing := missingCorrelationFields(event)
		if event.SessionID == "" {
			report.Summary.MissingSession++
		}
		if event.ToolCallID == "" {
			report.Summary.MissingToolCall++
		}
		if event.ProcessID == "" {
			report.Summary.MissingProcess++
		}
		for _, field := range missing {
			report.MissingFields[field]++
		}
		if len(missing) == 0 {
			report.Summary.FullyCorrelated++
			continue
		}
		if opts.Limit <= 0 || len(report.Gaps) < opts.Limit {
			report.Gaps = append(report.Gaps, CorrelationGap{
				EventID:               event.ID,
				RawEventID:            event.RawEventID,
				Source:                event.Source,
				Type:                  event.EventType,
				Missing:               missing,
				CorrelationMethod:     event.CorrelationMethod,
				CorrelationConfidence: event.CorrelationConfidence,
				ContainerID:           event.ContainerID,
				CgroupID:              event.CgroupID,
				PID:                   event.PID,
				PPID:                  event.PPID,
				CreatedAt:             event.CreatedAt,
				SuggestedBinding:      suggestedBinding(event),
			})
		}
	}
	report.Summary.CorrelationGapCount = report.Summary.RuntimeEvents - report.Summary.FullyCorrelated
	if report.Summary.RuntimeEvents > 0 {
		total := float64(report.Summary.RuntimeEvents)
		report.Summary.FullyCorrelatedRatio = float64(report.Summary.FullyCorrelated) / total
		report.Summary.ToolCallCoverageRatio = float64(report.Summary.RuntimeEvents-report.Summary.MissingToolCall) / total
		report.Summary.ProcessCoverageRatio = float64(report.Summary.RuntimeEvents-report.Summary.MissingProcess) / total
	}
	report.NextSteps = coverageNextSteps(report)
	sort.Strings(report.NextSteps)
	return report
}

func missingCorrelationFields(event telemetry.EventRecord) []string {
	missing := []string{}
	if event.SessionID == "" {
		missing = append(missing, "session_id")
	}
	if event.ToolCallID == "" {
		missing = append(missing, "tool_call_id")
	}
	if event.ProcessID == "" {
		missing = append(missing, "process_id")
	}
	return missing
}

func isTelemetrySource(source string) bool {
	return isRuntimeEventSource(source)
}

func isRuntimeEventSource(source string) bool {
	switch source {
	case "falco_jsonl", "tetragon_jsonl", "loongcollector_jsonl", "filtered_telemetry", "wrapper_runtime", "native_runtime", "record_file_diff", "record_process_sample", "record":
		return true
	default:
		return false
	}
}

func suggestedBinding(event telemetry.EventRecord) string {
	if event.ContainerID != "" {
		return "bind ToolCallScope using container_id=" + event.ContainerID
	}
	if event.CgroupID != "" {
		return "bind ToolCallScope using cgroup_id=" + event.CgroupID
	}
	if event.PID != 0 {
		return "bind ToolCallScope using pid/root_pid"
	}
	return "add container_id, cgroup_id, or pid to raw telemetry"
}

func coverageNextSteps(report CoverageReport) []string {
	steps := []string{}
	if report.Summary.RuntimeEvents == 0 {
		return []string{"ingest runtime telemetry with telemetry ingest-jsonl or telemetry ingest-falco"}
	}
	if report.Summary.MissingSession > 0 || report.Summary.MissingToolCall > 0 || report.Summary.MissingProcess > 0 {
		steps = append(steps, "register ToolCallScope bindings with telemetry bind")
	}
	if report.MissingFields["tool_call_id"] > 0 {
		steps = append(steps, "ensure agent harness or zero-SDK recorder creates tool_call scope before command execution")
	}
	if report.MissingFields["process_id"] > 0 {
		steps = append(steps, "ensure telemetry carries pid/cgroup/container identity that can resolve to process scope")
	}
	return steps
}
