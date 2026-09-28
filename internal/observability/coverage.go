package observability

import (
	"context"
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
	ResultSetID   string           `json:"result_set_id"`
	PageHash      string           `json:"page_hash"`
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
	return BuildCoverageContext(context.Background(), db, opts)
}

// Count the full selection without retaining event payloads. Only the gap
// examples are bounded; the summary must not describe just the first page.
func BuildCoverageContext(ctx context.Context, db *sql.DB, opts CoverageOptions) (CoverageReport, error) {
	query := `SELECT id, COALESCE(session_id,''), COALESCE(tool_call_id,''), COALESCE(process_id,''),
		COALESCE(raw_event_id,''), COALESCE(correlation_method,''), COALESCE(correlation_confidence,0),
		COALESCE(container_id,''), COALESCE(cgroup_id,''), COALESCE(pid,0), COALESCE(ppid,0), source, event_type, created_at FROM events`
	args := []any{}
	if opts.RunID != "" {
		query += ` WHERE run_id=?`
		args = append(args, opts.RunID)
	}
	query += ` ORDER BY created_at, id`
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return CoverageReport{}, err
	}
	defer rows.Close()
	report := newCoverage(opts.RunID)
	for rows.Next() {
		var event telemetry.EventRecord
		if err := rows.Scan(&event.ID, &event.SessionID, &event.ToolCallID, &event.ProcessID,
			&event.RawEventID, &event.CorrelationMethod, &event.CorrelationConfidence, &event.ContainerID,
			&event.CgroupID, &event.PID, &event.PPID, &event.Source, &event.EventType, &event.CreatedAt); err != nil {
			return CoverageReport{}, err
		}
		report.addEvent(event, coverageGapLimit(opts.Limit))
	}
	if err := rows.Err(); err != nil {
		return CoverageReport{}, err
	}
	return finishCoverage(report, opts), nil
}

func BuildCoverageFromEvents(runID string, events []telemetry.EventRecord, opts CoverageOptions) CoverageReport {
	report := newCoverage(runID)
	for _, event := range events {
		report.addEvent(event, coverageGapLimit(opts.Limit))
	}
	return finishCoverage(report, opts)
}

func coverageGapLimit(limit int) int {
	if limit <= 0 {
		return 100
	}
	if limit > 1000 {
		return 1000
	}
	return limit
}

func newCoverage(runID string) CoverageReport {
	return CoverageReport{
		SchemaVersion: CoverageSchemaVersion,
		RunID:         runID,
		MissingFields: map[string]int{},
		BySource:      map[string]int{},
		ByType:        map[string]int{},
	}
}

func (report *CoverageReport) addEvent(event telemetry.EventRecord, limit int) {
	if !isTelemetrySource(event.Source) {
		return
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
		return
	}
	if len(report.Gaps) < limit {
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

func finishCoverage(report CoverageReport, opts CoverageOptions) CoverageReport {
	report.Summary.CorrelationGapCount = report.Summary.RuntimeEvents - report.Summary.FullyCorrelated
	if report.Summary.RuntimeEvents > 0 {
		total := float64(report.Summary.RuntimeEvents)
		report.Summary.FullyCorrelatedRatio = float64(report.Summary.FullyCorrelated) / total
		report.Summary.ToolCallCoverageRatio = float64(report.Summary.RuntimeEvents-report.Summary.MissingToolCall) / total
		report.Summary.ProcessCoverageRatio = float64(report.Summary.RuntimeEvents-report.Summary.MissingProcess) / total
	}
	report.NextSteps = coverageNextSteps(report)
	sort.Strings(report.NextSteps)
	resultSetID, pageHash, err := coverageIntegrity(report, coverageGapLimit(opts.Limit))
	if err == nil {
		report.ResultSetID = resultSetID
		report.PageHash = pageHash
	}
	return report
}

func coverageIntegrity(report CoverageReport, limit int) (string, string, error) {
	resultSetID, err := digestObservation(map[string]any{
		"kind":           "observability_coverage_result_set",
		"run_id":         report.RunID,
		"summary":        report.Summary,
		"missing_fields": report.MissingFields,
		"by_source":      report.BySource,
		"by_type":        report.ByType,
	})
	if err != nil {
		return "", "", err
	}
	pageHash, err := digestObservation(map[string]any{
		"kind":          "observability_coverage_page",
		"result_set_id": resultSetID,
		"limit":         limit,
		"gaps":          report.Gaps,
		"next_steps":    report.NextSteps,
	})
	if err != nil {
		return "", "", err
	}
	return resultSetID, pageHash, nil
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
	// Raw event sources also include recorder/kernel producer identifiers.
	// Timeline uses "runtime" for synthesized process lifecycle entries, so
	// its separate classifier must not mistake those entries for raw events.
	switch source {
	case "agentprov_ebpf", "external_telemetry", "kernel", "loongcollector", "runtime", "zero_sdk_record", "zero_sdk_record_descendant":
		return true
	default:
		return isRuntimeEventSource(source)
	}
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
