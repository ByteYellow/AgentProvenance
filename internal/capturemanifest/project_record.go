package capturemanifest

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/byteyellow/agentprovenance/internal/record"
)

func (s Service) recorder(ctx context.Context, run string, e evidence) (Record, error) {
	r := initial(e)
	var payload, eventType, session, call, process string
	if err := s.DB.QueryRowContext(ctx, `SELECT payload,event_type,session_id,tool_call_id,process_id FROM events
		WHERE id=? AND run_id=? AND source='record'`, e.id, run).Scan(&payload, &eventType, &session, &call, &process); err != nil {
		return r, err
	}
	var body struct {
		AttemptID string                `json:"attempt_id"`
		Capture   *record.CaptureReport `json:"record_capture"`
	}
	if err := json.Unmarshal([]byte(payload), &body); err != nil {
		return r, err
	}
	c := body.Capture
	if c == nil || c.SchemaVersion != record.CaptureSchema || c.RunID != run || c.AttemptID == "" || c.AttemptID != body.AttemptID ||
		c.SessionID != session || c.ToolCallID != call || c.ProcessID != process || c.Producer.Name != "agentprov-record" || c.Producer.OS == "" || c.Producer.Architecture == "" ||
		(c.ScopeKind != "cgroup" && c.ScopeKind != "logical_process_scope") || c.CgroupID == "" || c.SampleIntervalMS <= 0 || c.PostRootGraceMS <= 0 {
		return r, fmt.Errorf("recorder capability identity mismatch")
	}
	if eventType != map[string]string{"start": "exec_start", "end": "exec_end", "error": "exec_error"}[c.Boundary] ||
		(c.Boundary == "start" && (c.Status != "recording" || c.EndedAt != "" || c.Sampling != nil)) ||
		(c.Boundary != "start" && c.Status != "stopped" && c.Status != "partial") || (c.Boundary == "end" && c.Sampling == nil) {
		return r, fmt.Errorf("recorder capability boundary mismatch")
	}
	observed, err := time.Parse(time.RFC3339Nano, c.ObservedAt)
	if err != nil {
		return r, fmt.Errorf("invalid recorder observation time")
	}
	var start, end time.Time
	for _, point := range []struct {
		text string
		at   *time.Time
	}{{c.StartedAt, &start}, {c.EndedAt, &end}} {
		if point.text != "" {
			*point.at, err = time.Parse(time.RFC3339Nano, point.text)
			if err != nil || point.at.After(observed) {
				return r, fmt.Errorf("invalid recorder capture time")
			}
		}
	}
	if (c.Boundary == "start" && start.IsZero()) || (c.Boundary != "start" && end.IsZero()) || (!start.IsZero() && !end.IsZero() && end.Before(start)) {
		return r, fmt.Errorf("invalid recorder capture interval")
	}
	if p := c.Sampling; p != nil {
		from, err1 := time.Parse(time.RFC3339Nano, p.StartedAt)
		until, err2 := time.Parse(time.RFC3339Nano, p.EndedAt)
		if err1 != nil || err2 != nil || from.Before(start) || until.Before(from) || until.After(observed) || p.Attempts == 0 || p.Failures > p.Attempts {
			return r, fmt.Errorf("invalid recorder sampling observation")
		}
	}
	r.EvidenceRef, r.Source, r.Placement, r.IdentityDomain = "runtime_event/"+e.id, "record", "local_process", "record_scope"
	r.Identity = map[string]string{"attempt_id": c.AttemptID, "session_id": session, "tool_call_id": call, "process_id": process,
		"scope_kind": c.ScopeKind, "cgroup_id": c.CgroupID, "producer_name": c.Producer.Name, "os": c.Producer.OS, "architecture": c.Producer.Architecture,
		"sample_interval_ms": strconv.FormatInt(c.SampleIntervalMS, 10), "post_root_grace_ms": strconv.FormatInt(c.PostRootGraceMS, 10)}
	for key, value := range map[string]string{"kernel": c.Producer.Kernel, "boot_id": c.Producer.BootID} {
		if value != "" {
			r.Identity[key] = value
		}
	}
	if c.Producer.Version != "" {
		r.ProducerVersion = c.Producer.Version
	}
	if c.Producer.Commit != "" {
		r.ProducerCommit = c.Producer.Commit
	}
	r.ObservedAt, r.StartedAt, r.EndedAt, r.Status, r.IntervalBasis = c.ObservedAt, c.StartedAt, c.EndedAt, c.Status, "recorder_observation"
	r.Issues = append(r.Issues, c.Issues...)
	started := c.StartedAt != ""
	rootState := "not_started"
	if started {
		rootState = "observed"
	}
	features := []Feature{
		{Name: "root_process_lifecycle", Category: "system_telemetry", Supported: ptr(true), Enabled: ptr(true), Observed: &started, State: rootState, Basis: "owned_process"},
		{Name: "process_tree_polling", Category: "system_telemetry", Enabled: ptr(true), State: "configured", Basis: "process_table_sampling"},
		{Name: "workspace_file_diff", Category: "files", Supported: ptr(true), Enabled: &c.WorkspaceFiles, State: "configured", Basis: "post_execution_snapshot"},
		{Name: "kernel_syscalls", Category: "system_telemetry", Supported: ptr(false), Enabled: ptr(false), State: "unsupported", Basis: "recorder_method"},
		{Name: "tls_plaintext", Category: "model_intent", Supported: ptr(false), Enabled: ptr(false), State: "unsupported", Basis: "recorder_method"},
	}
	if !c.WorkspaceFiles {
		features[2].State = "disabled"
	} else if c.FileCapture != nil {
		features[2].State = c.FileCapture.Status
	}
	var samplingFailures *string
	if p := c.Sampling; p != nil {
		observed := p.Attempts > p.Failures
		features[1].Observed = &observed
		features[1].State = "observed"
		if p.Failures > 0 {
			features[1].State = "partial"
			if !observed {
				features[1].State = "failed"
			}
		}
		samplingFailures = decimal(&p.Failures)
		r.Identity["sampling_started_at"], r.Identity["sampling_ended_at"] = p.StartedAt, p.EndedAt
		r.Identity["sampling_attempts"] = strconv.FormatUint(p.Attempts, 10)
	}
	r.Snapshots = []Snapshot{{ObservedAt: c.ObservedAt, Boundary: c.Boundary, Status: c.Status, Features: features}}
	r.Retention = []Retention{{Category: "workspace_files", Enabled: &c.WorkspaceFiles, Basis: "recorder_setting"}}
	r.Loss = []Counter{
		{Name: "missed_processes", Scope: "recorder", ScopeID: c.AttemptID, Value: nil, Basis: "sampling_has_no_total"},
		{Name: "process_table_failures", Scope: "recorder", ScopeID: c.AttemptID, Value: samplingFailures, Basis: "recorded_sampling_attempts"},
		{Name: "sample_binding_failures", Scope: "recorder", ScopeID: c.AttemptID, Value: decimal(&c.BindingFailures), Basis: "recorded_persistence_attempts"},
		{Name: "sample_event_failures", Scope: "recorder", ScopeID: c.AttemptID, Value: decimal(&c.EventFailures), Basis: "recorded_persistence_attempts"},
	}
	return r, nil
}
