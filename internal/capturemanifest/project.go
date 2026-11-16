package capturemanifest

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/handoff"
	"github.com/byteyellow/agentprovenance/internal/observability"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/sensor"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func (s Service) read(ctx context.Context, run string, e evidence) (Record, error) {
	r := initial(e)
	read := func(out any) error { return provenance.ReadObjectPayload(s.DB, run, e.id, out) }
	switch e.objectType {
	case "telemetry_batch":
		return s.batch(ctx, run, e)
	case "sensor_capability_interval":
		var c observability.CapabilityInterval
		if err := read(&c); err != nil {
			return r, err
		}
		if c.SchemaVersion != observability.CapabilityIntervalSchema || c.RunID != run || (c.Basis != "recorded_capability_changes" && c.Basis != "collector_receive_window") || c.StartedAt.IsZero() || c.EndedAt.Before(c.StartedAt) || c.Report.SchemaVersion != "agentprovenance.sensor_capabilities/v1" || c.Report.CollectorID == "" || c.Report.Revision == 0 {
			return r, fmt.Errorf("capability interval identity mismatch")
		}
		r.Source, r.Placement, r.IdentityDomain = "agentprov_sensor", "local_kernel", "linux_kernel"
		r.Status, r.StartedAt, r.EndedAt, r.IntervalBasis = c.Report.Status, timestamp(c.StartedAt), timestamp(c.EndedAt), c.Basis
		r.ObservedAt = c.Report.ChangedAt
		r.sensorProducer(c.Report)
		if c.Basis == "collector_receive_window" {
			if c.BatchID == "" || c.ReceiverID == "" || c.WindowSealed == nil {
				return r, fmt.Errorf("native capture window identity mismatch")
			}
			r.Identity["batch_id"], r.Identity["receiver_id"] = c.BatchID, c.ReceiverID
			if !*c.WindowSealed {
				r.Issues = append(r.Issues, "collector_receive_window_unsealed")
			}
		}
		r.Snapshots = append(r.Snapshots, sensorSnapshot("change", c.Report))
	case "runtime_capture":
		var c observability.RuntimeCaptureReport
		if err := read(&c); err != nil {
			return r, err
		}
		if c.RunID != run || c.SchemaVersion != observability.RuntimeCaptureSchema {
			return r, fmt.Errorf("runtime capture identity mismatch")
		}
		r.Source, r.Placement = "agentprov_sensor", "local_capture_process"
		if c.KernelState == "observed" {
			r.Placement, r.IdentityDomain = "local_kernel", "linux_kernel"
		}
		r.Status, r.StartedAt, r.EndedAt, r.IntervalBasis = c.Status, c.StartedAt, c.EndedAt, "boundary_samples"
		r.Issues = append(r.Issues, c.Issues...)
		r.Issues = append(r.Issues, c.Limitations...)
		for _, point := range []struct {
			boundary string
			caps     *sensor.CapabilityReport
		}{{"start", c.CapabilitiesStart}, {"end", c.CapabilitiesEnd}} {
			if point.caps != nil {
				r.Snapshots = append(r.Snapshots, sensorSnapshot(point.boundary, *point.caps))
				if point.boundary == "start" || c.CapabilitiesStart == nil {
					r.sensorProducer(*point.caps)
				}
			}
		}
		r.Loss = append(r.Loss, signedCounter("dropped_events", "run", c.RunDroppedEvents, "recorded_run_count"))
		r.addCounters(c.NodeCounterDelta, "node", "capture_interval_delta")
	case "execution_checkpoint":
		var c handoff.Checkpoint
		if err := read(&c); err != nil {
			return r, err
		}
		if c.SchemaVersion != handoff.SchemaVersion || c.AttemptID == "" || c.Revision <= 0 || c.Source.Validate() != nil || c.Target.Validate() != nil || (c.Scope != nil && c.Scope.RunID != run) {
			return r, fmt.Errorf("execution checkpoint identity mismatch")
		}
		r.Source, r.Placement, r.IdentityDomain = "execution_capture", "executor", "execution_scope"
		r.Identity = map[string]string{"producer_id": c.Target.ProducerID, "instance_id": c.Target.InstanceID, "generation": c.Target.Generation, "attempt_id": c.AttemptID}
		r.ObservedAt, r.Status, r.IntervalBasis = timestamp(c.At), string(c.State.Capture), "boundary_samples"
		r.ExecutionState = &c.State
		if c.Scope != nil {
			r.Identity["scope_kind"], r.Identity["cgroup_id"] = c.Scope.ScopeKind, c.Scope.CgroupID
		}
		if err := r.projectPlatform(c); err != nil {
			return r, err
		}
		if c.Runtime != nil {
			if err := r.projectRuntime(c, run); err != nil {
				return r, err
			}
			if c.Runtime.Execution.Binding.Mode == "runsc" {
				break
			}
		}
		if c.Capture == nil {
			r.Issues = append(r.Issues, "native_capture_not_recorded")
			break
		}
		if c.Capture.SchemaVersion != "agentprovenance.execution_native_capture/v1" && c.Capture.SchemaVersion != "agentprovenance.execution_native_capture/v2" {
			return r, fmt.Errorf("unsupported native capture schema")
		}
		r.Source, r.Placement, r.IdentityDomain = "agentprov_sensor", "executor_local_kernel", "linux_kernel"
		for _, point := range []struct {
			boundary string
			value    *handoff.NativeCapturePoint
		}{{"start", c.Capture.Start}, {"end", c.Capture.End}} {
			if point.value == nil {
				continue
			}
			v := point.value
			if v.Scope.RunID != run {
				return r, fmt.Errorf("native capture scope mismatch")
			}
			p := sensorSnapshot(point.boundary, v.Capabilities)
			p.ObservedAt = timestamp(v.Sensor.ObservedAt)
			if p.Identity == nil {
				p.Identity = map[string]string{}
			}
			p.Identity["collector_id"] = v.Sensor.CollectorID
			r.Snapshots = append(r.Snapshots, p)
			if point.boundary == "start" {
				r.sensorProducer(v.Capabilities)
				r.StartedAt = p.ObservedAt
				r.Identity["collector_id"] = v.Sensor.CollectorID
			} else {
				r.EndedAt = p.ObservedAt
				if r.Identity["collector_id"] != "" && r.Identity["collector_id"] != v.Sensor.CollectorID {
					r.Issues = append(r.Issues, "collector_changed")
				}
			}
			r.Loss = append(r.Loss, Counter{Name: "kernel_drops", Scope: "collector", ScopeID: v.Sensor.CollectorID, Value: decimal(&v.Sensor.KernelDrops), Basis: point.boundary + "_cumulative"},
				Counter{Name: "state_queue_drops", Scope: "collector", ScopeID: v.Sensor.CollectorID, Value: decimal(&v.Sensor.StateQueueDrops), Basis: point.boundary + "_cumulative"},
				Counter{Name: "tls_lost_streams", Scope: "collector", ScopeID: v.Sensor.CollectorID, Value: decimal(&v.Sensor.TLSLostStreams), Basis: point.boundary + "_cumulative"})
		}
		r.Issues = append(r.Issues, c.Capture.Issues...)
		if p := c.Capture.ScopeProgress; p != nil {
			r.addCounters(map[string]int64{"dropped": p.Dropped, "failed": p.Failed, "pending": p.Pending, "sampling_gaps": p.SamplingGaps}, "scope_prefix", "saved_scope_prefix")
		}
	case "agent_context_coverage":
		var c agentcontext.Coverage
		if err := read(&c); err != nil {
			return r, err
		}
		if c.SchemaVersion != agentcontext.SchemaVersion || c.RunID != run || c.ID == "" {
			return r, fmt.Errorf("context coverage identity mismatch")
		}
		if c.CapturePolicy != nil {
			if err := c.CapturePolicy.Validate(); err != nil {
				return r, err
			}
		}
		if c.Source.Browser != nil && c.Source.Notebook != nil {
			return r, fmt.Errorf("conflicting context identity domains")
		}
		r.Source, r.Placement, r.IdentityDomain = "agent_context", "application", "harness_session"
		r.Identity = map[string]string{"source_id": c.Source.ID, "harness": c.Source.Harness, "session_id": c.Source.SessionID, "parser_version": c.Source.ParserVersion}
		if c.Source.ApplicationVersion != "" {
			r.Identity["application_version"] = c.Source.ApplicationVersion
		}
		if b := c.Source.Browser; b != nil {
			r.IdentityDomain = "browser"
			r.Identity["producer_id"], r.Identity["namespace"], r.Identity["instance_id"], r.Identity["generation"] = b.ProducerID, b.Namespace, b.InstanceID, b.Generation
			r.Identity["browser_id"], r.Identity["context_id"] = b.BrowserID, b.ContextID
		}
		if n := c.Source.Notebook; n != nil {
			r.IdentityDomain = "notebook"
			r.Identity["producer_id"], r.Identity["namespace"], r.Identity["instance_id"], r.Identity["generation"] = n.ProducerID, n.Namespace, n.InstanceID, n.Generation
			r.Identity["notebook_id"], r.Identity["kernel_id"], r.Identity["kernel_session_id"] = n.NotebookID, n.KernelID, n.KernelSessionID
		}
		r.ObservedAt, r.StartedAt, r.EndedAt = c.ObservedAt, c.StartedAt, c.EndedAt
		r.Status, r.IntervalBasis = string(c.Status), "source_processing_range"
		r.retention(c.CapturePolicy)
		for _, issue := range c.Issues {
			r.Issues = append(r.Issues, issue.Code)
		}
		for _, counter := range []struct {
			name  string
			value *int64
		}{{"failed", c.Counts.Failed}, {"truncated", c.Counts.Truncated}, {"unrecognized", c.Counts.Unrecognized}, {"deferred", c.Counts.Deferred}} {
			r.Loss = append(r.Loss, signedCounter(counter.name, "processing_range", counter.value, "source_report"))
		}
	case "context_capture_policy":
		var p agentcontext.CapturePolicy
		if err := read(&p); err != nil {
			return r, err
		}
		if err := p.Validate(); err != nil {
			return r, err
		}
		r.Source, r.Status, r.IntervalBasis = "context_retention", "configured", "run_configuration"
		r.retention(&p)
	case "run_capture_settings":
		var c observability.CaptureSettings
		if err := read(&c); err != nil {
			return r, err
		}
		if err := c.Validate(); err != nil {
			return r, err
		}
		r.Source, r.Status, r.IntervalBasis = "launch_settings", "configured", "run_configuration"
		r.Retention = []Retention{{"workspace_snapshot", c.WorkspaceSnapshot, "launch_setting"}, {"tls_full_body", c.TLSFullBody, "launch_setting"}, {"agent_context", c.AgentContext, "launch_setting"}}
		var enabled *bool
		if c.SensorMode == "off" {
			enabled = ptr(false)
		}
		r.Snapshots = append(r.Snapshots, Snapshot{Boundary: "configuration", Status: c.SensorMode, Features: []Feature{{Name: "kernel_sensor", Category: "system_telemetry", Enabled: enabled, State: c.SensorMode, Basis: "launch_setting"}}})
	case "sentry_stream":
		return s.sentry(ctx, run, e)
	case "record_capture":
		return s.recorder(ctx, run, e)
	default:
		return r, fmt.Errorf("unsupported capture evidence type")
	}
	return r, nil
}

func ptr[T any](v T) *T { return &v }

func timestamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func sensorSnapshot(boundary string, c sensor.CapabilityReport) Snapshot {
	s := Snapshot{ObservedAt: c.UpdatedAt, Boundary: boundary, Status: c.Status, Reason: c.Reason, Features: []Feature{}}
	if c.SchemaVersion != "agentprovenance.sensor_capabilities/v1" {
		s.Status = "unknown"
		return s
	}
	s.Ready = ptr(c.Ready)
	s.Identity = map[string]string{}
	if c.CollectorID != "" {
		s.Identity["collector_id"], s.Identity["capability_revision"], s.Identity["changed_at"] = c.CollectorID, strconv.FormatUint(c.Revision, 10), c.ChangedAt
	}
	if p := c.Producer; p != nil {
		s.Identity["producer_version"], s.Identity["producer_commit"], s.Identity["placement"] = p.Version, p.Commit, p.Placement
		s.Identity["sensor_name"], s.Identity["os"], s.Identity["architecture"] = p.Name, p.OS, p.Architecture
		s.Identity["kernel"], s.Identity["boot_id"], s.Identity["placement_basis"] = p.Kernel, p.BootID, p.PlacementBasis
	}
	if p := c.ProcfsIdentity; p != nil {
		s.Identity["pid_namespace"], s.Identity["pid_namespace_basis"] = p.PIDNamespace, p.Mode
	}
	if len(s.Identity) == 0 {
		s.Identity = nil
	}
	for _, p := range c.Probes {
		f := Feature{Name: p.Name, Category: p.Category, Target: p.Target, State: p.Status, Reason: p.Reason, Basis: "probe_observation"}
		switch p.Status {
		case "attached":
			f.Supported, f.Enabled = ptr(true), ptr(true)
		case "unsupported":
			f.Supported, f.Enabled = ptr(false), ptr(false)
		case "disabled", "detached":
			f.Enabled = ptr(false)
		case "failed":
			f.Enabled = ptr(false)
		}
		s.Features = append(s.Features, f)
	}
	if p := c.AccessControlState; p != nil {
		s.Features = append(s.Features, Feature{Name: "apparmor_state", Category: "access_control", Enabled: ptr(p.AppArmor), State: "configured", Basis: p.Mode},
			Feature{Name: "seccomp_state", Category: "access_control", Enabled: ptr(p.Seccomp), State: "configured", Basis: p.Mode})
	}
	return s
}

func (r *Record) sensorProducer(c sensor.CapabilityReport) {
	if c.CollectorID != "" {
		r.Identity["collector_id"] = c.CollectorID
		r.Identity["capability_revision"] = strconv.FormatUint(c.Revision, 10)
	}
	if p := c.Producer; p != nil {
		if p.Version != "" {
			r.ProducerVersion = p.Version
		}
		if p.Commit != "" {
			r.ProducerCommit = p.Commit
		}
		if p.Placement != "" {
			r.Placement = p.Placement
		}
		r.Identity["sensor_name"], r.Identity["os"], r.Identity["architecture"] = p.Name, p.OS, p.Architecture
		r.Identity["kernel"], r.Identity["boot_id"], r.Identity["placement_basis"] = p.Kernel, p.BootID, p.PlacementBasis
	}
}

func (r *Record) retention(p *agentcontext.CapturePolicy) {
	if p == nil {
		return
	}
	for _, item := range []struct {
		category string
		enabled  bool
	}{{"tool_results", p.ToolResults}, {"source_records", p.SourceRecords}, {"history", p.History}, {"configuration", p.Configuration}, {"attachments", p.RetainAttachments()}} {
		r.Retention = append(r.Retention, Retention{item.category, ptr(item.enabled), "recorded_capture_policy"})
	}
}

func signedCounter(name, scope string, v *int64, basis string) Counter {
	c := Counter{Name: name, Scope: scope, Basis: basis}
	if v != nil && *v >= 0 {
		c.Value = ptr(strconv.FormatInt(*v, 10))
	}
	return c
}

func decimal(value *uint64) *string {
	if value == nil {
		return nil
	}
	return ptr(strconv.FormatUint(*value, 10))
}

func (r *Record) addCounters(values map[string]int64, scope, basis string) {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		v := values[key]
		r.Loss = append(r.Loss, signedCounter(key, scope, &v, basis))
	}
}

func (s Service) sentry(ctx context.Context, run string, e evidence) (Record, error) {
	r := initial(e)
	var event telemetry.EventRecord
	err := s.DB.QueryRowContext(ctx, `SELECT id,run_id,source,event_type,payload,created_at,raw_event_id,correlation_method,container_id,
		session_id,tool_call_id,process_id,cgroup_id,pid,tgid,ppid FROM events WHERE run_id=? AND id=?`, run, e.id).
		Scan(&event.ID, &event.RunID, &event.Source, &event.EventType, &event.Payload, &event.CreatedAt, &event.RawEventID, &event.CorrelationMethod,
			&event.ContainerID, &event.SessionID, &event.ToolCallID, &event.ProcessID, &event.CgroupID, &event.PID, &event.TGID, &event.PPID)
	if err != nil {
		return r, err
	}
	c, err := telemetry.ReadSecCheckEvidence(event)
	if err != nil {
		return r, err
	}
	r.EvidenceRef = "runtime_event/" + event.ID
	r.Source, r.Placement, r.IdentityDomain = "gvisor_seccheck", "host_receiver", "sentry"
	r.Identity = map[string]string{"namespace": c.Registration.Namespace, "instance_id": c.Registration.InstanceID, "generation": c.Registration.Generation,
		"sandbox_id": c.Registration.SandboxID, "container_id": c.Registration.ContainerID, "connection_id": c.ConnectionID, "runtime_release": c.RuntimeRelease}
	r.ObservedAt, r.Status, r.IntervalBasis = timestamp(c.ReceivedAt), c.Reason, "stream_observation"
	r.Loss = append(r.Loss, Counter{Name: "reported_dropped_events", Scope: "sentry_connection", ScopeID: c.ConnectionID, Value: decimal(c.DroppedDelta), Basis: "source_delta"})
	if c.DropCounterDecreased {
		r.Issues = append(r.Issues, "drop_counter_decreased")
	}
	r.Issues = append(r.Issues, c.IdentityGaps...)
	if c.Kind == "event" {
		point, err := telemetry.ReadSecCheckPoint(event)
		if err != nil {
			return r, err
		}
		r.Status, r.IntervalBasis = "observed", "checkpoint_observation"
		r.Identity["protocol_version"] = strconv.FormatUint(uint64(c.ProtocolVersion), 10)
		r.Identity["message_type"] = strconv.FormatUint(uint64(point.MessageType), 10)
		target := point.Stage
		if point.SyscallNumber != nil {
			target += "/syscall=" + strconv.FormatUint(*point.SyscallNumber, 10)
		}
		r.Snapshots = append(r.Snapshots, Snapshot{ObservedAt: event.CreatedAt, Boundary: "event", Status: "observed",
			Features: []Feature{{Name: point.MessageName, Category: "system_telemetry", Target: target, Observed: ptr(true), State: "observed", Basis: "saved_sentry_event"}}})
		if c.DroppedDelta != nil && *c.DroppedDelta > 0 {
			r.Issues = append(r.Issues, "reported_event_loss")
		}
	}
	if c.Capabilities != nil {
		caps := c.Capabilities
		if caps.ProducerVersion != "" {
			r.ProducerVersion = caps.ProducerVersion
		}
		if caps.ProducerCommit != "" {
			r.ProducerCommit = caps.ProducerCommit
		}
		r.Identity["producer_id"] = caps.Producer
		p := Snapshot{ObservedAt: r.ObservedAt, Boundary: "stream", Status: c.Reason, Features: []Feature{}}
		for _, name := range caps.SupportedPoints {
			p.Features = append(p.Features, Feature{Name: name, Category: "system_telemetry", Supported: ptr(true), State: "supported", Basis: "saved_receiver_capability"})
		}
		if caps.ModelIntent == "none" {
			p.Features = append(p.Features, Feature{Name: "tls_plaintext", Category: "model_intent", Supported: ptr(false), Enabled: ptr(false), State: "unsupported", Basis: "saved_receiver_capability"})
		}
		r.Snapshots = append(r.Snapshots, p)
		r.Retention = append(r.Retention, Retention{"raw_packets", ptr(caps.RawPacketsRetained), "saved_receiver_capability"})
	}
	return r, nil
}
