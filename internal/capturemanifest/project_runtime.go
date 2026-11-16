package capturemanifest

import (
	"context"
	"fmt"
	"strconv"

	"github.com/byteyellow/agentprovenance/internal/handoff"
	"github.com/byteyellow/agentprovenance/internal/runtimeadapter"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func (r *Record) projectPlatform(c handoff.Checkpoint) error {
	if c.PlatformBinding == nil {
		return nil
	}
	b, err := c.PlatformBinding.Resolve(context.Background(), runtimeadapter.Target(c.Target))
	if err != nil {
		return fmt.Errorf("capture platform binding: %w", err)
	}
	for name, value := range map[string]string{"runtime_mode": b.Mode, "runtime_container_id": b.ContainerID,
		"runtime_class": b.RuntimeClass, "runtime_handler": b.RuntimeHandler, "pod_uid": b.PodUID, "guest_boot_id": b.GuestBootID} {
		if value != "" {
			r.Identity[name] = value
		}
	}
	r.Identity["platform_basis"] = "recorded_platform_binding"
	return nil
}

func (r *Record) projectRuntime(c handoff.Checkpoint, run string) error {
	v := c.Runtime.Execution
	if v.SchemaVersion != runtimeadapter.Schema || v.Binding.Target != runtimeadapter.Target(c.Target) || v.RunID != run || v.AttemptID != c.AttemptID {
		return fmt.Errorf("runtime capture execution identity mismatch")
	}
	if _, err := v.Binding.Resolve(context.Background(), runtimeadapter.Target(c.Target)); err != nil {
		return fmt.Errorf("runtime capture binding: %w", err)
	}
	if c.PlatformBinding != nil && *c.PlatformBinding != v.Binding {
		return fmt.Errorf("runtime capture platform binding mismatch")
	}
	if v.Binding.Mode == "guest" {
		if c.Runtime.Capture != nil || v.SentryPID != 0 {
			return fmt.Errorf("guest runtime cannot contain Sentry capture or process identity")
		}
		r.Identity["runtime_operation_id"] = v.OperationID
		r.Issues = append(r.Issues, v.Gaps...)
		return nil
	}
	if v.Binding.Mode != "runsc" || c.Capture != nil {
		return fmt.Errorf("runtime capture observation domain mismatch")
	}
	r.Source, r.Placement, r.IdentityDomain = "runtime_execution", "host_runtime_control", "sentry"
	r.Identity["runtime_mode"], r.Identity["runtime_container_id"] = v.Binding.Mode, v.Binding.ContainerID
	r.Identity["runtime_release"], r.Identity["runtime_operation_id"] = v.RuntimeRelease, v.OperationID
	if v.SentryPID > 0 {
		r.Identity["sentry_pid"], r.Identity["sentry_pid_basis"] = strconv.FormatInt(int64(v.SentryPID), 10), v.SentryPIDBasis
	}
	r.Issues = append(r.Issues, v.Gaps...)
	if c.Runtime.Capture == nil {
		r.Issues = append(r.Issues, "runtime_capture_not_recorded")
		return nil
	}
	capture := c.Runtime.Capture
	if capture.ObservationLayer != "sentry" {
		return fmt.Errorf("runtime capture layer mismatch")
	}
	r.Issues = append(r.Issues, capture.Gaps...)
	for _, boundary := range []struct {
		name  string
		point *runtimeadapter.CapturePoint
	}{{"start", capture.Start}, {"end", capture.End}} {
		if boundary.point == nil {
			continue
		}
		p := boundary.point
		reg := p.Scope.Registration
		if p.Target != v.Binding.Target || reg.Validate() != nil || reg.Namespace != c.Target.ProducerID || reg.InstanceID != c.Target.InstanceID ||
			reg.Generation != c.Target.Generation || reg.ContainerID != v.Binding.ContainerID {
			return fmt.Errorf("runtime capture receiver target mismatch")
		}
		var selected *telemetry.SecCheckTargetStatus
		for i := range p.Status.Targets {
			item := &p.Status.Targets[i]
			if item.Target == p.Scope {
				if selected != nil {
					return fmt.Errorf("duplicate runtime capture receiver target")
				}
				selected = item
			}
		}
		if selected == nil {
			return fmt.Errorf("runtime capture receiver target not recorded")
		}
		caps := p.Status.Capabilities
		s := Snapshot{Boundary: boundary.name, ObservedAt: timestamp(p.ObservedAt), Status: selected.State,
			Identity: map[string]string{"collector_id": p.Status.CollectorID, "connection_id": selected.ConnectionID,
				"namespace": reg.Namespace, "instance_id": reg.InstanceID, "generation": reg.Generation,
				"sandbox_id": reg.SandboxID, "container_id": reg.ContainerID, "runtime_release": p.Status.ExpectedRuntimeRelease,
				"protocol_version": strconv.FormatUint(uint64(p.Status.ProtocolVersion), 10),
				"producer_version": caps.ProducerVersion, "producer_commit": caps.ProducerCommit}, Features: []Feature{},
			Observation: observation("sentry", "recorded_receiver_status", "sentry_connection", selected.ConnectionID, r.EvidenceRef)}
		for _, name := range caps.SupportedPoints {
			s.Features = append(s.Features, Feature{Name: name, Category: "system_telemetry", Supported: ptr(true), State: "supported", Basis: "saved_receiver_capability"})
		}
		r.Snapshots = append(r.Snapshots, s)
		if boundary.name == "start" {
			r.StartedAt = s.ObservedAt
		} else {
			r.EndedAt = s.ObservedAt
		}
		for _, counter := range []struct {
			name  string
			value uint64
		}{{"reported_dropped_events", selected.ReportedDrops}, {"drop_counter_decreases", selected.DropCounterDecreases}, {"identity_gap_records", selected.IdentityGapRecords}} {
			r.Loss = append(r.Loss, Counter{Name: counter.name, Scope: "sentry_connection", ScopeID: selected.ConnectionID,
				Value: decimal(&counter.value), Basis: boundary.name + "_cumulative"})
		}
		r.Counts = append(r.Counts, Counter{Name: "accepted_records", Scope: "sentry_connection", ScopeID: selected.ConnectionID,
			Value: decimal(&selected.AcceptedRecords), Basis: boundary.name + "_cumulative"})
	}
	return nil
}
