package runtimeadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/byteyellow/agentprovenance/internal/seccheck"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

type CapturePoint struct {
	Target     Target                          `json:"target"`
	ObservedAt time.Time                       `json:"observed_at"`
	Status     telemetry.SecCheckCollectStatus `json:"receiver_status"`
	Scope      seccheck.Target                 `json:"receiver_target"`
}

// Keep the public status type for callers, but serialize only this target's
// receiver boundaries. The node spool can contain unrelated runs and streams.
func (p CapturePoint) MarshalJSON() ([]byte, error) {
	type receiverStatus struct {
		SchemaVersion          string                           `json:"schema_version"`
		CollectorID            string                           `json:"collector_id"`
		GeneratedAt            string                           `json:"generated_at"`
		State                  string                           `json:"state"`
		ExpectedRuntimeRelease string                           `json:"expected_runtime_release"`
		ProtocolVersion        uint32                           `json:"protocol_version"`
		Capabilities           seccheck.Capabilities            `json:"capabilities"`
		Targets                []telemetry.SecCheckTargetStatus `json:"targets"`
	}
	s := p.Status
	selected := []telemetry.SecCheckTargetStatus{}
	for _, target := range s.Targets {
		if target.Target == p.Scope {
			selected = append(selected, target)
		}
	}
	return json.Marshal(struct {
		Target     Target          `json:"target"`
		ObservedAt time.Time       `json:"observed_at"`
		Status     receiverStatus  `json:"receiver_status"`
		Scope      seccheck.Target `json:"receiver_target"`
	}{p.Target, p.ObservedAt, receiverStatus{s.SchemaVersion, s.CollectorID, s.GeneratedAt, s.State, s.ExpectedRuntimeRelease, s.ProtocolVersion, s.Capabilities, selected}, p.Scope})
}

type CaptureReport struct {
	ObservationLayer string        `json:"observation_layer"`
	ScopeRef         string        `json:"scope_ref"`
	State            string        `json:"state"`
	Start            *CapturePoint `json:"start,omitempty"`
	End              *CapturePoint `json:"end,omitempty"`
	Gaps             []string      `json:"gaps"`
	Error            string        `json:"error,omitempty"`
}

// SecCheck reads the separately managed receiver's existing status. The
// receiver keeps its own authenticated socket, durable spool and event store.
// Container status has no call identity or command-scoped drain watermark.
type SecCheck struct {
	Target     Target
	Receiver   seccheck.Target
	ReadStatus func(context.Context) (telemetry.SecCheckCollectStatus, error)
	MaxAge     time.Duration
	Now        func() time.Time
}

func (s SecCheck) Probe(ctx context.Context, target Target) (CapturePoint, error) {
	p := CapturePoint{Target: target, Scope: s.Receiver}
	if err := ctx.Err(); err != nil {
		return p, err
	}
	if target != s.Target || target.Validate() != nil || s.Receiver.Registration.Namespace != target.ProducerID || s.Receiver.Registration.InstanceID != target.InstanceID || s.Receiver.Registration.Generation != target.Generation {
		return p, fmt.Errorf("SecCheck receiver target identity or generation mismatch")
	}
	cfg := seccheck.CollectionConfig{SchemaVersion: seccheck.CollectionConfigSchema, RuntimeRelease: seccheck.RuntimeRelease, Targets: []seccheck.Target{s.Receiver}}
	if err := cfg.Validate(); err != nil {
		return p, err
	}
	if s.ReadStatus == nil {
		return p, fmt.Errorf("SecCheck receiver status is not configured")
	}
	status, err := s.ReadStatus(ctx)
	if err != nil {
		return p, err
	}
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now()
	}
	maxAge := s.MaxAge
	if maxAge == 0 {
		maxAge = 15 * time.Second
	}
	at, err := time.Parse(time.RFC3339Nano, status.GeneratedAt)
	if err != nil || maxAge <= 0 || now.Sub(at) > maxAge || at.After(now.Add(time.Second)) {
		return p, fmt.Errorf("SecCheck receiver status is stale or invalid")
	}
	if status.SchemaVersion != "agentprovenance.seccheck_status/v1" || status.CollectorID == "" || status.ExpectedRuntimeRelease != seccheck.RuntimeRelease || status.ProtocolVersion != seccheck.ProtocolVersion || status.State != "listening" || status.Error != "" || status.LastWorkerError != "" {
		return p, fmt.Errorf("SecCheck receiver is not ready")
	}
	matches := 0
	var selected telemetry.SecCheckTargetStatus
	for _, scope := range status.Targets {
		if scope.Target == s.Receiver {
			matches++
			selected = scope
			if scope.State != "connected" || scope.ConnectionID == "" {
				return p, fmt.Errorf("SecCheck target is not connected")
			}
		}
	}
	if matches != 1 {
		return p, fmt.Errorf("SecCheck receiver scope does not match the configured target")
	}
	status.Targets = []telemetry.SecCheckTargetStatus{selected}
	status.Spool = telemetry.NativeStreamStatus{}
	p.ObservedAt, p.Status = now, status
	return p, nil
}

func (s SecCheck) Finish(ctx context.Context, target Target, start CapturePoint) CaptureReport {
	r := CaptureReport{ObservationLayer: "sentry", State: "incomplete", Start: &start,
		Gaps: []string{"shared_call_identity_unavailable", "command_capture_watermark_unavailable", "receiver_evidence_in_separate_run"}}
	identity, _ := seccheck.IdentityFor(s.Receiver.Registration, nil)
	r.ScopeRef = identity.Scope
	if start.Target != target || start.Scope != s.Receiver {
		r.Error = "SecCheck start target mismatch"
		r.Gaps = append(r.Gaps, "capture_target_mismatch")
		return r
	}
	end, err := s.Probe(ctx, target)
	if err != nil {
		r.Error = err.Error()
		r.Gaps = append(r.Gaps, "receiver_unavailable")
		return r
	}
	r.End = &end
	if end.Status.CollectorID != start.Status.CollectorID {
		r.Gaps = append(r.Gaps, "collector_restarted")
	}
	var first, last telemetry.SecCheckTargetStatus
	for _, t := range start.Status.Targets {
		if t.Target == s.Receiver {
			first = t
		}
	}
	for _, t := range end.Status.Targets {
		if t.Target == s.Receiver {
			last = t
		}
	}
	if first.ConnectionID != last.ConnectionID {
		r.Gaps = append(r.Gaps, "receiver_reconnected")
	}
	if last.AcceptedRecords < first.AcceptedRecords || last.ReportedDrops != first.ReportedDrops || last.DropCounterDecreases != first.DropCounterDecreases || last.IdentityGapRecords != first.IdentityGapRecords {
		r.Gaps = append(r.Gaps, "receiver_loss_or_identity_gap")
	}
	return r
}
