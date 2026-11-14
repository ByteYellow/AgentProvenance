package handoff

import (
	"context"
	"fmt"
	"time"

	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/byteyellow/agentprovenance/internal/sensor"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

const nativeCaptureSchema = "agentprovenance.execution_native_capture/v2"

type NativeCapturePoint struct {
	Scope        record.ExecutionScope   `json:"scope"`
	Sensor       sensor.CaptureBoundary  `json:"sensor"`
	Spool        telemetry.NativePrefix  `json:"spool"`
	Capabilities sensor.CapabilityReport `json:"capabilities"`
}

// The shared prefix remains visible. Only the execution's collector interval,
// cgroup and unclassified rows participate in scope-drain completion.
type NativeCaptureReport struct {
	SchemaVersion string                          `json:"schema_version"`
	State         CaptureState                    `json:"state"`
	Start         *NativeCapturePoint             `json:"start,omitempty"`
	End           *NativeCapturePoint             `json:"end,omitempty"`
	Scope         *record.ScopeObservation        `json:"scope_observation,omitempty"`
	Progress      *telemetry.NativePrefixProgress `json:"shared_prefix,omitempty"`
	ScopePrefix   *telemetry.NativeScopePrefix    `json:"scope_prefix,omitempty"`
	ScopeProgress *telemetry.NativePrefixProgress `json:"scope_progress,omitempty"`
	Issues        []string                        `json:"issues"`
	Error         string                          `json:"error,omitempty"`
}

// NativeCapture uses one live collector for all executor jobs. Ownership and
// shutdown stay with the caller; it must stop the executor before the collector.
type NativeCapture struct {
	Checkpointer interface {
		Checkpoint(context.Context, func(sensor.CaptureBoundary) error) (sensor.CaptureBoundary, error)
	}
	Stream       *telemetry.NativeStream
	Capabilities func() sensor.CapabilityReport
	Timeout      time.Duration
}

func (n *NativeCapture) deadline(ctx context.Context) (context.Context, context.CancelFunc) {
	duration := n.Timeout
	if duration <= 0 {
		duration = 3 * time.Second
	}
	return context.WithTimeout(ctx, duration)
}

func (n *NativeCapture) point(ctx context.Context, scope record.ExecutionScope) (*NativeCapturePoint, error) {
	if n == nil || n.Checkpointer == nil || n.Stream == nil || n.Capabilities == nil {
		return nil, fmt.Errorf("native execution capture is not configured")
	}
	p := &NativeCapturePoint{Scope: scope}
	boundary, err := n.Checkpointer.Checkpoint(ctx, func(sensor.CaptureBoundary) error {
		p.Capabilities = n.Capabilities()
		if !p.Capabilities.Ready {
			return fmt.Errorf("native execution capture probes are not ready")
		}
		var err error
		p.Spool, err = n.Stream.SnapshotPrefix(ctx)
		return err
	})
	if err != nil {
		return nil, err
	}
	p.Sensor = boundary
	return p, nil
}

func (n *NativeCapture) Begin(ctx context.Context, scope record.ExecutionScope) (*NativeCapturePoint, error) {
	if n == nil {
		return nil, fmt.Errorf("native execution capture is not configured")
	}
	if scope.ScopeKind != "cgroup" || scope.CgroupID == "" {
		return nil, fmt.Errorf("native execution capture requires an owned kernel cgroup")
	}
	ctx, cancel := n.deadline(ctx)
	defer cancel()
	return n.point(ctx, scope)
}

func (n *NativeCapture) Finish(ctx context.Context, start NativeCapturePoint, result record.Result) NativeCaptureReport {
	r := NativeCaptureReport{SchemaVersion: nativeCaptureSchema, State: Incomplete, Start: &start,
		Scope: result.ScopeObservation, Issues: []string{}}
	ctx, cancel := n.deadline(ctx)
	defer cancel()
	if result.Scope == nil || result.Scope.RunID != start.Scope.RunID || result.Scope.BindingID != start.Scope.BindingID ||
		result.Scope.CgroupID != start.Scope.CgroupID || result.RootPID <= 0 || result.EndEventID == "" {
		r.Issues = append(r.Issues, "execution_boundary_missing")
		return r
	}
	end, err := n.point(ctx, *result.Scope)
	if err != nil {
		r.Issues, r.Error = append(r.Issues, "sensor_checkpoint_failed"), err.Error()
		return r
	}
	r.End = end
	prefix, err := n.Stream.SnapshotScopePrefix(ctx, start.Spool, end.Spool, start.Scope.CgroupID)
	if err != nil {
		r.Issues, r.Error = append(r.Issues, "scope_checkpoint_failed"), err.Error()
		return r
	}
	r.ScopePrefix = &prefix
	progress, err := n.Stream.DrainScopePrefix(ctx, prefix)
	r.ScopeProgress = &progress
	if err != nil {
		r.Issues, r.Error = append(r.Issues, "spool_drain_failed"), err.Error()
	}
	// Preserve node backlog separately, including when scope drain timed out.
	sharedCtx, sharedCancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	shared, sharedErr := n.Stream.ReadPrefix(sharedCtx, end.Spool)
	sharedCancel()
	if sharedErr != nil {
		r.Issues = append(r.Issues, "shared_prefix_status_unavailable")
		if r.Error == "" {
			r.Error = sharedErr.Error()
		}
	} else {
		r.Progress = &shared
	}
	r.Issues = append(r.Issues, nativeCaptureIssues(start, *end, r.Scope, progress)...)
	if len(r.Issues) == 0 {
		r.State = Sealed
	}
	return r
}

func nativeCaptureIssues(start, end NativeCapturePoint, scope *record.ScopeObservation, progress telemetry.NativePrefixProgress) []string {
	issues := []string{}
	if scope == nil || scope.Empty == nil || scope.Error != "" || scope.ScopeKind != "cgroup" || scope.CgroupID != start.Scope.CgroupID {
		issues = append(issues, "scope_population_unknown")
	} else if !*scope.Empty {
		issues = append(issues, "scope_still_populated")
	}
	if start.Sensor.CollectorID != end.Sensor.CollectorID || start.Spool.CollectorID != end.Spool.CollectorID ||
		end.Sensor.Sequence <= start.Sensor.Sequence || end.Sensor.KernelTimeNS < start.Sensor.KernelTimeNS ||
		end.Sensor.DecodedRecords < start.Sensor.DecodedRecords || end.Spool.Sequence < start.Spool.Sequence {
		issues = append(issues, "collector_boundary_changed")
	}
	if end.Sensor.KernelDrops != start.Sensor.KernelDrops || end.Sensor.StateQueueDrops != start.Sensor.StateQueueDrops {
		issues = append(issues, "shared_collector_loss")
	}
	if end.Sensor.PendingTLSStreams > 0 || end.Sensor.PendingTLSBytes > 0 {
		issues = append(issues, "shared_tls_pending")
	}
	if end.Sensor.TLSLostStreams != start.Sensor.TLSLostStreams || end.Sensor.TLSLostBytes != start.Sensor.TLSLostBytes {
		issues = append(issues, "shared_tls_loss")
	}
	for _, key := range []string{"invalid", "dropped_oversize", "dropped_queue_full", "dropped_partial_recovery"} {
		if end.Spool.Counters[key] != start.Spool.Counters[key] {
			issues = append(issues, "shared_spool_loss")
			break
		}
	}
	if progress.State != "settled" || progress.PendingBatches != 0 || progress.Pending != 0 {
		issues = append(issues, "scope_prefix_pending")
	}
	if progress.Dropped != 0 || progress.Failed != 0 {
		issues = append(issues, "scope_prefix_loss")
	}
	if progress.SamplingGaps != 0 {
		issues = append(issues, "scope_state_sampling_gap")
	}
	return issues
}
