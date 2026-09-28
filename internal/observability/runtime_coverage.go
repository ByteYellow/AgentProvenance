package observability

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/sensor"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

const RuntimeCaptureSchema = "agentprovenance.runtime_capture/v1"

// RuntimeCoverage separates a saved capture interval from a fresh query over
// stored events. Neither correlation ratios nor signatures prove completeness.
type RuntimeCoverage struct {
	SchemaVersion string               `json:"schema_version"`
	RunID         string               `json:"run_id"`
	Capture       RuntimeCaptureReport `json:"capture"`
	Correlation   CoverageReport       `json:"correlation"`
}

type RuntimeCaptureReport struct {
	SchemaVersion     string                   `json:"schema_version"`
	RunID             string                   `json:"run_id"`
	Status            string                   `json:"status"`
	Scope             string                   `json:"scope"`
	KernelState       string                   `json:"kernel_state"`
	StartedAt         string                   `json:"started_at,omitempty"`
	EndedAt           string                   `json:"ended_at,omitempty"`
	NodeCounterDelta  map[string]int64         `json:"node_counter_delta"`
	NodePendingEvents *int64                   `json:"node_pending_events"`
	NodeQueuedBytes   *int64                   `json:"node_queued_bytes"`
	RunDroppedEvents  *int64                   `json:"run_dropped_events"`
	RunImpact         string                   `json:"run_impact"`
	CapabilitiesStart *sensor.CapabilityReport `json:"capabilities_start,omitempty"`
	CapabilitiesEnd   *sensor.CapabilityReport `json:"capabilities_end,omitempty"`
	Issues            []string                 `json:"issues"`
	Ref               string                   `json:"ref,omitempty"`
}

// CaptureSnapshot is sampled only by the capture lifecycle, never when a
// historical run is queried or imported on another machine.
type CaptureSnapshot struct {
	ObservedAt   time.Time
	Native       *telemetry.NativeStreamStatus
	Capabilities *sensor.CapabilityReport
	Issues       []string
}

func ObserveCapture(ctx context.Context, db *sql.DB, paths store.Paths, startedAfter time.Time) CaptureSnapshot {
	s := CaptureSnapshot{ObservedAt: time.Now().UTC()}
	native, err := telemetry.ReadNativeStreamStatusContext(ctx, db)
	if err != nil {
		s.Issues = append(s.Issues, "native_status_unavailable")
	} else {
		s.Native = &native
	}
	f, err := os.Open(filepath.Join(paths.Logs, "sensor-capabilities.json"))
	if err != nil {
		s.Issues = append(s.Issues, "probe_snapshot_unavailable")
		return s
	}
	defer f.Close()
	const maxBytes = 1 << 20
	raw, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	var caps sensor.CapabilityReport
	if err != nil || len(raw) > maxBytes || json.Unmarshal(raw, &caps) != nil || caps.SchemaVersion != "agentprovenance.sensor_capabilities/v1" {
		s.Issues = append(s.Issues, "probe_snapshot_invalid")
		return s
	}
	at, err := time.Parse(time.RFC3339Nano, caps.UpdatedAt)
	if err != nil || at.Before(startedAfter) || at.After(time.Now().UTC()) {
		s.Issues = append(s.Issues, "probe_snapshot_stale")
		return s
	}
	s.Capabilities = &caps
	return s
}

var lossCounters = []string{
	"dropped_queue_full", "dropped_oversize", "dropped_partial_recovery", "dropped_partial_shutdown",
	"expired_uncorrelated", "invalid", "kernel_dropped_events", "tls_reassembly_dropped_streams",
	"tls_reassembly_dropped_bytes", "tls_truncated_messages",
}

// KernelState is disabled, unavailable, or observed. An observed interval is
// bounded by launch's readiness/exit checks, not a claim of continuous health.
func BuildRuntimeCapture(runID, kernelState string, before, after CaptureSnapshot, cleanStop bool) RuntimeCaptureReport {
	r := RuntimeCaptureReport{SchemaVersion: RuntimeCaptureSchema, RunID: runID, Status: "ok",
		Scope: "node_capture_during_run", KernelState: kernelState, RunImpact: "unknown", Issues: []string{}}
	if !before.ObservedAt.IsZero() {
		r.StartedAt = before.ObservedAt.UTC().Format(time.RFC3339Nano)
	}
	if !after.ObservedAt.IsZero() {
		r.EndedAt = after.ObservedAt.UTC().Format(time.RFC3339Nano)
	}
	if kernelState != "observed" {
		r.Status = "disabled"
		if kernelState != "disabled" {
			r.Status = "no_input"
			r.Issues = append(r.Issues, "kernel_capture_unavailable")
		}
		return r
	}
	r.Issues = append(r.Issues, before.Issues...)
	r.Issues = append(r.Issues, after.Issues...)
	r.CapabilitiesStart, r.CapabilitiesEnd = before.Capabilities, after.Capabilities
	if !cleanStop {
		r.Issues = append(r.Issues, "collector_exit_unconfirmed")
	}
	if before.ObservedAt.IsZero() || after.ObservedAt.Before(before.ObservedAt) {
		r.Issues = append(r.Issues, "capture_interval_invalid")
	}
	if before.Capabilities == nil || after.Capabilities == nil {
		r.Issues = append(r.Issues, "probe_coverage_unknown")
	} else {
		if !before.Capabilities.Ready || before.Capabilities.Status != "ready" || after.Capabilities.Status == "failed" || after.Capabilities.Status == "degraded" {
			r.Issues = append(r.Issues, "probe_coverage_degraded")
		}
		for _, c := range []*sensor.CapabilityReport{before.Capabilities, after.Capabilities} {
			if c.TLSDiscovery.Enabled && (c.TLSDiscovery.Reason != "" || c.TLSDiscovery.SkippedTargets > 0 || c.TLSDiscovery.UnreadableProcesses > 0 || c.TLSDiscovery.TruncatedMaps > 0 || c.TLSDiscovery.UnsupportedExecutables > 0) {
				r.Issues = append(r.Issues, "tls_discovery_partial")
			}
			for _, p := range c.Probes {
				if p.Status == "failed" || p.Status == "unsupported" {
					r.Issues = append(r.Issues, "probe_coverage_degraded")
				}
			}
		}
	}
	if before.Native == nil || after.Native == nil {
		r.Issues = append(r.Issues, "node_counters_unavailable")
	} else {
		r.NodePendingEvents, r.NodeQueuedBytes = &after.Native.PendingEvents, &after.Native.QueuedBytes
		r.NodeCounterDelta = map[string]int64{}
		keys := map[string]bool{}
		for k := range before.Native.Counters {
			keys[k] = true
		}
		for k := range after.Native.Counters {
			keys[k] = true
		}
		for k := range keys {
			delta := after.Native.Counters[k] - before.Native.Counters[k]
			if delta < 0 {
				r.Issues = append(r.Issues, "node_counters_reset")
				continue
			}
			r.NodeCounterDelta[k] = delta
		}
		for _, k := range lossCounters {
			if r.NodeCounterDelta[k] > 0 {
				r.Issues = append(r.Issues, "node_loss_during_capture")
			}
		}
		if after.Native.PendingEvents > 0 || after.Native.QueuedBytes > 0 || after.Native.LastError != "" {
			r.Issues = append(r.Issues, "node_backlog_at_seal")
		}
	}
	sort.Strings(r.Issues)
	unique := r.Issues[:0]
	for _, issue := range r.Issues {
		if len(unique) == 0 || unique[len(unique)-1] != issue {
			unique = append(unique, issue)
		}
	}
	r.Issues = unique
	if len(r.Issues) > 0 {
		r.Status = "partial"
	} else {
		r.RunImpact = "no_node_loss_reported"
	}
	return r
}

func SaveRuntimeCapture(db *sql.DB, paths store.Paths, report *RuntimeCaptureReport) error {
	if report == nil || report.RunID == "" || report.SchemaVersion != RuntimeCaptureSchema {
		return fmt.Errorf("invalid runtime capture report")
	}
	value := *report
	value.Ref = ""
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return err
	}
	obj, err := (provenance.ObjectStore{DB: db, Paths: paths}).PutExternalObject(provenance.ExternalObjectInput{
		Type: "runtime_capture", SourceID: "runtime_capture/" + report.RunID, RunID: report.RunID, Payload: payload,
	})
	if err == nil {
		report.Ref = obj.Hash
	}
	return err
}

func ReadRuntimeCoverage(ctx context.Context, db *sql.DB, runID string) (RuntimeCoverage, error) {
	r := RuntimeCoverage{SchemaVersion: "agentprovenance.runtime_coverage/v1", RunID: runID,
		Capture: RuntimeCaptureReport{SchemaVersion: RuntimeCaptureSchema, RunID: runID,
			Status: "legacy_not_recorded", Scope: "unknown", KernelState: "unknown", RunImpact: "unknown",
			Issues: []string{"runtime_capture_not_recorded"}}}
	var ref string
	err := db.QueryRowContext(ctx, `SELECT hash FROM provenance_objects WHERE run_id=? AND object_type='runtime_capture'
		ORDER BY created_at DESC, hash DESC LIMIT 1`, runID).Scan(&ref)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return r, err
	}
	if err == nil {
		if err := provenance.ReadObjectPayload(db, runID, ref, &r.Capture); err != nil {
			return r, err
		}
		if r.Capture.SchemaVersion != RuntimeCaptureSchema || r.Capture.RunID != runID {
			return r, fmt.Errorf("runtime capture identity mismatch")
		}
		r.Capture.Ref = ref
	}
	r.Correlation, err = BuildCoverageContext(ctx, db, CoverageOptions{RunID: runID, Limit: 25})
	return r, err
}
