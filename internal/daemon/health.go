package daemon

import (
	"context"
	"net/http"
	"time"

	"github.com/byteyellow/agentprovenance/internal/i18n"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func (s Server) live(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"schema_version": "agentprovenance.daemon_liveness/v1", "status": "ok"})
}

// Health is readiness, not process liveness. Preserve the existing successful
// response fields, but never substitute zero/ok for an unreadable database.
func (s Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	runtimeName := ""
	if s.Driver != nil {
		runtimeName = s.Driver.Name()
	}
	body := map[string]any{
		"schema_version": "agentprovenance.daemon_health/v1", "status": "unavailable", "ready": false,
		"runtime": runtimeName, "sample_interval_ms": s.SampleInterval.Milliseconds(), "sample_limit": s.SampleLimit,
		"sample_timeout_ms": s.SampleTimeout.Milliseconds(), "raw_retention_ms": s.RawRetention.Milliseconds(), "max_raw_samples": s.MaxRawSamples,
		"background_sampler": s.SampleInterval > 0, "evidence_interval_ms": s.EvidenceInterval.Milliseconds(), "evidence_limit": s.EvidenceLimit,
		"spool_interval_ms": s.SpoolInterval.Milliseconds(), "spool_limit": s.SpoolLimit, "spool_max_queued": s.SpoolMaxQueued,
		"spool_max_bytes": s.SpoolMaxBytes, "spool_max_batch_bytes": s.SpoolMaxBatchBytes, "spool_drop_policy": s.SpoolDropPolicy,
		"gc_interval_ms": s.GCInterval.Milliseconds(), "gc_limit": s.GCLimit,
		"last_cpu_sample_at": nil, "queued_evidence": nil, "queued_gc": nil, "queued_spool": nil, "queued_spool_bytes": nil,
		"coverage_status": "unknown",
	}
	fail := func(check string, err error) {
		body["checks"] = map[string]any{check: map[string]any{"status": "failed", "reason": err.Error()}}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(w, body)
	}
	if s.DB == nil {
		fail("storage", i18n.Errorf("database is not configured"))
		return
	}
	var schema int
	var last string
	var evidence, gc, spool, spoolBytes, failed int64
	err := s.DB.QueryRowContext(ctx, `SELECT
  (SELECT COALESCE(MAX(version),0) FROM schema_versions),
  (SELECT COALESCE(MAX(created_at),'') FROM cpu_samples),
  (SELECT COUNT(*) FROM evidence_events WHERE status='queued'),
  (SELECT COUNT(*) FROM gc_jobs WHERE status='queued'),
  (SELECT COUNT(*) FROM telemetry_spool_batches WHERE status IN ('initializing','capturing','queued','processing') OR (format='native' AND status='processed' AND spool_path!='')),
  (SELECT COALESCE(SUM(size_bytes),0) FROM telemetry_spool_batches WHERE status IN ('initializing','capturing','queued','processing') OR (format='native' AND status='processed' AND spool_path!='')),
  (SELECT COUNT(*) FROM telemetry_spool_batches WHERE status='failed')`).Scan(&schema, &last, &evidence, &gc, &spool, &spoolBytes, &failed)
	if err != nil {
		fail("storage", err)
		return
	}
	if schema != store.SchemaVersion {
		fail("schema", i18n.Errorf("database schema %d, binary requires %d", schema, store.SchemaVersion))
		return
	}
	capture, err := telemetry.ReadNativeStreamStatusContext(ctx, s.DB)
	if err != nil {
		fail("capture_status", err)
		return
	}
	body["status"], body["ready"] = "ok", true
	body["checks"] = map[string]any{"storage": map[string]any{"status": "ok"}, "schema": map[string]any{"status": "ok", "version": schema}}
	body["last_cpu_sample_at"], body["queued_evidence"], body["queued_gc"] = last, evidence, gc
	body["queued_spool"], body["queued_spool_bytes"], body["failed_spool"] = spool, spoolBytes, failed
	body["native_capture"] = capture
	// A working query service can be ready even with known historical loss.
	// Keep coverage separate: pending work is not itself proof of event loss.
	coverage := "not_observed"
	if capture.Counters["captured"] > 0 {
		coverage = "no_recorded_gaps"
	}
	if capture.PendingEvents > 0 {
		coverage = "pending"
	}
	for _, key := range []string{"dropped_queue_full", "dropped_oversize", "expired_uncorrelated", "kernel_dropped_events", "tls_truncated_messages", "tls_reassembly_dropped_streams", "tls_reassembly_dropped_bytes", "dropped_partial_recovery", "dropped_partial_shutdown", "invalid"} {
		if capture.Counters[key] > 0 {
			coverage = "gaps_recorded"
			break
		}
	}
	body["coverage_status"] = coverage
	if failed > 0 || capture.LastError != "" || coverage == "gaps_recorded" {
		body["status"] = "degraded"
	}
	writeJSON(w, body)
}
