package daemon

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/byteyellow/agentprovenance/internal/control"
	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/evidence"
	"github.com/byteyellow/agentprovenance/internal/experimental/economics"
	"github.com/byteyellow/agentprovenance/internal/experimental/scheduler"
	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	securitymodel "github.com/byteyellow/agentprovenance/internal/security"
	"github.com/byteyellow/agentprovenance/internal/store"
	runtimeplane "github.com/byteyellow/agentprovenance/internal/substrate/runtime"
	"github.com/byteyellow/agentprovenance/internal/substrate/state"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

type Server struct {
	DB               *sql.DB
	Paths            store.Paths
	Driver           runtimeplane.Driver
	SampleInterval   time.Duration
	SampleLimit      int
	SampleTimeout    time.Duration
	RawRetention     time.Duration
	MaxRawSamples    int
	EvidenceInterval time.Duration
	EvidenceLimit    int
	GCInterval       time.Duration
	GCLimit          int
	writeMu          *sync.Mutex
}

func NewServer(dataDir string) (Server, func(), error) {
	paths, err := store.Init(dataDir)
	if err != nil {
		return Server{}, nil, err
	}
	db, err := store.Open(paths)
	if err != nil {
		return Server{}, nil, err
	}
	driver, err := runtimeplane.NewDriver("docker", paths)
	if err != nil {
		db.Close()
		return Server{}, nil, err
	}
	return Server{DB: db, Paths: paths, Driver: driver, writeMu: &sync.Mutex{}}, func() { db.Close() }, nil
}

func (s Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", s.health)
	mux.HandleFunc("GET /v1/scheduler/status", s.schedulerStatus)
	mux.HandleFunc("POST /v1/leases", s.createLease)
	mux.HandleFunc("POST /v1/sessions", s.createSession)
	mux.HandleFunc("GET /v1/sessions", s.listSessions)
	mux.HandleFunc("/v1/sessions/", s.sessionByID)
	mux.HandleFunc("POST /v1/snapshots", s.createSnapshot)
	mux.HandleFunc("/v1/snapshots/", s.snapshotByID)
	mux.HandleFunc("POST /v1/telemetry/bind", s.bindTelemetry)
	mux.HandleFunc("POST /v1/telemetry/ingest-falco", s.ingestFalco)
	mux.HandleFunc("GET /v1/graph/verify", s.graphVerify)
	mux.HandleFunc("GET /v1/evidence/manifest", s.evidenceManifest)
	mux.HandleFunc("POST /v1/forensics/export", s.forensicsExport)
	return mux
}

func (s Server) control() control.Service {
	return control.Service{DB: s.DB, Paths: s.Paths, Driver: s.Driver, WriteMu: s.writeMu}
}

func (s Server) health(w http.ResponseWriter, r *http.Request) {
	var lastSample string
	var queuedEvidence, queuedGC int64
	_ = s.DB.QueryRow(`SELECT COALESCE(MAX(created_at), '') FROM cpu_samples`).Scan(&lastSample)
	_ = s.DB.QueryRow(`SELECT COALESCE(COUNT(*), 0) FROM evidence_events WHERE status = 'queued'`).Scan(&queuedEvidence)
	_ = s.DB.QueryRow(`SELECT COALESCE(COUNT(*), 0) FROM gc_jobs WHERE status = 'queued'`).Scan(&queuedGC)
	writeJSON(w, map[string]any{
		"status":               "ok",
		"runtime":              s.Driver.Name(),
		"sample_interval_ms":   s.SampleInterval.Milliseconds(),
		"sample_limit":         s.SampleLimit,
		"sample_timeout_ms":    s.SampleTimeout.Milliseconds(),
		"raw_retention_ms":     s.RawRetention.Milliseconds(),
		"max_raw_samples":      s.MaxRawSamples,
		"last_cpu_sample_at":   lastSample,
		"background_sampler":   s.SampleInterval > 0,
		"evidence_interval_ms": s.EvidenceInterval.Milliseconds(),
		"evidence_limit":       s.EvidenceLimit,
		"gc_interval_ms":       s.GCInterval.Milliseconds(),
		"gc_limit":             s.GCLimit,
		"queued_evidence":      queuedEvidence,
		"queued_gc":            queuedGC,
	})
}

func (s Server) schedulerStatus(w http.ResponseWriter, r *http.Request) {
	state, err := (scheduler.Scheduler{DB: s.DB}).NodeState(r.URL.Query().Get("snapshot"))
	writeResult(w, map[string]any{"node": state}, err)
}

func (s Server) StartSampler(ctx context.Context) {
	if s.SampleInterval <= 0 {
		return
	}
	ticker := time.NewTicker(s.SampleInterval)
	defer ticker.Stop()
	s.sampleOnce()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sampleOnce()
		}
	}
}

func (s Server) sampleOnce() {
	result, err := economics.SampleRunningDockerSessionsWithOptions(s.DB, economics.SamplerOptions{Limit: s.SampleLimit, Timeout: s.SampleTimeout, RawRetention: s.RawRetention, MaxRawPerSession: s.MaxRawSamples})
	now := time.Now().UTC().Format(time.RFC3339Nano)
	payload := fmt.Sprintf(`{"sampled":%d,"failed":%d,"skipped":%d,"errors":%q}`, result.Sampled, result.Failed, result.Skipped, strings.Join(result.Errors, "; "))
	if err != nil {
		payload = fmt.Sprintf(`{"sampled":0,"failed":1,"errors":%q}`, err.Error())
	}
	_, _ = s.DB.Exec(`INSERT INTO events (id, source, event_type, payload, created_at)
		VALUES ('evt-' || lower(hex(randomblob(6))), 'daemon_sampler', 'scheduler_sample', ?, ?)`, payload, now)
}

func (s Server) StartEvidenceWorker(ctx context.Context) {
	if s.EvidenceInterval <= 0 {
		return
	}
	ticker := time.NewTicker(s.EvidenceInterval)
	defer ticker.Stop()
	s.processEvidenceOnce()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.processEvidenceOnce()
		}
	}
}

func (s Server) processEvidenceOnce() {
	limit := s.EvidenceLimit
	if limit <= 0 {
		limit = 100
	}
	result, err := (evidence.Service{DB: s.DB, Paths: s.Paths}).ProcessEvidence(limit)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	payload := fmt.Sprintf(`{"processed":%d}`, result.Processed)
	if err != nil {
		payload = fmt.Sprintf(`{"processed":%d,"error":%q}`, result.Processed, err.Error())
	}
	_, _ = s.DB.Exec(`INSERT INTO events (id, source, event_type, payload, created_at)
		VALUES ('evt-' || lower(hex(randomblob(6))), 'daemon_evidence', 'evidence_worker', ?, ?)`, payload, now)
}

func (s Server) StartGCWorker(ctx context.Context) {
	if s.GCInterval <= 0 {
		return
	}
	ticker := time.NewTicker(s.GCInterval)
	defer ticker.Stop()
	s.gcOnce()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.gcOnce()
		}
	}
}

func (s Server) gcOnce() {
	limit := s.GCLimit
	if limit <= 0 {
		limit = 100
	}
	result, err := (evidence.Service{DB: s.DB, Paths: s.Paths}).RunGC(limit)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	payload := fmt.Sprintf(`{"processed":%d,"failed":%d,"reclaimed_bytes":%d,"reclaimed_inodes":%d}`, result.Processed, result.Failed, result.ReclaimedBytes, result.ReclaimedInodes)
	if err != nil {
		payload = fmt.Sprintf(`{"processed":%d,"failed":%d,"error":%q}`, result.Processed, result.Failed+1, err.Error())
	}
	_, _ = s.DB.Exec(`INSERT INTO events (id, source, event_type, payload, created_at)
		VALUES ('evt-' || lower(hex(randomblob(6))), 'daemon_gc', 'gc_worker', ?, ?)`, payload, now)
}

func (s Server) createLease(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Task string `json:"task"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	s.lockWrites()
	defer s.unlockWrites()
	id, err := s.control().CreateLease(req.Task)
	writeResult(w, map[string]any{"lease_id": id}, err)
}

func (s Server) createSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LeaseID string `json:"lease_id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	s.lockWrites()
	defer s.unlockWrites()
	id, err := s.control().CreateSession(req.LeaseID)
	writeResult(w, map[string]any{"session_id": id}, err)
}

func (s Server) listSessions(w http.ResponseWriter, r *http.Request) {
	items, err := s.control().ListSessions()
	writeResult(w, map[string]any{"sessions": items}, err)
}

func (s Server) sessionByID(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/sessions/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	sessionID := parts[0]
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			item, err := s.control().InspectSession(sessionID)
			writeResult(w, map[string]any{"session": item}, err)
		case http.MethodDelete:
			s.lockWrites()
			defer s.unlockWrites()
			err := s.control().RemoveSession(sessionID)
			writeResult(w, map[string]any{"status": "removed"}, err)
		default:
			http.NotFound(w, r)
		}
		return
	}
	switch parts[1] {
	case "cpu-profile":
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var req struct {
			Profile string `json:"profile"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		s.lockWrites()
		defer s.unlockWrites()
		err := s.control().SetSessionCPUProfile(sessionID, req.Profile)
		writeResult(w, map[string]any{"status": "updated", "profile": req.Profile}, err)
	case "exec":
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		s.exec(w, r, sessionID)
	case "stop":
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		s.lockWrites()
		defer s.unlockWrites()
		err := s.control().StopSession(sessionID)
		writeResult(w, map[string]any{"status": "stopped"}, err)
	default:
		http.NotFound(w, r)
	}
}

func (s Server) exec(w http.ResponseWriter, r *http.Request, sessionID string) {
	var req struct {
		Command []string `json:"command"`
		Stream  bool     `json:"stream"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Stream {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		processID, err := s.control().ExecStream(sessionID, req.Command, flushWriter{ResponseWriter: w}, flushWriter{ResponseWriter: w})
		if err != nil {
			fmt.Fprintf(w, "\nerror=%q\n", err.Error())
			return
		}
		fmt.Fprintf(w, "\n%s\n", processID)
		return
	}
	processID, err := s.control().Exec(sessionID, req.Command, false)
	writeResult(w, map[string]any{"process_id": processID}, err)
}

func (s Server) createSnapshot(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
		Type      string `json:"type"`
		Path      string `json:"path"`
		Name      string `json:"name"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Type == "" {
		req.Type = "directory"
	}
	if req.Path == "" {
		req.Path = "/workspace"
	}
	if req.Type != "directory" {
		writeResult(w, nil, fmt.Errorf("only directory snapshots are supported"))
		return
	}
	s.lockWrites()
	defer s.unlockWrites()
	id, manifest, snapshotCreateMS, err := state.Service{DB: s.DB, Paths: s.Paths}.CreateDirectorySnapshot(req.SessionID, req.Path, req.Name)
	writeResult(w, map[string]any{"snapshot_id": id, "files": manifest.Files, "bytes": manifest.Bytes, "snapshot_create_ms": snapshotCreateMS, "hash": manifest.Hash}, err)
}

func (s Server) snapshotByID(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/snapshots/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] != "resume" || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	var req struct {
		LeaseID string `json:"lease_id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	s.lockWrites()
	defer s.unlockWrites()
	id, err := s.control().ResumeSnapshot(parts[0], req.LeaseID)
	writeResult(w, map[string]any{"session_id": id}, err)
}

func (s Server) bindTelemetry(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RunID         string  `json:"run_id"`
		SessionID     string  `json:"session_id"`
		AttemptID     string  `json:"attempt_id"`
		ToolCallID    string  `json:"tool_call_id"`
		ProcessID     string  `json:"process_id"`
		ContainerID   string  `json:"container_id"`
		CgroupID      string  `json:"cgroup_id"`
		RootPID       int64   `json:"root_pid"`
		PID           int64   `json:"pid"`
		StartedAt     string  `json:"started_at"`
		EndedAt       string  `json:"ended_at"`
		BindingSource string  `json:"binding_source"`
		Confidence    float64 `json:"confidence"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	s.lockWrites()
	defer s.unlockWrites()
	id, err := correlation.RecordBinding(s.DB, correlation.Binding{
		RunID:         req.RunID,
		SessionID:     req.SessionID,
		AttemptID:     req.AttemptID,
		ToolCallID:    req.ToolCallID,
		ProcessID:     req.ProcessID,
		ContainerID:   req.ContainerID,
		CgroupID:      req.CgroupID,
		RootPID:       req.RootPID,
		PID:           req.PID,
		StartedAt:     req.StartedAt,
		EndedAt:       req.EndedAt,
		BindingSource: req.BindingSource,
		Confidence:    req.Confidence,
	})
	writeResult(w, map[string]any{"binding_id": id, "schema_version": "agentprovenance.daemon_telemetry_binding/v1"}, err)
}

func (s Server) ingestFalco(w http.ResponseWriter, r *http.Request) {
	var req struct {
		File     string `json:"file"`
		RunID    string `json:"run_id"`
		NoPolicy bool   `json:"no_policy"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	s.lockWrites()
	defer s.unlockWrites()
	file, err := os.Open(req.File)
	if err != nil {
		writeResult(w, nil, err)
		return
	}
	defer file.Close()
	result, err := telemetry.IngestFalco(s.DB, telemetry.FalcoIngestOptions{Path: req.File, RunID: req.RunID}, file)
	if err == nil && !req.NoPolicy {
		evaluateTelemetryPolicy(s.DB, &result)
	}
	writeResult(w, map[string]any{"batch": result, "policy_decisions": result.PolicyDecisions, "schema_version": "agentprovenance.daemon_falco_ingest/v1"}, err)
}

func (s Server) graphVerify(w http.ResponseWriter, r *http.Request) {
	runID := r.URL.Query().Get("run")
	result, err := provenance.Verify(s.DB, runID)
	writeResult(w, result, err)
}

func (s Server) evidenceManifest(w http.ResponseWriter, r *http.Request) {
	runID := r.URL.Query().Get("run")
	materialize := r.URL.Query().Get("materialize") == "1" || r.URL.Query().Get("materialize") == "true"
	objectLimit := 25
	if materialize {
		s.lockWrites()
		defer s.unlockWrites()
	}
	result, err := buildEvidenceManifest(s.DB, s.Paths, runID, objectLimit, materialize)
	writeResult(w, result, err)
}

func (s Server) forensicsExport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RunID string `json:"run_id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	s.lockWrites()
	defer s.unlockWrites()
	bundle, err := (forensics.Service{DB: s.DB, Paths: s.Paths}).ExportBundle(req.RunID)
	writeResult(w, bundle, err)
}

func evaluateTelemetryPolicy(db *sql.DB, result *telemetry.JSONLIngestResult) {
	if result == nil {
		return
	}
	for _, eventID := range result.EventIDs {
		record, persisted, err := securitymodel.EvaluateRuntimeEvent(db, eventID)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("event %s: policy failed: %v", eventID, err))
			result.Failed++
			continue
		}
		if persisted {
			result.PolicyDecisions++
			result.PolicyDecisionIDs = append(result.PolicyDecisionIDs, record.ID)
		}
	}
}

func buildEvidenceManifest(db *sql.DB, paths store.Paths, runID string, objectLimit int, materialize bool) (evidence.MaterializedManifest, error) {
	report, err := evidence.BuildManifest(db, evidence.ManifestOptions{RunID: runID, ObjectLimit: objectLimit})
	if err != nil {
		return evidence.MaterializedManifest{}, err
	}
	output := evidence.MaterializedManifest{Manifest: report}
	if !materialize {
		return output, nil
	}
	parentHashes := make([]string, 0, len(report.Objects.TopRefs))
	for _, ref := range report.Objects.TopRefs {
		if ref.Hash != "" {
			parentHashes = append(parentHashes, ref.Hash)
		}
	}
	result, err := (provenance.ObjectStore{DB: db, Paths: paths}).PutExternalObject(provenance.ExternalObjectInput{
		Type:     "evidence_manifest",
		SourceID: runID,
		RunID:    runID,
		Parents:  parentHashes,
		Refs: map[string]any{
			"run_id":                  runID,
			"schema_version":          report.SchemaVersion,
			"summary_result_set_id":   report.Summary.ResultSetID,
			"timeline_result_set_id":  report.Timeline.ResultSetID,
			"objects_result_set_id":   report.Objects.ResultSetID,
			"risks_result_set_id":     report.Security.RisksResultSetID,
			"responses_result_set_id": report.Security.ResponsesResultSetID,
		},
		Payload: map[string]any{"manifest": report},
	})
	if err != nil {
		return evidence.MaterializedManifest{}, err
	}
	output.ObjectHash = result.Hash
	output.ObjectPath = result.Path
	return output, nil
}

func (s Server) lockWrites() {
	if s.writeMu != nil {
		s.writeMu.Lock()
	}
}

func (s Server) unlockWrites() {
	if s.writeMu != nil {
		s.writeMu.Unlock()
	}
}

type flushWriter struct {
	http.ResponseWriter
}

func (w flushWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
	return n, err
}

func decodeJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(out); err != nil {
		writeResult(w, nil, err)
		return false
	}
	return true
}

func writeResult(w http.ResponseWriter, data any, err error) {
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, data)
}

func writeJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(data)
}
