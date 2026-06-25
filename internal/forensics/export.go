package forensics

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/byteyellow/agentprovenance/internal/evidence"
	"github.com/byteyellow/agentprovenance/internal/ids"
	"github.com/byteyellow/agentprovenance/internal/security"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

type Service struct {
	DB    *sql.DB
	Paths store.Paths
}

type BundleInfo struct {
	SchemaVersion string `json:"schema_version"`
	ID            string `json:"id"`
	RunID         string `json:"run_id"`
	Path          string `json:"path"`
	SHA256        string `json:"sha256"`
	SizeBytes     int64  `json:"size_bytes"`
	Status        string `json:"status"`
	CreatedAt     string `json:"created_at"`
}

func (s Service) Export(runID string) (string, error) {
	info, err := s.ExportBundle(runID)
	if err != nil {
		return "", err
	}
	return info.Path, nil
}

func (s Service) ExportBundle(runID string) (BundleInfo, error) {
	if runID == "" {
		return BundleInfo{}, fmt.Errorf("run_id is required")
	}
	events, err := telemetry.ListEvents(s.DB, runID, "")
	if err != nil {
		return BundleInfo{}, err
	}
	decisions, err := security.ListDecisions(s.DB, runID)
	if err != nil {
		return BundleInfo{}, err
	}
	risks, err := security.ListRiskSignals(s.DB, runID)
	if err != nil {
		return BundleInfo{}, err
	}
	responses, err := security.ListResponseActions(s.DB, runID)
	if err != nil {
		return BundleInfo{}, err
	}
	batches, err := telemetry.ListBatches(s.DB, runID)
	if err != nil {
		return BundleInfo{}, err
	}
	evidenceManifest, err := evidence.BuildManifest(s.DB, evidence.ManifestOptions{RunID: runID})
	if err != nil {
		return BundleInfo{}, err
	}
	sessions, err := selectRows(s.DB, `SELECT id, lease_id, status, run_id, COALESCE(container_id, '') AS container_id, workspace_host_path, startup_cold_ms, created_at, updated_at
		FROM sessions WHERE run_id = ? ORDER BY created_at ASC`, runID)
	if err != nil {
		return BundleInfo{}, err
	}
	processes, err := selectRows(s.DB, `SELECT id, session_id, COALESCE(container_id, '') AS container_id, COALESCE(exec_id, '') AS exec_id, command, status, COALESCE(exit_code, 0) AS exit_code, started_at, COALESCE(ended_at, '') AS ended_at
		FROM processes WHERE session_id IN (SELECT id FROM sessions WHERE run_id = ?) ORDER BY started_at ASC`, runID)
	if err != nil {
		return BundleInfo{}, err
	}
	snapshots, err := selectRows(s.DB, `SELECT id, COALESCE(name, '') AS name, COALESCE(session_id, '') AS session_id, COALESCE(parent_id, '') AS parent_id, kind, source, path, manifest_hash, file_count, bytes, snapshot_create_ms, status, created_at
		FROM snapshots WHERE session_id IN (SELECT id FROM sessions WHERE run_id = ?) ORDER BY created_at ASC`, runID)
	if err != nil {
		return BundleInfo{}, err
	}
	evidenceEvents, err := selectRows(s.DB, `SELECT id, rollout_id, attempt_id, session_id, tool_call_id, snapshot_id, event_type, priority, status, created_at, COALESCE(processed_at, '') AS processed_at, COALESCE(payload, '') AS payload
		FROM evidence_events WHERE run_id = ? ORDER BY created_at ASC`, runID)
	if err != nil {
		return BundleInfo{}, err
	}
	graphEdges, err := selectRows(s.DB, `SELECT id, COALESCE(rollout_id, '') AS rollout_id, from_id, to_id, edge_type, COALESCE(source_event_id, '') AS source_event_id, created_at
		FROM graph_edges WHERE run_id = ? ORDER BY created_at ASC`, runID)
	if err != nil {
		return BundleInfo{}, err
	}
	costSamples, err := selectRows(s.DB, `SELECT id, COALESCE(session_id, '') AS session_id, active_cpu_seconds, idle_seconds, wall_seconds, snapshot_bytes, policy_block_count, quarantine_count, node_id, fanout_cost, saved_cost, created_at
		FROM cost_samples WHERE run_id = ? ORDER BY created_at ASC`, runID)
	if err != nil {
		return BundleInfo{}, err
	}

	bundle := map[string]any{
		"schema_version":    "agentprovenance.forensics_bundle/v1",
		"run_id":            runID,
		"exported_at":       time.Now().UTC().Format(time.RFC3339Nano),
		"evidence_manifest": evidenceManifest,
		"sessions":          sessions,
		"processes":         processes,
		"snapshots":         snapshots,
		"events":            events,
		"telemetry_batches": telemetryBatchSummaries(batches),
		"policy_decisions":  decisions,
		"risk_signals":      risks,
		"response_actions":  responses,
		"evidence_events":   evidenceEvents,
		"graph_edges":       graphEdges,
		"cost_samples":      costSamples,
	}
	raw, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return BundleInfo{}, err
	}
	bundleID := ids.New("forensics")
	path := filepath.Join(s.Paths.Artifacts, bundleID+".json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return BundleInfo{}, err
	}
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.DB.Exec(`INSERT INTO forensics_bundles (id, run_id, path, sha256, size_bytes, status, created_at)
		VALUES (?, ?, ?, ?, ?, 'ready', ?)`, bundleID, runID, path, hash, len(raw), now)
	if err != nil {
		return BundleInfo{}, err
	}
	return BundleInfo{SchemaVersion: "agentprovenance.forensics_export/v1", ID: bundleID, RunID: runID, Path: path, SHA256: hash, SizeBytes: int64(len(raw)), Status: "ready", CreatedAt: now}, nil
}

func telemetryBatchSummaries(batches []telemetry.BatchRecord) []map[string]any {
	out := make([]map[string]any, 0, len(batches))
	for _, batch := range batches {
		out = append(out, map[string]any{
			"id":                batch.ID,
			"run_id":            batch.RunID,
			"format":            batch.Format,
			"path":              batch.Path,
			"file_sha256":       batch.FileSHA256,
			"read":              batch.Read,
			"ingested":          batch.Ingested,
			"skipped":           batch.Skipped,
			"failed":            batch.Failed,
			"event_ids_sha256":  batch.EventIDsSHA256,
			"created_at":        batch.CreatedAt,
			"source_query_hint": "telemetry batches --run " + batch.RunID,
		})
	}
	return out
}

func selectRows(db *sql.DB, query string, args ...any) ([]map[string]any, error) {
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	result := []map[string]any{}
	for rows.Next() {
		values := make([]any, len(columns))
		valuePtrs := make([]any, len(columns))
		for i := range columns {
			valuePtrs[i] = &values[i]
		}
		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, err
		}
		item := map[string]any{}
		for i, column := range columns {
			switch v := values[i].(type) {
			case []byte:
				item[column] = string(v)
			default:
				item[column] = v
			}
		}
		result = append(result, item)
	}
	return result, rows.Err()
}
