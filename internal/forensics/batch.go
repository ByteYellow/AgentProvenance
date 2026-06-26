package forensics

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/ids"
	"github.com/byteyellow/agentprovenance/internal/signal"
)

type BatchExportOptions struct {
	BatchID             string `json:"batch_id,omitempty"`
	RunID               string `json:"run_id,omitempty"`
	JobID               string `json:"job_id,omitempty"`
	ShardID             string `json:"shard_id,omitempty"`
	Latest              bool   `json:"latest,omitempty"`
	Limit               int    `json:"limit"`
	IncludeRunBundles   bool   `json:"include_run_bundles"`
	IncludeEvalContexts bool   `json:"include_eval_contexts,omitempty"`
}

type BatchBundleInfo struct {
	SchemaVersion string             `json:"schema_version"`
	ID            string             `json:"id"`
	BatchID       string             `json:"batch_id,omitempty"`
	Path          string             `json:"path"`
	SHA256        string             `json:"sha256"`
	SizeBytes     int64              `json:"size_bytes"`
	Status        string             `json:"status"`
	CreatedAt     string             `json:"created_at"`
	RunCount      int                `json:"run_count"`
	ItemCount     int                `json:"item_count"`
	ResultSetID   string             `json:"result_set_id"`
	PageHash      string             `json:"page_hash"`
	RunBundles    []BundleInfo       `json:"run_bundles,omitempty"`
	Query         BatchExportOptions `json:"query"`
}

type BatchBundle struct {
	SchemaVersion string               `json:"schema_version"`
	BundleID      string               `json:"bundle_id"`
	ExportedAt    string               `json:"exported_at"`
	Query         BatchExportOptions   `json:"query"`
	Summary       BatchSummary         `json:"summary"`
	RunBundles    []BundleInfo         `json:"run_bundles,omitempty"`
	EvalContexts  []signal.EvalContext `json:"eval_contexts,omitempty"`
	Commands      []BatchCommandRef    `json:"commands"`
	ResultSetID   string               `json:"result_set_id"`
	PageHash      string               `json:"page_hash"`
}

type BatchSummary struct {
	SchemaVersion string             `json:"schema_version"`
	Query         BatchExportOptions `json:"query"`
	BatchCount    int                `json:"batch_count"`
	ItemCount     int                `json:"item_count"`
	Passed        int                `json:"passed"`
	Failed        int                `json:"failed"`
	Skipped       int                `json:"skipped"`
	StatusCounts  map[string]int     `json:"status_counts"`
	Shards        map[string]int     `json:"shards,omitempty"`
	RunIDs        []string           `json:"run_ids"`
	Batches       []BatchHead        `json:"batches"`
	Items         []BatchItem        `json:"items"`
	ResultSetID   string             `json:"result_set_id"`
	PageHash      string             `json:"page_hash"`
}

type BatchHead struct {
	BatchID     string         `json:"batch_id"`
	InputSHA256 string         `json:"input_sha256"`
	StartedAt   string         `json:"started_at"`
	EndedAt     string         `json:"ended_at"`
	JobCount    int            `json:"job_count"`
	Passed      int            `json:"passed"`
	Failed      int            `json:"failed"`
	Skipped     int            `json:"skipped"`
	Shards      map[string]int `json:"shards,omitempty"`
	ResultSetID string         `json:"result_set_id"`
	PageHash    string         `json:"page_hash"`
	CreatedAt   string         `json:"created_at"`
}

type BatchItem struct {
	BatchID                 string   `json:"batch_id"`
	Index                   int      `json:"index"`
	JobID                   string   `json:"job_id,omitempty"`
	ShardID                 string   `json:"shard_id,omitempty"`
	RunID                   string   `json:"run_id,omitempty"`
	AttemptID               string   `json:"attempt_id,omitempty"`
	ToolCallID              string   `json:"tool_call_id,omitempty"`
	ProcessID               string   `json:"process_id,omitempty"`
	Workdir                 string   `json:"workdir,omitempty"`
	Command                 string   `json:"command,omitempty"`
	Status                  string   `json:"status"`
	ExitCode                int      `json:"exit_code"`
	WallMS                  int64    `json:"wall_ms"`
	ChangedFileCount        int      `json:"changed_file_count"`
	ChangedFiles            []string `json:"changed_files,omitempty"`
	Error                   string   `json:"error,omitempty"`
	EvidenceManifestCommand string   `json:"evidence_manifest_command,omitempty"`
	EvalContextCommand      string   `json:"eval_context_command,omitempty"`
	ExplainCommand          string   `json:"explain_command,omitempty"`
}

type BatchCommandRef struct {
	RunID            string `json:"run_id"`
	EvidenceManifest string `json:"evidence_manifest"`
	EvalContext      string `json:"eval_context"`
	Explain          string `json:"explain"`
	ForensicsExport  string `json:"forensics_export"`
}

func (s Service) ExportBatch(opts BatchExportOptions) (BatchBundleInfo, error) {
	if opts.Limit <= 0 {
		opts.Limit = 100
	}
	summary, err := BuildBatchSummary(s.DB, opts)
	if err != nil {
		return BatchBundleInfo{}, err
	}
	if len(summary.Items) == 0 {
		return BatchBundleInfo{}, fmt.Errorf("no batch items matched query")
	}
	runIDs := uniqueRunIDs(summary.Items)
	var runBundles []BundleInfo
	if opts.IncludeRunBundles {
		for _, runID := range runIDs {
			info, err := s.ExportBundle(runID)
			if err != nil {
				return BatchBundleInfo{}, fmt.Errorf("export run %s: %w", runID, err)
			}
			runBundles = append(runBundles, info)
		}
	}
	var evalContexts []signal.EvalContext
	if opts.IncludeEvalContexts {
		for _, runID := range runIDs {
			ctx, err := signal.BuildEvalContext(s.DB, runID)
			if err != nil {
				return BatchBundleInfo{}, fmt.Errorf("eval context %s: %w", runID, err)
			}
			evalContexts = append(evalContexts, ctx)
		}
	}
	commands := make([]BatchCommandRef, 0, len(runIDs))
	for _, runID := range runIDs {
		commands = append(commands, BatchCommandRef{
			RunID:            runID,
			EvidenceManifest: "evidence manifest --run " + runID + " --json",
			EvalContext:      "signal context --run " + runID,
			Explain:          "graph explain --run " + runID + " --json",
			ForensicsExport:  "forensics export " + runID + " --json",
		})
	}
	bundleID := ids.New("forensics-batch")
	bundle := BatchBundle{
		SchemaVersion: "agentprovenance.batch_forensics_bundle/v1",
		BundleID:      bundleID,
		ExportedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		Query:         opts,
		Summary:       summary,
		RunBundles:    runBundles,
		EvalContexts:  evalContexts,
		Commands:      commands,
	}
	bundle.ResultSetID = digestJSON("batch_forensics_result_set", map[string]any{
		"schema_version": bundle.SchemaVersion,
		"query":          opts,
		"run_ids":        runIDs,
		"summary":        summary.ResultSetID,
		"run_bundles":    runBundleHashes(runBundles),
	})
	bundle.PageHash = digestJSON("batch_forensics_page", map[string]any{
		"schema_version": bundle.SchemaVersion,
		"summary":        summary.PageHash,
		"commands":       commands,
		"run_bundles":    runBundles,
	})
	raw, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return BatchBundleInfo{}, err
	}
	path := filepath.Join(s.Paths.Artifacts, bundleID+".json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return BatchBundleInfo{}, err
	}
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	now := time.Now().UTC().Format(time.RFC3339Nano)
	return BatchBundleInfo{
		SchemaVersion: "agentprovenance.batch_forensics_export/v1",
		ID:            bundleID,
		BatchID:       primaryBatchID(summary.Batches),
		Path:          path,
		SHA256:        hash,
		SizeBytes:     int64(len(raw)),
		Status:        "ready",
		CreatedAt:     now,
		RunCount:      len(runIDs),
		ItemCount:     summary.ItemCount,
		ResultSetID:   bundle.ResultSetID,
		PageHash:      bundle.PageHash,
		RunBundles:    runBundles,
		Query:         opts,
	}, nil
}

func BuildBatchSummary(db *sql.DB, opts BatchExportOptions) (BatchSummary, error) {
	if opts.Limit <= 0 {
		opts.Limit = 100
	}
	batches, err := listBatchHeads(db, opts)
	if err != nil {
		return BatchSummary{}, err
	}
	items := make([]BatchItem, 0)
	statusCounts := map[string]int{}
	shards := map[string]int{}
	runSet := map[string]struct{}{}
	for _, batch := range batches {
		batchItems, err := listBatchItems(db, batch.BatchID, opts, opts.Limit-len(items))
		if err != nil {
			return BatchSummary{}, err
		}
		for _, item := range batchItems {
			items = append(items, item)
			statusCounts[item.Status]++
			if item.ShardID != "" {
				shards[item.ShardID]++
			}
			if item.RunID != "" {
				runSet[item.RunID] = struct{}{}
			}
		}
		if len(items) >= opts.Limit {
			break
		}
	}
	runIDs := make([]string, 0, len(runSet))
	for runID := range runSet {
		runIDs = append(runIDs, runID)
	}
	sort.Strings(runIDs)
	report := BatchSummary{
		SchemaVersion: "agentprovenance.record_batch_summary/v1",
		Query:         opts,
		BatchCount:    len(batches),
		ItemCount:     len(items),
		Passed:        statusCounts["passed"],
		Failed:        statusCounts["failed"],
		Skipped:       statusCounts["skipped"],
		StatusCounts:  statusCounts,
		Shards:        shards,
		RunIDs:        runIDs,
		Batches:       batches,
		Items:         items,
	}
	report.ResultSetID = digestJSON("record_batch_summary_result_set", map[string]any{
		"schema_version": report.SchemaVersion,
		"query":          opts,
		"batch_ids":      batchIDs(batches),
	})
	report.PageHash = digestJSON("record_batch_summary_page", map[string]any{
		"schema_version": report.SchemaVersion,
		"query":          opts,
		"items":          items,
		"status_counts":  statusCounts,
	})
	return report, nil
}

func listBatchHeads(db *sql.DB, opts BatchExportOptions) ([]BatchHead, error) {
	where := []string{"1=1"}
	args := []any{}
	if strings.TrimSpace(opts.BatchID) != "" {
		where = append(where, "id = ?")
		args = append(args, opts.BatchID)
	}
	existsWhere := []string{}
	if strings.TrimSpace(opts.RunID) != "" {
		existsWhere = append(existsWhere, "run_id = ?")
		args = append(args, opts.RunID)
	}
	if strings.TrimSpace(opts.JobID) != "" {
		existsWhere = append(existsWhere, "job_id = ?")
		args = append(args, opts.JobID)
	}
	if strings.TrimSpace(opts.ShardID) != "" {
		existsWhere = append(existsWhere, "shard_id = ?")
		args = append(args, opts.ShardID)
	}
	if len(existsWhere) > 0 {
		where = append(where, "EXISTS (SELECT 1 FROM record_batch_items i WHERE i.batch_id = record_batches.id AND "+joinAnd(existsWhere)+")")
	}
	limit := opts.Limit
	if opts.Latest {
		limit = 1
	}
	query := fmt.Sprintf(`SELECT id, input_sha256, started_at, ended_at, job_count, passed, failed, skipped, shards_json, result_set_id, page_hash, created_at
		FROM record_batches WHERE %s ORDER BY created_at DESC LIMIT ?`, joinAnd(where))
	args = append(args, limit)
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BatchHead
	for rows.Next() {
		var item BatchHead
		var shardsJSON string
		if err := rows.Scan(&item.BatchID, &item.InputSHA256, &item.StartedAt, &item.EndedAt, &item.JobCount, &item.Passed, &item.Failed, &item.Skipped, &shardsJSON, &item.ResultSetID, &item.PageHash, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.Shards = decodeStringIntMap(shardsJSON)
		out = append(out, item)
	}
	return out, rows.Err()
}

func listBatchItems(db *sql.DB, batchID string, opts BatchExportOptions, limit int) ([]BatchItem, error) {
	if limit <= 0 {
		return nil, nil
	}
	where := []string{"batch_id = ?"}
	args := []any{batchID}
	if strings.TrimSpace(opts.RunID) != "" {
		where = append(where, "run_id = ?")
		args = append(args, opts.RunID)
	}
	if strings.TrimSpace(opts.JobID) != "" {
		where = append(where, "job_id = ?")
		args = append(args, opts.JobID)
	}
	if strings.TrimSpace(opts.ShardID) != "" {
		where = append(where, "shard_id = ?")
		args = append(args, opts.ShardID)
	}
	query := fmt.Sprintf(`SELECT idx, job_id, shard_id, run_id, attempt_id, tool_call_id, process_id, workdir, command, status, exit_code, wall_ms, changed_file_count, changed_files_json, error, evidence_manifest_command, eval_context_command, explain_command
		FROM record_batch_items WHERE %s ORDER BY idx ASC LIMIT ?`, joinAnd(where))
	args = append(args, limit)
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BatchItem
	for rows.Next() {
		var item BatchItem
		var changedFilesJSON string
		if err := rows.Scan(&item.Index, &item.JobID, &item.ShardID, &item.RunID, &item.AttemptID, &item.ToolCallID, &item.ProcessID, &item.Workdir, &item.Command, &item.Status, &item.ExitCode, &item.WallMS, &item.ChangedFileCount, &changedFilesJSON, &item.Error, &item.EvidenceManifestCommand, &item.EvalContextCommand, &item.ExplainCommand); err != nil {
			return nil, err
		}
		item.BatchID = batchID
		_ = json.Unmarshal([]byte(changedFilesJSON), &item.ChangedFiles)
		out = append(out, item)
	}
	return out, rows.Err()
}

func uniqueRunIDs(items []BatchItem) []string {
	set := map[string]struct{}{}
	for _, item := range items {
		if item.RunID != "" {
			set[item.RunID] = struct{}{}
		}
	}
	runIDs := make([]string, 0, len(set))
	for runID := range set {
		runIDs = append(runIDs, runID)
	}
	sort.Strings(runIDs)
	return runIDs
}

func runBundleHashes(items []BundleInfo) []string {
	hashes := make([]string, 0, len(items))
	for _, item := range items {
		if item.SHA256 != "" {
			hashes = append(hashes, item.SHA256)
		}
	}
	sort.Strings(hashes)
	return hashes
}

func batchIDs(batches []BatchHead) []string {
	out := make([]string, 0, len(batches))
	for _, batch := range batches {
		out = append(out, batch.BatchID)
	}
	sort.Strings(out)
	return out
}

func primaryBatchID(batches []BatchHead) string {
	if len(batches) == 1 {
		return batches[0].BatchID
	}
	return ""
}

func decodeStringIntMap(raw string) map[string]int {
	out := map[string]int{}
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func joinAnd(parts []string) string {
	if len(parts) == 0 {
		return "1=1"
	}
	out := parts[0]
	for _, part := range parts[1:] {
		out += " AND " + part
	}
	return out
}

func digestJSON(prefix string, value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(append([]byte(prefix+":"), raw...))
	return hex.EncodeToString(sum[:])
}
