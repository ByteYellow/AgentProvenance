package cli

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"text/tabwriter"

	"github.com/byteyellow/agentprovenance/internal/evidence"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/spf13/cobra"
)

func evidenceCmd(dataDir, daemonURL *string) *cobra.Command {
	var limit int
	var runID string
	var objectLimit int
	var jsonOut bool
	var materializeObject bool
	process := &cobra.Command{
		Use:   "process",
		Short: "process queued compact evidence events into materialized graph edges",
		RunE: func(cmd *cobra.Command, args []string) error {
			service, cleanup, err := evidenceSvc(*dataDir)
			if err != nil {
				return err
			}
			defer cleanup()
			result, err := service.ProcessEvidence(limit)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "processed=%d\n", result.Processed)
			return nil
		},
	}
	process.Flags().IntVar(&limit, "limit", 100, "maximum evidence events to process")
	manifest := &cobra.Command{
		Use:   "manifest",
		Short: "build a run-level evidence manifest across observability, objects, risk, and response data",
		RunE: func(cmd *cobra.Command, args []string) error {
			if runID == "" {
				return fmt.Errorf("--run is required")
			}
			output, err := evidenceManifest(*dataDir, *daemonURL, runID, objectLimit, materializeObject)
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if materializeObject {
					return enc.Encode(output)
				}
				return enc.Encode(output.Manifest)
			}
			return printEvidenceManifest(cmd.OutOrStdout(), output)
		},
	}
	manifest.Flags().StringVar(&runID, "run", "", "run id")
	manifest.Flags().IntVar(&objectLimit, "object-limit", 25, "maximum object refs to include")
	manifest.Flags().BoolVar(&materializeObject, "materialize", false, "write the evidence manifest as a content-addressed provenance object")
	manifest.Flags().BoolVar(&jsonOut, "json", false, "emit JSON evidence manifest")
	cmd := &cobra.Command{Use: "evidence", Short: "evidence processing and manifest commands"}
	cmd.AddCommand(process)
	cmd.AddCommand(manifest)
	cmd.AddCommand(evidenceBatchSummaryCmd(dataDir))
	return cmd
}

func evidenceBatchSummaryCmd(dataDir *string) *cobra.Command {
	var batchID string
	var runID string
	var jobID string
	var shardID string
	var latest bool
	var limit int
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "batch-summary",
		Short: "summarize record batch manifests by batch, job, shard, or run",
		RunE: func(cmd *cobra.Command, args []string) error {
			paths, err := store.Init(*dataDir)
			if err != nil {
				return err
			}
			db, err := store.Open(paths)
			if err != nil {
				return err
			}
			defer db.Close()
			report, err := buildRecordBatchSummary(db, batchSummaryOptions{
				BatchID: batchID,
				RunID:   runID,
				JobID:   jobID,
				ShardID: shardID,
				Latest:  latest,
				Limit:   limit,
			})
			if err != nil {
				return err
			}
			if jsonOut {
				return printJSON(cmd.OutOrStdout(), report)
			}
			return printRecordBatchSummary(cmd.OutOrStdout(), report)
		},
	}
	cmd.Flags().StringVar(&batchID, "batch", "", "record batch id")
	cmd.Flags().StringVar(&runID, "run", "", "run id")
	cmd.Flags().StringVar(&jobID, "job", "", "job id")
	cmd.Flags().StringVar(&shardID, "shard", "", "shard id")
	cmd.Flags().BoolVar(&latest, "latest", false, "summarize only the latest batch matching filters")
	cmd.Flags().IntVar(&limit, "limit", 100, "maximum batch items to return")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON batch summary")
	return cmd
}

type batchSummaryOptions struct {
	BatchID string `json:"batch_id,omitempty"`
	RunID   string `json:"run_id,omitempty"`
	JobID   string `json:"job_id,omitempty"`
	ShardID string `json:"shard_id,omitempty"`
	Latest  bool   `json:"latest,omitempty"`
	Limit   int    `json:"limit"`
}

type recordBatchSummary struct {
	SchemaVersion string                   `json:"schema_version"`
	Query         batchSummaryOptions      `json:"query"`
	BatchCount    int                      `json:"batch_count"`
	ItemCount     int                      `json:"item_count"`
	Passed        int                      `json:"passed"`
	Failed        int                      `json:"failed"`
	Skipped       int                      `json:"skipped"`
	StatusCounts  map[string]int           `json:"status_counts"`
	Shards        map[string]int           `json:"shards,omitempty"`
	RunIDs        []string                 `json:"run_ids"`
	Batches       []recordBatchSummaryHead `json:"batches"`
	Items         []recordBatchItem        `json:"items"`
	ResultSetID   string                   `json:"result_set_id"`
	PageHash      string                   `json:"page_hash"`
}

type recordBatchSummaryHead struct {
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

func buildRecordBatchSummary(db *sql.DB, opts batchSummaryOptions) (recordBatchSummary, error) {
	if opts.Limit <= 0 {
		opts.Limit = 100
	}
	batches, err := listRecordBatchHeads(db, opts)
	if err != nil {
		return recordBatchSummary{}, err
	}
	items := make([]recordBatchItem, 0)
	statusCounts := map[string]int{}
	shards := map[string]int{}
	runSet := map[string]struct{}{}
	for _, batch := range batches {
		batchItems, err := listRecordBatchItems(db, batch.BatchID, opts, opts.Limit-len(items))
		if err != nil {
			return recordBatchSummary{}, err
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
	report := recordBatchSummary{
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
	report.ResultSetID = digestMap("record_batch_summary_result_set", map[string]any{
		"schema_version": report.SchemaVersion,
		"query":          opts,
		"batch_ids":      batchIDs(batches),
	})
	report.PageHash = digestMap("record_batch_summary_page", map[string]any{
		"schema_version": report.SchemaVersion,
		"query":          opts,
		"items":          items,
		"status_counts":  statusCounts,
	})
	return report, nil
}

func listRecordBatchHeads(db *sql.DB, opts batchSummaryOptions) ([]recordBatchSummaryHead, error) {
	where := []string{"1=1"}
	args := []any{}
	if opts.BatchID != "" {
		where = append(where, "id = ?")
		args = append(args, opts.BatchID)
	}
	existsWhere := []string{}
	if opts.RunID != "" {
		existsWhere = append(existsWhere, "run_id = ?")
		args = append(args, opts.RunID)
	}
	if opts.JobID != "" {
		existsWhere = append(existsWhere, "job_id = ?")
		args = append(args, opts.JobID)
	}
	if opts.ShardID != "" {
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
	var out []recordBatchSummaryHead
	for rows.Next() {
		var item recordBatchSummaryHead
		var shardsJSON string
		if err := rows.Scan(&item.BatchID, &item.InputSHA256, &item.StartedAt, &item.EndedAt, &item.JobCount, &item.Passed, &item.Failed, &item.Skipped, &shardsJSON, &item.ResultSetID, &item.PageHash, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.Shards = decodeStringIntMap(shardsJSON)
		out = append(out, item)
	}
	return out, rows.Err()
}

func listRecordBatchItems(db *sql.DB, batchID string, opts batchSummaryOptions, limit int) ([]recordBatchItem, error) {
	if limit <= 0 {
		return nil, nil
	}
	where := []string{"batch_id = ?"}
	args := []any{batchID}
	if opts.RunID != "" {
		where = append(where, "run_id = ?")
		args = append(args, opts.RunID)
	}
	if opts.JobID != "" {
		where = append(where, "job_id = ?")
		args = append(args, opts.JobID)
	}
	if opts.ShardID != "" {
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
	var out []recordBatchItem
	for rows.Next() {
		var item recordBatchItem
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

func printRecordBatchSummary(out io.Writer, report recordBatchSummary) error {
	fmt.Fprintf(out, "schema=%s batches=%d items=%d passed=%d failed=%d result_set=%s page_hash=%s\n",
		report.SchemaVersion, report.BatchCount, report.ItemCount, report.Passed, report.Failed, report.ResultSetID, report.PageHash)
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "BATCH\tJOB\tSHARD\tRUN\tSTATUS\tEXIT\tCHANGED\tWALL_MS")
	for _, item := range report.Items {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\n",
			item.BatchID, item.JobID, item.ShardID, item.RunID, item.Status, item.ExitCode, item.ChangedFileCount, item.WallMS)
	}
	return w.Flush()
}

func batchIDs(batches []recordBatchSummaryHead) []string {
	out := make([]string, 0, len(batches))
	for _, batch := range batches {
		out = append(out, batch.BatchID)
	}
	sort.Strings(out)
	return out
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

func evidenceManifest(dataDir, daemonURL, runID string, objectLimit int, materializeObject bool) (evidence.MaterializedManifest, error) {
	if client, ok := daemonClient(daemonURL); ok {
		return client.EvidenceManifest(runID, materializeObject)
	}
	paths, err := store.Init(dataDir)
	if err != nil {
		return evidence.MaterializedManifest{}, err
	}
	db, err := store.Open(paths)
	if err != nil {
		return evidence.MaterializedManifest{}, err
	}
	defer db.Close()
	report, err := evidence.BuildManifest(db, evidence.ManifestOptions{RunID: runID, ObjectLimit: objectLimit})
	if err != nil {
		return evidence.MaterializedManifest{}, err
	}
	output := evidence.MaterializedManifest{Manifest: report}
	if !materializeObject {
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

func printEvidenceManifest(out io.Writer, output evidence.MaterializedManifest) error {
	report := output.Manifest
	fmt.Fprintf(out, "run=%s schema=%s result_set=%s page_hash=%s\n", report.RunID, report.SchemaVersion, report.ResultSetID, report.PageHash)
	if output.ObjectHash != "" {
		fmt.Fprintf(out, "object_hash=%s object_path=%s\n", output.ObjectHash, output.ObjectPath)
	}
	fmt.Fprintf(out, "summary events=%d runtime_events=%d risks=%d responses=%d tool_call_coverage=%.2f process_coverage=%.2f\n",
		report.Summary.EventCount, report.Summary.Runtime.Events, report.Security.RiskCount, report.Security.ResponseCount,
		report.Summary.Runtime.ToolCallCoverageRatio, report.Summary.Runtime.ProcessCoverageRatio)
	fmt.Fprintf(out, "timeline events=%d result_set=%s page_hash=%s\n", report.Timeline.EventCount, report.Timeline.ResultSetID, report.Timeline.PageHash)
	fmt.Fprintf(out, "objects count=%d bytes=%d result_set=%s page_hash=%s has_more=%t\n",
		report.Objects.ObjectCount, report.Objects.TotalBytes, report.Objects.ResultSetID, report.Objects.PageHash, report.Objects.HasMore)
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "OBJECT_TYPE\tCOUNT")
	for typ, count := range report.Objects.ByType {
		fmt.Fprintf(w, "%s\t%d\n", typ, count)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if len(report.RecommendedViews) > 0 {
		fmt.Fprintln(out, "next_views:")
		for _, view := range report.RecommendedViews {
			fmt.Fprintf(out, "  agentprov %s\n", view)
		}
	}
	return nil
}

func gcCmd(dataDir *string) *cobra.Command {
	var limit int
	run := &cobra.Command{
		Use:   "run",
		Short: "process queued async GC jobs",
		RunE: func(cmd *cobra.Command, args []string) error {
			service, cleanup, err := evidenceSvc(*dataDir)
			if err != nil {
				return err
			}
			defer cleanup()
			result, err := service.RunGC(limit)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "processed=%d failed=%d reclaimed_bytes=%d reclaimed_inodes=%d\n", result.Processed, result.Failed, result.ReclaimedBytes, result.ReclaimedInodes)
			return nil
		},
	}
	run.Flags().IntVar(&limit, "limit", 100, "maximum GC jobs to process")
	status := &cobra.Command{
		Use:   "status",
		Short: "show async GC queue status",
		RunE: func(cmd *cobra.Command, args []string) error {
			paths, err := store.Init(*dataDir)
			if err != nil {
				return err
			}
			db, err := store.Open(paths)
			if err != nil {
				return err
			}
			defer db.Close()
			rows, err := db.Query(`SELECT status, COUNT(*), COALESCE(SUM(reclaimed_bytes), 0), COALESCE(SUM(reclaimed_inodes), 0), COALESCE(SUM(gc_latency_ms), 0)
				FROM gc_jobs GROUP BY status ORDER BY status`)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var status string
				var count, bytes, inodes, latency int64
				if err := rows.Scan(&status, &count, &bytes, &inodes, &latency); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "status=%s count=%d reclaimed_bytes=%d reclaimed_inodes=%d gc_latency_ms=%d\n", status, count, bytes, inodes, latency)
			}
			return rows.Err()
		},
	}
	cmd := &cobra.Command{Use: "gc", Short: "async workspace GC commands"}
	cmd.AddCommand(run)
	cmd.AddCommand(status)
	return cmd
}

func evidenceSvc(dataDir string) (evidence.Service, func(), error) {
	paths, err := store.Init(dataDir)
	if err != nil {
		return evidence.Service{}, nil, err
	}
	db, err := store.Open(paths)
	if err != nil {
		return evidence.Service{}, nil, err
	}
	return evidence.Service{DB: db, Paths: paths}, func() { db.Close() }, nil
}
