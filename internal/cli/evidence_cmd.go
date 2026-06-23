package cli

import (
	"encoding/json"
	"fmt"
	"text/tabwriter"

	"github.com/byteyellow/agentprovenance/internal/evidence"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/spf13/cobra"
)

func evidenceCmd(dataDir *string) *cobra.Command {
	var limit int
	var runID string
	var objectLimit int
	var jsonOut bool
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
			paths, err := store.Init(*dataDir)
			if err != nil {
				return err
			}
			db, err := store.Open(paths)
			if err != nil {
				return err
			}
			defer db.Close()
			report, err := evidence.BuildManifest(db, evidence.ManifestOptions{RunID: runID, ObjectLimit: objectLimit})
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "run=%s schema=%s result_set=%s page_hash=%s\n", report.RunID, report.SchemaVersion, report.ResultSetID, report.PageHash)
			fmt.Fprintf(cmd.OutOrStdout(), "summary events=%d runtime_events=%d risks=%d responses=%d tool_call_coverage=%.2f process_coverage=%.2f\n",
				report.Summary.EventCount, report.Summary.Runtime.Events, report.Security.RiskCount, report.Security.ResponseCount,
				report.Summary.Runtime.ToolCallCoverageRatio, report.Summary.Runtime.ProcessCoverageRatio)
			fmt.Fprintf(cmd.OutOrStdout(), "timeline events=%d result_set=%s page_hash=%s\n", report.Timeline.EventCount, report.Timeline.ResultSetID, report.Timeline.PageHash)
			fmt.Fprintf(cmd.OutOrStdout(), "objects count=%d bytes=%d result_set=%s page_hash=%s has_more=%t\n",
				report.Objects.ObjectCount, report.Objects.TotalBytes, report.Objects.ResultSetID, report.Objects.PageHash, report.Objects.HasMore)
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "OBJECT_TYPE\tCOUNT")
			for typ, count := range report.Objects.ByType {
				fmt.Fprintf(w, "%s\t%d\n", typ, count)
			}
			if err := w.Flush(); err != nil {
				return err
			}
			if len(report.RecommendedViews) > 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "next_views:")
				for _, view := range report.RecommendedViews {
					fmt.Fprintf(cmd.OutOrStdout(), "  agentprov %s\n", view)
				}
			}
			return nil
		},
	}
	manifest.Flags().StringVar(&runID, "run", "", "run id")
	manifest.Flags().IntVar(&objectLimit, "object-limit", 25, "maximum object refs to include")
	manifest.Flags().BoolVar(&jsonOut, "json", false, "emit JSON evidence manifest")
	cmd := &cobra.Command{Use: "evidence", Short: "evidence processing and manifest commands"}
	cmd.AddCommand(process)
	cmd.AddCommand(manifest)
	return cmd
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
