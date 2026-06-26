package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/spf13/cobra"
)

func forensicsCmd(dataDir, daemonURL *string) *cobra.Command {
	var jsonOut bool
	var batchID string
	var runID string
	var jobID string
	var shardID string
	var latest bool
	var limit int
	var includeRunBundles bool
	var includeEvalContexts bool
	export := &cobra.Command{
		Use:   "export <run_id>",
		Short: "export a forensics bundle for a run",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			bundle, err := exportForensics(*dataDir, *daemonURL, args[0])
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(bundle)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "bundle_id=%s path=%s sha256=%s size_bytes=%d\n", bundle.ID, bundle.Path, bundle.SHA256, bundle.SizeBytes)
			return nil
		},
	}
	export.Flags().BoolVar(&jsonOut, "json", false, "emit structured forensics export JSON")
	exportBatch := &cobra.Command{
		Use:   "export-batch",
		Short: "export a batch-level forensics audit bundle",
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := forensics.BatchExportOptions{
				BatchID:             batchID,
				RunID:               runID,
				JobID:               jobID,
				ShardID:             shardID,
				Latest:              latest,
				Limit:               limit,
				IncludeRunBundles:   includeRunBundles,
				IncludeEvalContexts: includeEvalContexts,
			}
			bundle, err := exportBatchForensics(*dataDir, *daemonURL, opts)
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(bundle)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "bundle_id=%s batch=%s runs=%d items=%d path=%s sha256=%s size_bytes=%d\n",
				bundle.ID, bundle.BatchID, bundle.RunCount, bundle.ItemCount, bundle.Path, bundle.SHA256, bundle.SizeBytes)
			if len(bundle.RunBundles) > 0 {
				refs := make([]string, 0, len(bundle.RunBundles))
				for _, runBundle := range bundle.RunBundles {
					refs = append(refs, runBundle.RunID+"="+runBundle.SHA256)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "run_bundles=%s\n", strings.Join(refs, ","))
			}
			return nil
		},
	}
	exportBatch.Flags().StringVar(&batchID, "batch", "", "record batch id")
	exportBatch.Flags().StringVar(&runID, "run", "", "run id")
	exportBatch.Flags().StringVar(&jobID, "job", "", "job id")
	exportBatch.Flags().StringVar(&shardID, "shard", "", "shard id")
	exportBatch.Flags().BoolVar(&latest, "latest", false, "export only the latest batch matching filters")
	exportBatch.Flags().IntVar(&limit, "limit", 100, "maximum batch items to include")
	exportBatch.Flags().BoolVar(&includeRunBundles, "include-run-bundles", true, "export and reference per-run forensics bundles")
	exportBatch.Flags().BoolVar(&includeEvalContexts, "include-eval-contexts", false, "embed EvalContext records in the batch bundle")
	exportBatch.Flags().BoolVar(&jsonOut, "json", false, "emit structured batch forensics export JSON")
	cmd := &cobra.Command{Use: "forensics", Short: "forensics bundle commands"}
	cmd.AddCommand(export)
	cmd.AddCommand(exportBatch)
	return cmd
}

func exportForensics(dataDir, daemonURL, runID string) (forensics.BundleInfo, error) {
	if client, ok := daemonClient(daemonURL); ok {
		return client.ExportForensics(runID)
	}
	paths, err := store.Init(dataDir)
	if err != nil {
		return forensics.BundleInfo{}, err
	}
	db, err := store.Open(paths)
	if err != nil {
		return forensics.BundleInfo{}, err
	}
	defer db.Close()
	return (forensics.Service{DB: db, Paths: paths}).ExportBundle(runID)
}

func exportBatchForensics(dataDir, daemonURL string, opts forensics.BatchExportOptions) (forensics.BatchBundleInfo, error) {
	if client, ok := daemonClient(daemonURL); ok {
		return client.ExportBatchForensics(opts)
	}
	paths, err := store.Init(dataDir)
	if err != nil {
		return forensics.BatchBundleInfo{}, err
	}
	db, err := store.Open(paths)
	if err != nil {
		return forensics.BatchBundleInfo{}, err
	}
	defer db.Close()
	return (forensics.Service{DB: db, Paths: paths}).ExportBatch(opts)
}
