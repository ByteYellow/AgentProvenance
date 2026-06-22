package cli

import (
	"fmt"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/baseline"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/spf13/cobra"
)

func baselineCmd(dataDir *string) *cobra.Command {
	var templateName, runID string
	learn := &cobra.Command{
		Use:   "learn",
		Short: "learn a per-template behavior baseline from a run",
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
			profile, err := baseline.Learn(db, templateName, runID)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "baseline_id=%s template=%s exec_count=%d process_observed_count=%d outlived_root_count=%d file_write_count=%d secret_path_count=%d network_event_count=%d metadata_ip_count=%d private_cidr_count=%d policy_block_count=%d suspicious_runtime_count=%d active_cpu_seconds=%.3f status=%s\n",
				profile.ID, profile.TemplateName, profile.Features.ExecCount, profile.Features.ProcessObservedCount, profile.Features.OutlivedRootCount,
				profile.Features.FileWriteCount, profile.Features.SecretPathCount, profile.Features.NetworkEventCount, profile.Features.MetadataIPCount,
				profile.Features.PrivateCIDRCount, profile.Features.PolicyBlockCount, profile.Features.SuspiciousRuntimeCount, profile.Features.ActiveCPUSeconds, profile.Status)
			return nil
		},
	}
	learn.Flags().StringVar(&templateName, "template", "", "template name")
	learn.Flags().StringVar(&runID, "run", "", "run id")
	_ = learn.MarkFlagRequired("template")
	_ = learn.MarkFlagRequired("run")

	check := &cobra.Command{
		Use:   "check",
		Short: "check a run against the latest template baseline",
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
			status, deviations, err := baseline.Check(db, templateName, runID)
			if err != nil {
				return err
			}
			recommendation := "allow"
			if status == "anomalous" {
				recommendation = "audit"
				records, listErr := baseline.ListDeviations(db, runID)
				if listErr == nil {
					for _, record := range records {
						if record.RecommendedAction == "review" {
							recommendation = "review"
							break
						}
					}
				}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "status=%s deviations=%s recommendation=%s\n", status, strings.Join(deviations, ","), recommendation)
			return nil
		},
	}
	check.Flags().StringVar(&templateName, "template", "", "template name")
	check.Flags().StringVar(&runID, "run", "", "run id")
	_ = check.MarkFlagRequired("template")
	_ = check.MarkFlagRequired("run")

	cmd := &cobra.Command{Use: "baseline", Short: "behavior baseline commands"}
	cmd.AddCommand(learn)
	cmd.AddCommand(check)
	return cmd
}
