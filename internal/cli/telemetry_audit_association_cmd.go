package cli

import (
	"encoding/json"
	"fmt"
	"text/tabwriter"

	"github.com/byteyellow/agentprovenance/internal/daemon"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
	"github.com/spf13/cobra"
)

func telemetryAuditAssociationsCmd(dataDir, daemonURL *string) *cobra.Command {
	var opts telemetry.AuditAssociationOptions
	var jsonOut bool
	cmd := &cobra.Command{
		Use: "audit-associations", Args: cobra.NoArgs,
		Short: "inspect audit process and operation candidates without changing original evidence",
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.Limit < 1 || opts.Limit > 500 {
				return fmt.Errorf("audit association limit must be between 1 and 500")
			}
			var report telemetry.AuditAssociationReport
			var err error
			if *daemonURL != "" {
				report, err = daemon.NewClient(*daemonURL).TelemetryAuditAssociations(cmd.Context(), opts)
			} else {
				paths, initErr := store.Init(*dataDir)
				if initErr != nil {
					return initErr
				}
				db, openErr := store.Open(paths)
				if openErr != nil {
					return openErr
				}
				defer db.Close()
				report, err = telemetry.BuildAuditAssociations(cmd.Context(), db, opts)
			}
			if err != nil {
				return err
			}
			if jsonOut {
				encoder := json.NewEncoder(cmd.OutOrStdout())
				encoder.SetIndent("", "  ")
				return encoder.Encode(report)
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, commandText(cmd, "EVENT\tMECHANISM\tDECISION\tPROCESS\tOPERATION\tCANDIDATES\tREASON"))
			for _, item := range report.Items {
				reason := item.Operation.Reason
				if item.Process.Reason != "" {
					reason = item.Process.Reason
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%s\n", item.EventID, item.Mechanism, item.Decision,
					item.Process.Status, item.Operation.Status, item.Operation.CandidateCount, reason)
			}
			for _, issue := range report.Issues {
				fmt.Fprintln(cmd.ErrOrStderr(), issue)
			}
			if report.NextCursor != "" {
				fmt.Fprintf(w, commandText(cmd, "next_cursor=%s\n"), report.NextCursor)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&opts.RunID, "run", "", "run containing these records; does not assign an Agent session")
	cmd.Flags().StringVar(&opts.EventID, "event", "", "inspect one saved audit event")
	cmd.Flags().IntVar(&opts.Limit, "limit", 100, "maximum audit decisions to analyze per page (1-500)")
	cmd.Flags().StringVar(&opts.Cursor, "cursor", "", "pagination cursor from previous audit association output")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit versioned audit association candidates and evidence references")
	_ = cmd.MarkFlagRequired("run")
	return cmd
}
