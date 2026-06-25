package cli

import (
	"encoding/json"
	"fmt"
	"text/tabwriter"

	"github.com/byteyellow/agentprovenance/internal/signal"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/spf13/cobra"
)

func signalCmd(dataDir *string) *cobra.Command {
	var runID string
	var jsonOut bool
	run := &cobra.Command{
		Use:   "run",
		Short: "run code-based evaluators over provenance evidence",
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
			report, err := signal.BuildRunReport(db, runID)
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintf(w, "run=%s schema=%s engine=%s decision_owner=%s signals=%d result_set=%s page_hash=%s\n",
				report.RunID, report.SchemaVersion, report.Engine, report.DecisionOwner, report.SignalCount, report.ResultSetID, report.PageHash)
			fmt.Fprintln(w, "ID\tKIND\tNAME\tATTEMPT\tTOOL_CALL\tSCORE\tLABEL\tREASON")
			for _, item := range report.Signals {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%.3f\t%s\t%s\n",
					item.ID, item.Kind, item.Name, item.AttemptID, item.ToolCallID, item.Score, item.Label, item.Reason)
			}
			return w.Flush()
		},
	}
	run.Flags().StringVar(&runID, "run", "", "run id")
	run.Flags().BoolVar(&jsonOut, "json", false, "emit structured evaluator signal JSON")
	_ = run.MarkFlagRequired("run")

	cmd := &cobra.Command{Use: "signal", Short: "code-based evaluator signal commands"}
	cmd.AddCommand(run)
	return cmd
}
