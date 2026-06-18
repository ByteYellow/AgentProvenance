package cli

import (
	"fmt"
	"github.com/byteyellow/agentprovenance/internal/attempt"
	"github.com/byteyellow/agentprovenance/internal/state"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/spf13/cobra"
	"text/tabwriter"
)

func attemptCmd(dataDir *string) *cobra.Command {
	var snapshot string
	var strategies []string
	var maxFanout int
	var maxCost float64
	var earlyStop bool
	var topK int
	bestOf := &cobra.Command{
		Use:   "best-of",
		Short: "fork attempts from one snapshot and record local candidate evidence",
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
			service := attempt.Service{DB: db, State: state.Service{DB: db, Paths: paths}}
			results, winner, err := service.BestOfWithOptions(snapshot, strategies, attempt.Options{MaxFanout: maxFanout, MaxCost: maxCost, EarlyStop: earlyStop, TopK: topK})
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ATTEMPT\tSTRATEGY\tSTATUS\tEXIT\tWALL_MS\tBUDGET\tSCORE\tCOST\tSAVED\tWINNER\tARTIFACT\tOUTPUT")
			for _, result := range results {
				winnerMark := ""
				if result.IsWinner {
					winnerMark = "yes"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%d\t%.3f\t%.6f\t%.6f\t%s\t%s\t%s\n", result.AttemptID, result.Strategy, result.Status, result.ExitCode, result.WallMS, result.BudgetSeconds, result.Score, result.CostEstimate, result.SavedCost, winnerMark, result.ArtifactResult, result.OutputSummary)
			}
			if err := w.Flush(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "candidate=%s winner=%s strategy=%s workspace=%s score=%.3f cost=%.6f artifact=%s\n", winner.AttemptID, winner.AttemptID, winner.Strategy, winner.WorkspacePath, winner.Score, winner.CostEstimate, winner.ArtifactResult)
			return nil
		},
	}
	bestOf.Flags().StringVar(&snapshot, "snapshot", "", "snapshot name or id")
	bestOf.Flags().StringArrayVar(&strategies, "strategy", nil, "strategy in name::command form; repeat for multiple attempts")
	bestOf.Flags().IntVar(&maxFanout, "max-fanout", 0, "maximum number of strategies to execute")
	bestOf.Flags().Float64Var(&maxCost, "max-cost", 0, "maximum fanout cost budget before stopping")
	bestOf.Flags().BoolVar(&earlyStop, "early-stop", false, "stop when a high-scoring passing attempt is found")
	bestOf.Flags().IntVar(&topK, "top-k", 0, "after probe commands, run full commands only for the top K strategies")
	_ = bestOf.MarkFlagRequired("snapshot")
	_ = bestOf.MarkFlagRequired("strategy")
	cmd := &cobra.Command{Use: "attempt", Short: "attempt execution and selection commands"}
	cmd.AddCommand(bestOf)
	return cmd
}
