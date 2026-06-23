package cli

import (
	"encoding/json"
	"fmt"
	"text/tabwriter"

	"github.com/byteyellow/agentprovenance/internal/observability"
	"github.com/spf13/cobra"
)

func observeCmd(dataDir *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "observe",
		Short: "summarize execution observability for agent runs",
	}
	cmd.AddCommand(observeSummaryCmd(dataDir))
	return cmd
}

func observeSummaryCmd(dataDir *string) *cobra.Command {
	var runID string
	var topN int
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "summary",
		Short: "show run-level observability coverage, risk, and evidence summary",
		RunE: func(cmd *cobra.Command, args []string) error {
			if runID == "" {
				return fmt.Errorf("--run is required")
			}
			db, cleanup, err := openLocalDB(*dataDir)
			if err != nil {
				return err
			}
			defer cleanup()
			summary, err := observability.BuildSummary(db, observability.SummaryOptions{RunID: runID, TopN: topN})
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(summary)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "run=%s schema=%s events=%d\n", summary.RunID, summary.SchemaVersion, summary.EventCount)
			fmt.Fprintf(cmd.OutOrStdout(), "application sessions=%d attempts=%d tool_calls=%d processes=%d snapshots=%d\n",
				summary.Application.Sessions, summary.Application.Attempts, summary.Application.ToolCalls, summary.Application.Processes, summary.Application.Snapshots)
			fmt.Fprintf(cmd.OutOrStdout(), "runtime events=%d with_session=%d with_tool_call=%d with_process=%d tool_call_coverage=%.2f process_coverage=%.2f\n",
				summary.Runtime.Events, summary.Runtime.EventsWithSession, summary.Runtime.EventsWithToolCall, summary.Runtime.EventsWithProcess,
				summary.Runtime.ToolCallCoverageRatio, summary.Runtime.ProcessCoverageRatio)
			fmt.Fprintf(cmd.OutOrStdout(), "risk signals=%d policy_decisions=%d baseline_deviations=%d response_actions=%d\n",
				summary.Risk.Signals, summary.Risk.PolicyDecisions, summary.Baseline.Deviations, summary.Response.Actions)
			printCounts(cmd, "EVENT_TYPE", summary.EventTypes)
			printCounts(cmd, "SOURCE", summary.Sources)
			if len(summary.TopEvidenceRefs) > 0 {
				w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "REF\tTYPE\tSOURCE\tSUMMARY")
				for _, ref := range summary.TopEvidenceRefs {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", ref.Ref, ref.Type, ref.Source, ref.Summary)
				}
				if err := w.Flush(); err != nil {
					return err
				}
			}
			if len(summary.RecommendedViews) > 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "next_views:")
				for _, view := range summary.RecommendedViews {
					fmt.Fprintf(cmd.OutOrStdout(), "  agentprov %s\n", view)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&runID, "run", "", "run id")
	cmd.Flags().IntVar(&topN, "top", 8, "maximum evidence refs to show")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	return cmd
}

func printCounts(cmd *cobra.Command, title string, counts map[string]int) {
	if len(counts) == 0 {
		return
	}
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "%s\tCOUNT\n", title)
	for _, item := range sortedCountItems(counts) {
		fmt.Fprintf(w, "%s\t%d\n", item.Name, item.Count)
	}
	_ = w.Flush()
}

type countItem struct {
	Name  string
	Count int
}

func sortedCountItems(counts map[string]int) []countItem {
	items := make([]countItem, 0, len(counts))
	for name, count := range counts {
		items = append(items, countItem{Name: name, Count: count})
	}
	for i := 0; i < len(items); i++ {
		for j := i + 1; j < len(items); j++ {
			if items[j].Count > items[i].Count || (items[j].Count == items[i].Count && items[j].Name < items[i].Name) {
				items[i], items[j] = items[j], items[i]
			}
		}
	}
	return items
}
