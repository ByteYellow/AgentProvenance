package cli

import (
	"fmt"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/spf13/cobra"
)

func timelineCmd(dataDir *string) *cobra.Command {
	var runID string
	var toolCallID string
	var processID string
	var eventType string
	var view string
	var limit int
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "timeline",
		Short: "show an execution timeline across agent context, telemetry, risk, and response evidence",
		RunE: func(cmd *cobra.Command, args []string) error {
			if runID == "" {
				return fmt.Errorf("--run is required")
			}
			db, cleanup, err := openLocalDB(*dataDir)
			if err != nil {
				return err
			}
			defer cleanup()
			opts := provenance.TimelineOptions{
				RunID:     runID,
				ToolCall:  toolCallID,
				ProcessID: processID,
				Type:      eventType,
				Limit:     limit,
				View:      view,
			}
			if asJSON {
				return provenance.PrintTimelineJSON(db, opts, cmd.OutOrStdout())
			}
			return provenance.PrintTimeline(db, opts, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&runID, "run", "", "run id")
	cmd.Flags().StringVar(&toolCallID, "tool-call", "", "filter by tool call id")
	cmd.Flags().StringVar(&processID, "process", "", "filter by process id")
	cmd.Flags().StringVar(&eventType, "type", "", "filter by normalized timeline event type")
	cmd.Flags().StringVar(&view, "view", "table", "timeline view: table or causality")
	cmd.Flags().IntVar(&limit, "limit", 0, "maximum timeline events returned")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit structured timeline JSON")
	return cmd
}
