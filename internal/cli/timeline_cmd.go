package cli

import (
	"encoding/json"
	"fmt"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/spf13/cobra"
)

func timelineCmd(dataDir, daemonURL *string) *cobra.Command {
	var runID string
	var toolCallID string
	var processID string
	var eventType string
	var view string
	var limit int
	var cursor string
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "timeline",
		Short: "show an execution timeline across agent context, telemetry, risk, and response evidence",
		RunE: func(cmd *cobra.Command, args []string) error {
			if runID == "" {
				return fmt.Errorf("--run is required")
			}
			opts := provenance.TimelineOptions{
				RunID:     runID,
				ToolCall:  toolCallID,
				ProcessID: processID,
				Type:      eventType,
				Limit:     limit,
				Cursor:    cursor,
				View:      view,
			}
			manifest, err := timelineManifest(*dataDir, *daemonURL, opts)
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(manifest)
			}
			return provenance.PrintTimelineManifest(manifest, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&runID, "run", "", "run id")
	cmd.Flags().StringVar(&toolCallID, "tool-call", "", "filter by tool call id")
	cmd.Flags().StringVar(&processID, "process", "", "filter by process id")
	cmd.Flags().StringVar(&eventType, "type", "", "filter by normalized timeline event type")
	cmd.Flags().StringVar(&view, "view", "table", "timeline view: table or causality")
	cmd.Flags().IntVar(&limit, "limit", 0, "maximum timeline events returned")
	cmd.Flags().StringVar(&cursor, "cursor", "", "pagination cursor from previous timeline output")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit structured timeline JSON")
	return cmd
}

func timelineManifest(dataDir, daemonURL string, opts provenance.TimelineOptions) (provenance.TimelineManifest, error) {
	if client, ok := daemonClient(daemonURL); ok {
		return client.Timeline(opts)
	}
	db, cleanup, err := openLocalDB(dataDir)
	if err != nil {
		return provenance.TimelineManifest{}, err
	}
	defer cleanup()
	return provenance.BuildTimeline(db, opts)
}
