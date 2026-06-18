package cli

import (
	"fmt"

	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/spf13/cobra"
)

func recordCmd(dataDir *string) *cobra.Command {
	var runID string
	var name string
	var workdir string
	cmd := &cobra.Command{
		Use:   "record -- <command...>",
		Short: "record a command as a zero-SDK agent execution",
		Args:  cobra.MinimumNArgs(1),
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
			result, err := (record.Service{DB: db, Paths: paths}).Run(record.Request{
				RunID:   runID,
				Name:    name,
				Workdir: workdir,
				Command: args,
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "run_id=%s rollout_id=%s base_snapshot=%s attempt=%s session=%s tool_call=%s process=%s status=%s exit=%d wall_ms=%d changed_files=%d workdir=%s\n",
				result.RunID, result.RolloutID, result.BaseSnapshotID, result.AttemptID, result.SessionID, result.ToolCallID, result.ProcessID, result.Status, result.ExitCode, result.WallMS, len(result.ChangedFiles), result.Workdir)
			for _, file := range result.ChangedFiles {
				fmt.Fprintf(cmd.OutOrStdout(), "changed_file=%s\n", file)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&runID, "run", "", "run id")
	cmd.Flags().StringVar(&name, "name", "record", "recording name")
	cmd.Flags().StringVar(&workdir, "workdir", "", "working directory; defaults to current directory")
	return cmd
}
