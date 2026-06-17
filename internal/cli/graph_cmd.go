package cli

import (
	"database/sql"
	"fmt"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/spf13/cobra"
)

func graphCmd(dataDir *string) *cobra.Command {
	var runID string
	var artifactRef string
	var attemptID string
	var toolCallID string
	var processID string
	openDB := func() (*sql.DB, error) {
		paths, err := store.Init(*dataDir)
		if err != nil {
			return nil, err
		}
		db, err := store.Open(paths)
		if err != nil {
			return nil, err
		}
		return db, nil
	}
	trace := &cobra.Command{
		Use:   "trace",
		Short: "trace run or artifact provenance",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := openDB()
			if err != nil {
				return err
			}
			defer db.Close()
			selected := 0
			for _, value := range []string{runID, artifactRef, attemptID, toolCallID, processID} {
				if value != "" {
					selected++
				}
			}
			if selected > 1 {
				return fmt.Errorf("use only one of --run, --artifact, --attempt, --tool-call, or --process")
			}
			if processID != "" {
				return provenance.TraceProcess(db, processID, cmd.OutOrStdout())
			}
			if toolCallID != "" {
				return provenance.TraceToolCall(db, toolCallID, cmd.OutOrStdout())
			}
			if attemptID != "" {
				return provenance.TraceAttempt(db, attemptID, cmd.OutOrStdout())
			}
			if artifactRef != "" {
				return provenance.TraceArtifact(db, artifactRef, cmd.OutOrStdout())
			}
			if runID != "" {
				return provenance.TraceRun(db, runID, cmd.OutOrStdout())
			}
			return fmt.Errorf("one of --run, --artifact, --attempt, --tool-call, or --process is required")
		},
	}
	trace.Flags().StringVar(&runID, "run", "", "run id")
	trace.Flags().StringVar(&artifactRef, "artifact", "", "artifact result ref")
	trace.Flags().StringVar(&attemptID, "attempt", "", "attempt id")
	trace.Flags().StringVar(&toolCallID, "tool-call", "", "tool call id")
	trace.Flags().StringVar(&processID, "process", "", "process id")

	var refsRunID string
	refs := &cobra.Command{
		Use:   "refs",
		Short: "list Git-like provenance refs for a run",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := openDB()
			if err != nil {
				return err
			}
			defer db.Close()
			if refsRunID == "" {
				return fmt.Errorf("--run is required")
			}
			return provenance.Refs(db, refsRunID, cmd.OutOrStdout())
		},
	}
	refs.Flags().StringVar(&refsRunID, "run", "", "run id")

	var logRunID string
	logCmd := &cobra.Command{
		Use:   "log",
		Short: "show Git-like provenance timeline for a run",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := openDB()
			if err != nil {
				return err
			}
			defer db.Close()
			if logRunID == "" {
				return fmt.Errorf("--run is required")
			}
			return provenance.Log(db, logRunID, cmd.OutOrStdout())
		},
	}
	logCmd.Flags().StringVar(&logRunID, "run", "", "run id")

	cmd := &cobra.Command{Use: "graph", Short: "provenance graph commands"}
	cmd.AddCommand(trace)
	cmd.AddCommand(refs)
	cmd.AddCommand(logCmd)
	return cmd
}
