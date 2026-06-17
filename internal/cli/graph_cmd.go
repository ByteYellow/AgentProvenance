package cli

import (
	"fmt"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/spf13/cobra"
)

func graphCmd(dataDir *string) *cobra.Command {
	var runID string
	var artifactRef string
	trace := &cobra.Command{
		Use:   "trace",
		Short: "trace run or artifact provenance",
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
			if runID != "" && artifactRef != "" {
				return fmt.Errorf("use only one of --run or --artifact")
			}
			if artifactRef != "" {
				return provenance.TraceArtifact(db, artifactRef, cmd.OutOrStdout())
			}
			if runID != "" {
				return provenance.TraceRun(db, runID, cmd.OutOrStdout())
			}
			return fmt.Errorf("one of --run or --artifact is required")
		},
	}
	trace.Flags().StringVar(&runID, "run", "", "run id")
	trace.Flags().StringVar(&artifactRef, "artifact", "", "artifact result ref")
	cmd := &cobra.Command{Use: "graph", Short: "provenance graph commands"}
	cmd.AddCommand(trace)
	return cmd
}
