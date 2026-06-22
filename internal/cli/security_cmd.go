package cli

import (
	"database/sql"
	"fmt"
	"text/tabwriter"

	"github.com/byteyellow/agentprovenance/internal/baseline"
	securitymodel "github.com/byteyellow/agentprovenance/internal/security"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/spf13/cobra"
)

func securityCmd(dataDir *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "security",
		Short: "security evidence, deviation, and response commands",
	}
	cmd.AddCommand(securityRisksCmd(dataDir))
	cmd.AddCommand(securityDeviationsCmd(dataDir))
	cmd.AddCommand(securityResponsesCmd(dataDir))
	return cmd
}

func securityRisksCmd(dataDir *string) *cobra.Command {
	var runID string
	cmd := &cobra.Command{
		Use:   "risks",
		Short: "list normalized risk signals",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, cleanup, err := openLocalDB(*dataDir)
			if err != nil {
				return err
			}
			defer cleanup()
			records, err := securitymodel.ListRiskSignals(db, runID)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tRUN\tSESSION\tTOOL_CALL\tPROCESS\tTYPE\tSEVERITY\tACTION\tREASON\tCREATED_AT")
			for _, record := range records {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					record.ID, record.RunID, record.SessionID, record.ToolCallID, record.ProcessID,
					record.SignalType, record.Severity, record.RecommendedAction, record.Reason, record.CreatedAt)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&runID, "run", "", "filter by run id")
	return cmd
}

func securityDeviationsCmd(dataDir *string) *cobra.Command {
	var runID string
	cmd := &cobra.Command{
		Use:   "deviations",
		Short: "list baseline deviation signals",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, cleanup, err := openLocalDB(*dataDir)
			if err != nil {
				return err
			}
			defer cleanup()
			records, err := baseline.ListDeviations(db, runID)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tRUN\tTEMPLATE\tTYPE\tSTATUS\tEXPECTED\tOBSERVED\tACTION\tCREATED_AT")
			for _, record := range records {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%.3f\t%.3f\t%s\t%s\n",
					record.ID, record.RunID, record.TemplateName, record.DeviationType, record.Status,
					record.ExpectedValue, record.ObservedValue, record.RecommendedAction, record.CreatedAt)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&runID, "run", "", "filter by run id")
	return cmd
}

func securityResponsesCmd(dataDir *string) *cobra.Command {
	var runID string
	cmd := &cobra.Command{
		Use:   "responses",
		Short: "list recorded response actions",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, cleanup, err := openLocalDB(*dataDir)
			if err != nil {
				return err
			}
			defer cleanup()
			records, err := securitymodel.ListResponseActions(db, runID)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tRUN\tACTION\tTARGET_TYPE\tTARGET_ID\tSTATUS\tRISK\tDECISION\tCREATED_AT")
			for _, record := range records {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					record.ID, record.RunID, record.ActionType, record.TargetType, record.TargetID,
					record.Status, record.RiskSignalID, record.PolicyDecisionID, record.CreatedAt)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&runID, "run", "", "filter by run id")
	return cmd
}

func openLocalDB(dataDir string) (*sql.DB, func(), error) {
	paths, err := store.Init(dataDir)
	if err != nil {
		return nil, nil, err
	}
	db, err := store.Open(paths)
	if err != nil {
		return nil, nil, err
	}
	return db, func() { db.Close() }, nil
}
