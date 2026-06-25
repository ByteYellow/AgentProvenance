package cli

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/byteyellow/agentprovenance/internal/signal"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/spf13/cobra"
)

func signalCmd(dataDir *string) *cobra.Command {
	var runID string
	var jsonOut bool
	var external string
	run := &cobra.Command{
		Use:   "run",
		Short: "run built-in or external evaluators over provenance evidence",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, closeFn, err := signalDB(*dataDir)
			if err != nil {
				return err
			}
			defer closeFn()
			ctx, err := signal.BuildEvalContext(db, runID)
			if err != nil {
				return err
			}
			var report signal.EvalReport
			if external != "" {
				report, err = signal.RunExternal(external, ctx)
			} else {
				report, err = signal.BuildBuiltinReportFromContext(ctx)
			}
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}
			return printSignalReport(cmd.OutOrStdout(), report)
		},
	}
	run.Flags().StringVar(&runID, "run", "", "run id")
	run.Flags().StringVar(&external, "external", "", "external evaluator command; EvalContext JSON is passed on stdin")
	run.Flags().BoolVar(&jsonOut, "json", false, "emit structured evaluator signal JSON")
	_ = run.MarkFlagRequired("run")

	var contextRunID string
	contextCmd := &cobra.Command{
		Use:   "context",
		Short: "export EvalContext JSON for external evaluators",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, closeFn, err := signalDB(*dataDir)
			if err != nil {
				return err
			}
			defer closeFn()
			ctx, err := signal.BuildEvalContext(db, contextRunID)
			if err != nil {
				return err
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(ctx)
		},
	}
	contextCmd.Flags().StringVar(&contextRunID, "run", "", "run id")
	_ = contextCmd.MarkFlagRequired("run")

	var importRunID string
	var importFile string
	var importJSON bool
	importCmd := &cobra.Command{
		Use:   "import",
		Short: "validate external evaluator signals",
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := os.ReadFile(importFile)
			if err != nil {
				return err
			}
			var output signal.ExternalEvalOutput
			if err := json.Unmarshal(raw, &output); err != nil {
				var signals []signal.EvalSignal
				if err2 := json.Unmarshal(raw, &signals); err2 != nil {
					return fmt.Errorf("signal import file must be {signals:[...]} or raw EvalSignal array: %w", err)
				}
				output.Signals = signals
			}
			report, err := signal.ImportSignals(importRunID, "imported-external-evaluator", output.Signals)
			if err != nil {
				return err
			}
			if importJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}
			return printSignalReport(cmd.OutOrStdout(), report)
		},
	}
	importCmd.Flags().StringVar(&importRunID, "run", "", "run id")
	importCmd.Flags().StringVar(&importFile, "file", "", "external signal JSON file")
	importCmd.Flags().BoolVar(&importJSON, "json", false, "emit structured evaluator signal JSON")
	_ = importCmd.MarkFlagRequired("run")
	_ = importCmd.MarkFlagRequired("file")

	cmd := &cobra.Command{Use: "signal", Short: "code-based evaluator signal commands"}
	cmd.AddCommand(run)
	cmd.AddCommand(contextCmd)
	cmd.AddCommand(importCmd)
	return cmd
}

func signalDB(dataDir string) (*sql.DB, func(), error) {
	paths, err := store.Init(dataDir)
	if err != nil {
		return nil, nil, err
	}
	db, err := store.Open(paths)
	if err != nil {
		return nil, nil, err
	}
	return db, func() { _ = db.Close() }, nil
}

func printSignalReport(out io.Writer, report signal.EvalReport) error {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "run=%s schema=%s engine=%s decision_owner=%s signals=%d result_set=%s page_hash=%s\n",
		report.RunID, report.SchemaVersion, report.Engine, report.DecisionOwner, report.SignalCount, report.ResultSetID, report.PageHash)
	fmt.Fprintln(w, "ID\tKIND\tNAME\tATTEMPT\tTOOL_CALL\tSCORE\tLABEL\tREASON")
	for _, item := range report.Signals {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%.3f\t%s\t%s\n",
			item.ID, item.Kind, item.Name, item.AttemptID, item.ToolCallID, item.Score, item.Label, item.Reason)
	}
	return w.Flush()
}
