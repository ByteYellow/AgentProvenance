package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/byteyellow/agentprovenance/internal/signals"
	"github.com/spf13/cobra"
)

// signalsCmd exposes the unified, graph-attached signal model (the
// agentprovenance.signals/v1 contract): one queryable surface across the
// behavior / cost / quality / security dimensions. Distinct from `signal`
// (singular), which is the external evaluator (EvalSignal) protocol.
func signalsCmd(dataDir *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "signals",
		Short: "query the unified signal model (behavior/cost/quality/security)",
	}
	cmd.AddCommand(signalsListCmd(dataDir))
	cmd.AddCommand(signalsBackfillCmd(dataDir))
	cmd.AddCommand(signalsValidateCmd())
	return cmd
}

func signalsValidateCmd() *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "validate a SignalSet JSON file against the agentprovenance.signals/v1 contract",
		RunE: func(cmd *cobra.Command, args []string) error {
			if file == "" {
				return fmt.Errorf("--file is required (use - for stdin)")
			}
			var data []byte
			var err error
			if file == "-" {
				data, err = io.ReadAll(cmd.InOrStdin())
			} else {
				data, err = os.ReadFile(file)
			}
			if err != nil {
				return err
			}
			set, err := signals.ValidateWireBytes(data)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "ok schema=%s run=%s count=%d\n", set.SchemaVersion, set.RunID, set.Count)
			return nil
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "SignalSet JSON file; use - for stdin")
	return cmd
}

func signalsListCmd(dataDir *string) *cobra.Command {
	var runID, dimension string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "list unified signals for a run (optionally filtered by dimension)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if runID == "" {
				return fmt.Errorf("--run is required")
			}
			if dimension != "" && !signals.Dimension(dimension).Valid() {
				return fmt.Errorf("invalid --dimension %q (want behavior|cost|quality|security)", dimension)
			}
			db, cleanup, err := openLocalDB(*dataDir)
			if err != nil {
				return err
			}
			defer cleanup()

			if dimension != "" {
				rows, err := signals.Query(db, signals.Filter{RunID: runID, Dimension: signals.Dimension(dimension)})
				if err != nil {
					return err
				}
				if jsonOut {
					return encodeJSON(cmd, rows)
				}
				return printSignalRows(cmd, rows)
			}
			set, err := signals.Export(db, runID)
			if err != nil {
				return err
			}
			if jsonOut {
				return encodeJSON(cmd, set)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "run=%s schema=%s count=%d\n", set.RunID, set.SchemaVersion, set.Count)
			printCounts(cmd, "DIMENSION", set.Counts)
			return printSignalRows(cmd, set.Signals)
		},
	}
	cmd.Flags().StringVar(&runID, "run", "", "run id")
	cmd.Flags().StringVar(&dimension, "dimension", "", "filter by dimension: behavior|cost|quality|security")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	return cmd
}

func signalsBackfillCmd(dataDir *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backfill",
		Short: "project legacy silos (risk_signals/baseline_deviations/cost_samples) into the unified model (idempotent)",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, cleanup, err := openLocalDB(*dataDir)
			if err != nil {
				return err
			}
			defer cleanup()
			n, err := signals.Backfill(db)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "projected %d new signal(s)\n", n)
			return nil
		},
	}
	return cmd
}

func printSignalRows(cmd *cobra.Command, rows []signals.Signal) error {
	if len(rows) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "(no signals)")
		return nil
	}
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "DIMENSION\tTYPE\tGRAPH_REF\tSEVERITY\tLABEL\tVALUE\tPRODUCED_BY")
	for _, s := range rows {
		fmt.Fprintf(w, "%s\t%s\t%s/%s\t%s\t%s\t%g\t%s\n",
			s.Dimension, s.Type, s.GraphRefKind, s.GraphRefID, s.Severity, s.Label, s.Value, s.ProducedBy)
	}
	return w.Flush()
}

func encodeJSON(cmd *cobra.Command, v any) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
