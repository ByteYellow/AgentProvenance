package cli

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/byteyellow/agentprovenance/internal/signal"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/spf13/cobra"
)

func signalCmd(dataDir, daemonURL *string) *cobra.Command {
	var runID string
	var jsonOut bool
	var external string
	run := &cobra.Command{
		Use:   "run",
		Short: "run built-in or external evaluators over provenance evidence",
		RunE: func(cmd *cobra.Command, args []string) error {
			var report signal.EvalReport
			var err error
			if client, ok := daemonClient(*daemonURL); ok {
				if external == "" {
					report, err = client.RunBuiltinSignals(runID)
				} else {
					ctx, ctxErr := client.SignalContext(runID)
					if ctxErr != nil {
						return ctxErr
					}
					localReport, runErr := signal.RunExternal(external, ctx)
					if runErr != nil {
						return runErr
					}
					report, err = client.ImportSignals(runID, external, localReport.Signals)
				}
			} else {
				db, closeFn, openErr := signalDB(*dataDir)
				if openErr != nil {
					return openErr
				}
				defer closeFn()
				ctx, ctxErr := signal.BuildEvalContext(db, runID)
				if ctxErr != nil {
					return ctxErr
				}
				if external != "" {
					report, err = signal.RunExternal(external, ctx)
				} else {
					report, err = signal.BuildBuiltinReportFromContext(ctx)
				}
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
			ctx, err := signalContext(*dataDir, *daemonURL, contextRunID)
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

	var batchContextRunsFile string
	var batchContextBatchID string
	var batchContextRunID string
	var batchContextJobID string
	var batchContextShardID string
	var batchContextLatest bool
	var batchContextLimit int
	batchContextCmd := &cobra.Command{
		Use:   "batch-context",
		Short: "export EvalContext JSONL for many runs",
		RunE: func(cmd *cobra.Command, args []string) error {
			runIDs, err := batchContextRunIDs(*dataDir, batchContextRunsFile, batchSummaryOptions{
				BatchID: batchContextBatchID,
				RunID:   batchContextRunID,
				JobID:   batchContextJobID,
				ShardID: batchContextShardID,
				Latest:  batchContextLatest,
				Limit:   batchContextLimit,
			})
			if err != nil {
				return err
			}
			if len(runIDs) == 0 {
				return fmt.Errorf("no run ids matched")
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			for _, runID := range runIDs {
				ctx, err := signalContext(*dataDir, *daemonURL, runID)
				if err != nil {
					return fmt.Errorf("run %s: %w", runID, err)
				}
				if err := enc.Encode(ctx); err != nil {
					return err
				}
			}
			return nil
		},
	}
	batchContextCmd.Flags().StringVar(&batchContextRunsFile, "runs", "", "JSONL run list; each line may be a run_id string, plain run id, or object with run_id")
	batchContextCmd.Flags().StringVar(&batchContextBatchID, "batch", "", "record batch id")
	batchContextCmd.Flags().StringVar(&batchContextRunID, "run", "", "single run id or record-batch run filter")
	batchContextCmd.Flags().StringVar(&batchContextJobID, "job", "", "record batch job id")
	batchContextCmd.Flags().StringVar(&batchContextShardID, "shard", "", "record batch shard id")
	batchContextCmd.Flags().BoolVar(&batchContextLatest, "latest", false, "use only the latest matching record batch")
	batchContextCmd.Flags().IntVar(&batchContextLimit, "limit", 100, "maximum run contexts to export")

	var importRunID string
	var importFile string
	var importBatchFile string
	var importBatchEngine string
	var importJSON bool
	importCmd := &cobra.Command{
		Use:   "import",
		Short: "validate external evaluator signals",
		RunE: func(cmd *cobra.Command, args []string) error {
			output, err := readExternalSignals(importFile)
			if err != nil {
				return err
			}
			var report signal.EvalReport
			if client, ok := daemonClient(*daemonURL); ok {
				report, err = client.ImportSignals(importRunID, "imported-external-evaluator", output.Signals)
			} else {
				report, err = signal.ImportSignals(importRunID, "imported-external-evaluator", output.Signals)
			}
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

	importBatchCmd := &cobra.Command{
		Use:   "import-batch",
		Short: "validate many external evaluator signal reports from JSONL",
		RunE: func(cmd *cobra.Command, args []string) error {
			reports, err := readExternalSignalReports(importBatchFile)
			if err != nil {
				return err
			}
			if len(reports) == 0 {
				return fmt.Errorf("no signal reports found")
			}
			report, err := signal.ImportBatchReports(importBatchEngine, reports)
			if err != nil {
				return err
			}
			if importJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}
			return printSignalBatchImportReport(cmd.OutOrStdout(), report)
		},
	}
	importBatchCmd.Flags().StringVar(&importBatchFile, "file", "", "JSONL signal report file; each line is EvalReport or {run_id,signals}")
	importBatchCmd.Flags().StringVar(&importBatchEngine, "engine", "imported-external-evaluator", "engine name to stamp onto imported reports")
	importBatchCmd.Flags().BoolVar(&importJSON, "json", false, "emit structured evaluator signal batch JSON")
	_ = importBatchCmd.MarkFlagRequired("file")

	cmd := &cobra.Command{Use: "signal", Short: "code-based evaluator signal commands"}
	cmd.AddCommand(run)
	cmd.AddCommand(contextCmd)
	cmd.AddCommand(batchContextCmd)
	cmd.AddCommand(importCmd)
	cmd.AddCommand(importBatchCmd)
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

func signalContext(dataDir, daemonURL, runID string) (signal.EvalContext, error) {
	if client, ok := daemonClient(daemonURL); ok {
		return client.SignalContext(runID)
	}
	db, closeFn, err := signalDB(dataDir)
	if err != nil {
		return signal.EvalContext{}, err
	}
	defer closeFn()
	return signal.BuildEvalContext(db, runID)
}

func batchContextRunIDs(dataDir, runsFile string, opts batchSummaryOptions) ([]string, error) {
	if runsFile != "" {
		return readRunIDList(runsFile)
	}
	if opts.RunID != "" && opts.BatchID == "" && opts.JobID == "" && opts.ShardID == "" && !opts.Latest {
		return []string{opts.RunID}, nil
	}
	db, closeFn, err := signalDB(dataDir)
	if err != nil {
		return nil, err
	}
	defer closeFn()
	report, err := buildRecordBatchSummary(db, opts)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	runIDs := make([]string, 0, len(report.Items))
	for _, item := range report.Items {
		if item.RunID == "" {
			continue
		}
		if _, ok := seen[item.RunID]; ok {
			continue
		}
		seen[item.RunID] = struct{}{}
		runIDs = append(runIDs, item.RunID)
	}
	return runIDs, nil
}

func readRunIDList(path string) ([]string, error) {
	var input io.Reader
	if path == "-" {
		input = os.Stdin
	} else {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		input = file
	}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var runIDs []string
	seen := map[string]struct{}{}
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		runID, err := parseRunIDLine(line)
		if err != nil {
			return nil, fmt.Errorf("parse run list line %d: %w", lineNo, err)
		}
		if runID == "" {
			return nil, fmt.Errorf("parse run list line %d: run_id is required", lineNo)
		}
		if _, ok := seen[runID]; ok {
			continue
		}
		seen[runID] = struct{}{}
		runIDs = append(runIDs, runID)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return runIDs, nil
}

func parseRunIDLine(line string) (string, error) {
	var asString string
	if err := json.Unmarshal([]byte(line), &asString); err == nil {
		return strings.TrimSpace(asString), nil
	}
	var asObject struct {
		RunID string `json:"run_id"`
	}
	if err := json.Unmarshal([]byte(line), &asObject); err == nil && asObject.RunID != "" {
		return strings.TrimSpace(asObject.RunID), nil
	}
	if strings.HasPrefix(line, "{") || strings.HasPrefix(line, "[") {
		return "", fmt.Errorf("JSON line must be a string or object with run_id")
	}
	return line, nil
}

func readExternalSignals(path string) (signal.ExternalEvalOutput, error) {
	var raw []byte
	var err error
	if path == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		return signal.ExternalEvalOutput{}, err
	}
	var output signal.ExternalEvalOutput
	if err := json.Unmarshal(raw, &output); err != nil {
		var signals []signal.EvalSignal
		if err2 := json.Unmarshal(raw, &signals); err2 != nil {
			return signal.ExternalEvalOutput{}, fmt.Errorf("signal import file must be {signals:[...]} or raw EvalSignal array: %w", err)
		}
		output.Signals = signals
	}
	return output, nil
}

func readExternalSignalReports(path string) ([]signal.EvalReport, error) {
	var input io.Reader
	if path == "-" {
		input = os.Stdin
	} else {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		input = file
	}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	var reports []signal.EvalReport
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		report, err := parseExternalSignalReportLine(line)
		if err != nil {
			return nil, fmt.Errorf("parse signal report line %d: %w", lineNo, err)
		}
		reports = append(reports, report)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return reports, nil
}

func parseExternalSignalReportLine(line string) (signal.EvalReport, error) {
	var report signal.EvalReport
	if err := json.Unmarshal([]byte(line), &report); err == nil && (report.RunID != "" || len(report.Signals) > 0) {
		return report, nil
	}
	var wrapped struct {
		RunID   string              `json:"run_id"`
		Signals []signal.EvalSignal `json:"signals"`
	}
	if err := json.Unmarshal([]byte(line), &wrapped); err != nil {
		return signal.EvalReport{}, err
	}
	return signal.EvalReport{RunID: wrapped.RunID, Signals: wrapped.Signals}, nil
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

func printSignalBatchImportReport(out io.Writer, report signal.BatchImportReport) error {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "schema=%s engine=%s reports=%d runs=%d signals=%d failed=%d result_set=%s page_hash=%s\n",
		report.SchemaVersion, report.Engine, report.ReportCount, report.RunCount, report.SignalCount, report.Failed, report.ResultSetID, report.PageHash)
	fmt.Fprintln(w, "RUN\tSIGNALS\tRESULT_SET\tPAGE_HASH")
	for _, item := range report.Runs {
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\n", item.RunID, item.SignalCount, item.ResultSetID, item.PageHash)
	}
	if len(report.Errors) > 0 {
		fmt.Fprintln(w, "ERROR\tMESSAGE")
		for _, item := range report.Errors {
			fmt.Fprintf(w, "error\t%s\n", item)
		}
	}
	return w.Flush()
}
