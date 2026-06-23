package cli

import (
	"encoding/json"
	"fmt"
	"github.com/byteyellow/agentprovenance/internal/correlation"
	securitymodel "github.com/byteyellow/agentprovenance/internal/security"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
	"github.com/spf13/cobra"
	"os"
	"text/tabwriter"
)

func telemetryCmd(dataDir *string) *cobra.Command {
	var runID, sessionID, eventType, toolCallID string
	var listJSON bool
	var batchesRunID string
	var batchesJSON bool
	list := &cobra.Command{
		Use:   "list",
		Short: "list recorded telemetry events",
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
			events, err := telemetry.ListEventsFiltered(db, telemetry.Filter{
				RunID:      runID,
				SessionID:  sessionID,
				Type:       eventType,
				ToolCallID: toolCallID,
			})
			if err != nil {
				return err
			}
			if listJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{
					"schema_version": "agentprovenance.telemetry_events/v1",
					"filter": map[string]string{
						"run_id":       runID,
						"session_id":   sessionID,
						"type":         eventType,
						"tool_call_id": toolCallID,
					},
					"event_count": len(events),
					"events":      events,
				})
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tRUN\tSESSION\tTOOL_CALL\tPROCESS\tSNAPSHOT\tCORRELATION\tCONFIDENCE\tSOURCE\tTYPE\tCREATED_AT")
			for _, event := range events {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%.2f\t%s\t%s\t%s\n", event.ID, event.RunID, event.SessionID, event.ToolCallID, event.ProcessID, event.SnapshotID, event.CorrelationMethod, event.CorrelationConfidence, event.Source, event.EventType, event.CreatedAt)
			}
			return w.Flush()
		},
	}
	list.Flags().StringVar(&runID, "run", "", "filter by run id")
	list.Flags().StringVar(&sessionID, "session", "", "filter by session id")
	list.Flags().StringVar(&eventType, "type", "", "filter by event type")
	list.Flags().StringVar(&toolCallID, "tool-call", "", "filter by tool call id")
	list.Flags().BoolVar(&listJSON, "json", false, "emit structured telemetry event JSON")
	cmd := &cobra.Command{Use: "telemetry", Short: "telemetry inspection commands"}
	cmd.AddCommand(list)
	cmd.AddCommand(telemetryBindCmd(dataDir))
	cmd.AddCommand(telemetryBindingsCmd(dataDir))
	cmd.AddCommand(telemetryIngestCmd(dataDir))
	cmd.AddCommand(telemetryIngestJSONLCmd(dataDir))
	cmd.AddCommand(telemetryIngestFalcoCmd(dataDir))
	batches := &cobra.Command{
		Use:   "batches",
		Short: "list telemetry ingest batch manifests",
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
			items, err := telemetry.ListBatches(db, batchesRunID)
			if err != nil {
				return err
			}
			if batchesJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{
					"schema_version": "agentprovenance.telemetry_batches/v1",
					"run_id":         batchesRunID,
					"batches":        items,
				})
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tRUN\tFORMAT\tREAD\tINGESTED\tSKIPPED\tFAILED\tFILE_SHA256\tEVENT_IDS_SHA256\tPATH\tCREATED_AT")
			for _, item := range items {
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%d\t%d\t%s\t%s\t%s\t%s\n",
					item.ID, item.RunID, item.Format, item.Read, item.Ingested, item.Skipped, item.Failed, item.FileSHA256, item.EventIDsSHA256, item.Path, item.CreatedAt)
			}
			return w.Flush()
		},
	}
	batches.Flags().StringVar(&batchesRunID, "run", "", "filter by run id")
	batches.Flags().BoolVar(&batchesJSON, "json", false, "emit JSON batch manifest list")
	cmd.AddCommand(batches)
	return cmd
}

func telemetryIngestFalcoCmd(dataDir *string) *cobra.Command {
	var opts telemetry.FalcoIngestOptions
	var jsonOut bool
	var noPolicy bool
	ingest := &cobra.Command{
		Use:   "ingest-falco",
		Short: "ingest Falco JSON/stdout events and map them into runtime telemetry",
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
			var input *os.File
			if opts.Path == "" || opts.Path == "-" {
				input = os.Stdin
				if opts.Path == "" {
					opts.Path = "stdin"
				}
			} else {
				input, err = os.Open(opts.Path)
				if err != nil {
					return err
				}
				defer input.Close()
			}
			result, err := telemetry.IngestFalco(db, opts, input)
			if err != nil {
				return err
			}
			decisionCount := 0
			if !noPolicy {
				for _, eventID := range result.EventIDs {
					if _, persisted, err := securitymodel.EvaluateRuntimeEvent(db, eventID); err != nil {
						result.Errors = append(result.Errors, fmt.Sprintf("event %s: policy failed: %v", eventID, err))
						result.Failed++
					} else if persisted {
						decisionCount++
					}
				}
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{
					"schema_version":   "agentprovenance.falco_ingest/v1",
					"batch":            result,
					"policy_decisions": decisionCount,
				})
			}
			fmt.Fprintf(cmd.OutOrStdout(), "batch=%s format=falco path=%s file_sha256=%s event_ids_sha256=%s read=%d ingested=%d skipped=%d failed=%d policy_decisions=%d\n",
				result.BatchID, result.Path, result.FileSHA256, result.EventIDsSHA256, result.Read, result.Ingested, result.Skipped, result.Failed, decisionCount)
			for _, msg := range result.Errors {
				fmt.Fprintf(cmd.OutOrStdout(), "error=%q\n", msg)
			}
			return nil
		},
	}
	ingest.Flags().StringVar(&opts.Path, "file", "-", "Falco JSON/stdout file path, or - for stdin")
	ingest.Flags().StringVar(&opts.RunID, "run", "", "default run id")
	ingest.Flags().StringVar(&opts.RolloutID, "rollout", "", "default rollout id")
	ingest.Flags().StringVar(&opts.AttemptID, "attempt", "", "default attempt id")
	ingest.Flags().StringVar(&opts.SessionID, "session", "", "default session id")
	ingest.Flags().StringVar(&opts.ToolCallID, "tool-call", "", "default tool call id")
	ingest.Flags().StringVar(&opts.ProcessID, "process", "", "default process id")
	ingest.Flags().StringVar(&opts.SnapshotID, "snapshot", "", "default snapshot id")
	ingest.Flags().BoolVar(&noPolicy, "no-policy", false, "disable automatic policy/risk/response evaluation")
	ingest.Flags().BoolVar(&jsonOut, "json", false, "emit JSON result")
	return ingest
}

func telemetryBindCmd(dataDir *string) *cobra.Command {
	var binding correlation.Binding
	bind := &cobra.Command{
		Use:   "bind",
		Short: "register a ToolCallScope binding for runtime telemetry correlation",
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
			id, err := correlation.RecordBinding(db, binding)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "binding_id=%s run=%s session=%s attempt=%s tool_call=%s process=%s container=%s cgroup=%s pid=%d source=%s confidence=%.2f\n",
				id, binding.RunID, binding.SessionID, binding.AttemptID, binding.ToolCallID, binding.ProcessID, binding.ContainerID, binding.CgroupID, binding.PID, binding.BindingSource, binding.Confidence)
			return nil
		},
	}
	bind.Flags().StringVar(&binding.RunID, "run", "", "run id")
	bind.Flags().StringVar(&binding.SessionID, "session", "", "session id")
	bind.Flags().StringVar(&binding.AttemptID, "attempt", "", "attempt id")
	bind.Flags().StringVar(&binding.ToolCallID, "tool-call", "", "tool call id")
	bind.Flags().StringVar(&binding.ProcessID, "process", "", "process id")
	bind.Flags().StringVar(&binding.ContainerID, "container-id", "", "container id visible to runtime telemetry")
	bind.Flags().StringVar(&binding.CgroupID, "cgroup-id", "", "cgroup id visible to runtime telemetry")
	bind.Flags().Int64Var(&binding.RootPID, "root-pid", 0, "root pid for the tool scope")
	bind.Flags().Int64Var(&binding.PID, "pid", 0, "pid or child pid visible to runtime telemetry")
	bind.Flags().StringVar(&binding.StartedAt, "started-at", "", "binding start time; defaults to now")
	bind.Flags().StringVar(&binding.EndedAt, "ended-at", "", "binding end time; empty means open")
	bind.Flags().StringVar(&binding.BindingSource, "source", "harness_tool_call_scope", "binding source")
	bind.Flags().Float64Var(&binding.Confidence, "confidence", 1, "binding confidence")
	_ = bind.MarkFlagRequired("run")
	_ = bind.MarkFlagRequired("tool-call")
	return bind
}

func telemetryBindingsCmd(dataDir *string) *cobra.Command {
	var filter correlation.BindingFilter
	bindings := &cobra.Command{
		Use:   "bindings",
		Short: "list ToolCallScope bindings",
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
			items, err := correlation.ListBindings(db, filter)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tRUN\tSESSION\tATTEMPT\tTOOL_CALL\tPROCESS\tCONTAINER\tCGROUP\tROOT_PID\tPID\tSOURCE\tCONFIDENCE\tSTARTED_AT\tENDED_AT")
			for _, item := range items {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%.2f\t%s\t%s\n",
					item.ID, item.RunID, item.SessionID, item.AttemptID, item.ToolCallID, item.ProcessID, item.ContainerID, item.CgroupID, item.RootPID, item.PID, item.BindingSource, item.Confidence, item.StartedAt, item.EndedAt)
			}
			return w.Flush()
		},
	}
	bindings.Flags().StringVar(&filter.RunID, "run", "", "filter by run id")
	bindings.Flags().StringVar(&filter.SessionID, "session", "", "filter by session id")
	bindings.Flags().StringVar(&filter.AttemptID, "attempt", "", "filter by attempt id")
	bindings.Flags().StringVar(&filter.ToolCallID, "tool-call", "", "filter by tool call id")
	bindings.Flags().StringVar(&filter.ProcessID, "process", "", "filter by process id")
	return bindings
}

func telemetryIngestCmd(dataDir *string) *cobra.Command {
	var event telemetry.IngestEvent
	ingest := &cobra.Command{
		Use:   "ingest",
		Short: "ingest a filtered high-value telemetry event",
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
			id, err := telemetry.IngestFiltered(db, event)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "event_id=%s type=%s source=%s\n", id, event.EventType, event.Source)
			return nil
		},
	}
	ingest.Flags().StringVar(&event.RunID, "run", "", "run id")
	ingest.Flags().StringVar(&event.RolloutID, "rollout", "", "rollout id")
	ingest.Flags().StringVar(&event.AttemptID, "attempt", "", "attempt id")
	ingest.Flags().StringVar(&event.SessionID, "session", "", "session id")
	ingest.Flags().StringVar(&event.ToolCallID, "tool-call", "", "tool call id")
	ingest.Flags().StringVar(&event.ProcessID, "process", "", "process id")
	ingest.Flags().StringVar(&event.SnapshotID, "snapshot", "", "snapshot id")
	ingest.Flags().StringVar(&event.RawEventID, "raw-event", "", "raw telemetry event id from the substrate")
	ingest.Flags().StringVar(&event.ContainerID, "container-id", "", "container id observed by runtime telemetry")
	ingest.Flags().StringVar(&event.CgroupID, "cgroup-id", "", "cgroup id observed by runtime telemetry")
	ingest.Flags().Int64Var(&event.PID, "pid", 0, "pid observed by runtime telemetry")
	ingest.Flags().Int64Var(&event.TGID, "tgid", 0, "tgid observed by runtime telemetry")
	ingest.Flags().Int64Var(&event.PPID, "ppid", 0, "parent pid observed by runtime telemetry")
	ingest.Flags().StringVar(&event.Timestamp, "timestamp", "", "runtime event timestamp; defaults to ingest time")
	ingest.Flags().StringVar(&event.Source, "source", "filtered_telemetry", "telemetry source")
	ingest.Flags().StringVar(&event.EventType, "type", "", "filtered event type")
	ingest.Flags().StringVar(&event.Payload, "payload", "{}", "JSON payload")
	_ = ingest.MarkFlagRequired("type")
	return ingest
}

func telemetryIngestJSONLCmd(dataDir *string) *cobra.Command {
	var opts telemetry.JSONLIngestOptions
	var jsonOut bool
	ingest := &cobra.Command{
		Use:   "ingest-jsonl",
		Short: "ingest filtered substrate telemetry JSONL from Tetragon, Falco, or LoongCollector",
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
			result, err := telemetry.IngestJSONL(db, opts)
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(result)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "batch=%s format=%s path=%s file_sha256=%s event_ids_sha256=%s read=%d ingested=%d skipped=%d failed=%d\n",
				result.BatchID, result.Format, result.Path, result.FileSHA256, result.EventIDsSHA256, result.Read, result.Ingested, result.Skipped, result.Failed)
			for _, msg := range result.Errors {
				fmt.Fprintf(cmd.OutOrStdout(), "error=%q\n", msg)
			}
			return nil
		},
	}
	ingest.Flags().StringVar(&opts.Format, "format", "auto", "jsonl format: auto, tetragon, falco, or loongcollector")
	ingest.Flags().StringVar(&opts.Path, "file", "", "JSONL file path")
	ingest.Flags().StringVar(&opts.RunID, "run", "", "default run id")
	ingest.Flags().StringVar(&opts.RolloutID, "rollout", "", "default rollout id")
	ingest.Flags().StringVar(&opts.AttemptID, "attempt", "", "default attempt id")
	ingest.Flags().StringVar(&opts.SessionID, "session", "", "default session id")
	ingest.Flags().StringVar(&opts.ToolCallID, "tool-call", "", "default tool call id")
	ingest.Flags().StringVar(&opts.ProcessID, "process", "", "default process id")
	ingest.Flags().StringVar(&opts.SnapshotID, "snapshot", "", "default snapshot id")
	ingest.Flags().BoolVar(&jsonOut, "json", false, "emit JSON result")
	_ = ingest.MarkFlagRequired("file")
	return ingest
}
