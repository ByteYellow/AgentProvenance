package cli

import (
	"fmt"
	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
	"github.com/spf13/cobra"
	"text/tabwriter"
)

func telemetryCmd(dataDir *string) *cobra.Command {
	var runID, sessionID, eventType, toolCallID string
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
	cmd := &cobra.Command{Use: "telemetry", Short: "telemetry inspection commands"}
	cmd.AddCommand(list)
	cmd.AddCommand(telemetryBindCmd(dataDir))
	cmd.AddCommand(telemetryBindingsCmd(dataDir))
	cmd.AddCommand(telemetryIngestCmd(dataDir))
	return cmd
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
