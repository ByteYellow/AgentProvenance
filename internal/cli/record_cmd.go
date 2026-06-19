package cli

import (
	"encoding/json"
	"fmt"

	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/spf13/cobra"
)

func recordCmd(dataDir *string) *cobra.Command {
	var runID string
	var name string
	var workdir string
	var withJSON bool
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
			if withJSON {
				return printRecordJSON(cmd, result)
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
	cmd.Flags().BoolVar(&withJSON, "json", false, "emit machine-readable zero-SDK record manifest")
	return cmd
}

func printRecordJSON(cmd *cobra.Command, result record.Result) error {
	processTreeCount := 0
	if result.RootPID != 0 {
		processTreeCount = 1 + len(result.Observed)
	}
	manifest := map[string]any{
		"schema_version":     "agentprovenance.record/v1",
		"run_id":             result.RunID,
		"rollout_id":         result.RolloutID,
		"base_snapshot_id":   result.BaseSnapshotID,
		"attempt_id":         result.AttemptID,
		"session_id":         result.SessionID,
		"tool_call_id":       result.ToolCallID,
		"process_id":         result.ProcessID,
		"workdir":            result.Workdir,
		"command":            result.Command,
		"status":             result.Status,
		"exit_code":          result.ExitCode,
		"wall_ms":            result.WallMS,
		"changed_files":      result.ChangedFiles,
		"changed_file_count": len(result.ChangedFiles),
		"context_mode":       "zero_sdk",
		"root_pid":           result.RootPID,
		"observed_processes": result.Observed,
		"orphan_policy":      result.OrphanPolicy,
		"post_root_grace_ms": result.PostRootGraceMS,
		"cwd":                result.CWD,
		"process_tree_count": processTreeCount,
		"time_window": map[string]any{
			"started_at": result.StartedAt,
			"ended_at":   result.EndedAt,
		},
		"scope_inference": map[string]any{
			"method":             "zero_sdk_root_process+cwd+time_window+file_diff",
			"root_pid":           result.RootPID,
			"process_tree_count": processTreeCount,
			"cwd":                result.CWD,
			"changed_file_count": len(result.ChangedFiles),
			"observed_processes": len(result.Observed),
			"boundary":           "root_pid_descendants+cwd+time_window+file_diff",
			"orphan_policy":      result.OrphanPolicy,
			"post_root_grace_ms": result.PostRootGraceMS,
		},
	}
	if result.FailureReason != "" {
		manifest["failure_reason"] = result.FailureReason
	}
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(manifest)
}
