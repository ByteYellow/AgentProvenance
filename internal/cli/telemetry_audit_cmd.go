package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/daemon"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
	"github.com/spf13/cobra"
)

func telemetryIngestAuditCmd(dataDir *string) *cobra.Command {
	var opts telemetry.AuditIngestOptions
	var preset string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "ingest-audit",
		Short: "read existing AppArmor/seccomp audit text or journal JSON without changing host policies",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var input io.Reader = cmd.InOrStdin()
			if opts.Path != "-" {
				file, err := os.Open(opts.Path)
				if err != nil {
					return err
				}
				defer file.Close()
				input = file
			}
			paths, err := store.Init(*dataDir)
			if err != nil {
				return err
			}
			db, err := store.Open(paths)
			if err != nil {
				return err
			}
			defer db.Close()
			daemon.WarnIfDaemonActive(*dataDir, cmd.ErrOrStderr(), commandLanguage(cmd))
			service := agentcontext.Service{DB: db, Paths: paths}
			if cmd.Flags().Changed("capture") {
				policy, err := agentcontext.NewCapturePolicy(preset, nil)
				if err != nil {
					return err
				}
				service.CapturePolicy = &policy
			}
			policy, err := service.EnsureCapturePolicy(cmd.Context(), opts.RunID)
			if err != nil {
				return err
			}
			opts.RetainRaw = policy.SourceRecords
			result, ingestErr := telemetry.IngestAuditReader(cmd.Context(), db, opts, input)
			if jsonOut {
				encoder := json.NewEncoder(cmd.OutOrStdout())
				encoder.SetIndent("", "  ")
				if err := encoder.Encode(result); err != nil {
					return err
				}
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), commandText(cmd, "read=%d ingested=%d duplicates=%d skipped=%d failed=%d identity_incomplete=%d status=%s\n"),
					result.Read, result.Ingested, result.Duplicates, result.Skipped, result.Failed, result.IdentityIncomplete, result.Status)
				for _, message := range result.Errors {
					fmt.Fprintln(cmd.ErrOrStderr(), message)
				}
			}
			if ingestErr != nil {
				return ingestErr
			}
			if result.Failed > 0 {
				return fmt.Errorf("audit import recorded %d invalid rows", result.Failed)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&opts.Path, "file", "", "existing audit log/journal JSON file, or - for stdin")
	cmd.Flags().StringVar(&opts.RunID, "run", "", "run containing these records; does not assign an Agent session")
	cmd.Flags().StringVar(&opts.Source.HostID, "host-id", "", "source host identity when absent from journal JSON")
	cmd.Flags().StringVar(&opts.Source.BootID, "boot-id", "", "source boot identity when absent from journal JSON")
	cmd.Flags().StringVar(&opts.Mechanism, "mechanism", "all", "read apparmor, seccomp, or all supported audit records")
	cmd.Flags().StringVar(&preset, "capture", "detailed", "raw-record retention for a new run: basic or detailed; existing run settings are reused")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit bounded import summary and record references")
	_ = cmd.MarkFlagRequired("file")
	_ = cmd.MarkFlagRequired("run")
	return cmd
}
