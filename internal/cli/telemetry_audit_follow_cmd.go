package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/daemon"
	"github.com/byteyellow/agentprovenance/internal/i18n"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
	"github.com/spf13/cobra"
)

func telemetryFollowAuditCmd(dataDir *string) *cobra.Command {
	var opts telemetry.AuditFollowOptions
	var preset string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:          "follow-audit",
		Short:        "follow an existing audit log with durable checkpoints and read-only coverage diagnostics",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			paths, err := store.Init(*dataDir)
			if err != nil {
				return err
			}
			db, err := store.Open(paths)
			if err != nil {
				return err
			}
			defer db.Close()
			locale := commandLanguage(cmd)
			if jsonOut {
				locale = i18n.English
			}
			daemon.WarnIfDaemonActive(*dataDir, cmd.ErrOrStderr(), locale)
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
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			encoder := json.NewEncoder(cmd.OutOrStdout())
			printStatus := func(result telemetry.AuditFollowStatus) error {
				if jsonOut {
					return encoder.Encode(result)
				}
				s := result.Reader
				_, err := fmt.Fprintf(cmd.OutOrStdout(), commandText(cmd, "reader=%s status=%s reason=%s read=%d ingested=%d duplicates=%d failed=%d pending_bytes=%d\n"), s.ReaderID, s.Status, s.Reason, s.Read, s.Ingested, s.Duplicates, s.Failed, s.PendingBytes)
				return err
			}
			var progress func(telemetry.AuditFollowStatus) error
			if !opts.Once {
				progress = printStatus
			}
			result, followErr := telemetry.FollowAuditFile(ctx, db, paths, opts, progress)
			if opts.Once || followErr != nil {
				if err := printStatus(result); err != nil {
					return err
				}
			}
			if followErr != nil {
				return followErr
			}
			if opts.Once && result.Reader.Failed > 0 {
				return fmt.Errorf("audit reader has recorded %d invalid rows", result.Reader.Failed)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&opts.Path, "file", "", "existing append-only audit text or journal JSON file")
	cmd.Flags().StringVar(&opts.RunID, "run", "", "run containing these records; does not assign an Agent session")
	cmd.Flags().StringVar(&opts.ReaderID, "reader-id", "", "checkpoint identity; defaults to the run, file path and mechanism")
	cmd.Flags().StringVar(&opts.Source.HostID, "host-id", "", "source host identity when absent from journal JSON")
	cmd.Flags().StringVar(&opts.Source.BootID, "boot-id", "", "source boot identity when absent from journal JSON")
	cmd.Flags().StringVar(&opts.Mechanism, "mechanism", "all", "read apparmor, seccomp, or all supported audit records")
	cmd.Flags().StringVar(&preset, "capture", "detailed", "raw-record retention for a new run: basic or detailed; existing run settings are reused")
	cmd.Flags().DurationVar(&opts.PollInterval, "poll-interval", time.Second, "interval between audit source checks (50ms to 1m)")
	cmd.Flags().BoolVar(&opts.Once, "once", false, "drain complete records currently available and stop without waiting for new bytes")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit English JSON status; continuous mode emits one object per update")
	_ = cmd.MarkFlagRequired("file")
	_ = cmd.MarkFlagRequired("run")
	return cmd
}
