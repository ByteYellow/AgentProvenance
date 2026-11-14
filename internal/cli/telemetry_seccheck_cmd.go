package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/byteyellow/agentprovenance/internal/seccheck"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
	"github.com/spf13/cobra"
)

func telemetrySecCheckConfigCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{Use: "seccheck-config", Short: "print a pinned runsc trace configuration for one private socket", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		config, err := seccheck.TraceConfig(socket)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(config)
	}}
	cmd.Flags().StringVar(&socket, "socket", "", "private absolute SOCK_SEQPACKET endpoint")
	_ = cmd.MarkFlagRequired("socket")
	return cmd
}

func telemetryReceiveSecCheckCmd(dataDir *string) *cobra.Command {
	var path string
	var jsonOut bool
	var opts telemetry.SecCheckCollectOptions
	cmd := &cobra.Command{Use: "receive-seccheck", Short: "receive registered gVisor observations into the durable local spool", Args: cobra.NoArgs, SilenceUsage: true, RunE: func(cmd *cobra.Command, _ []string) error {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > 1<<20 {
			return fmt.Errorf("SecCheck config must be a regular file of at most 1 MiB")
		}
		dec := json.NewDecoder(io.LimitReader(f, (1<<20)+1))
		dec.DisallowUnknownFields()
		var config seccheck.CollectionConfig
		if err := dec.Decode(&config); err != nil {
			return fmt.Errorf("invalid SecCheck config: %w", err)
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			return fmt.Errorf("SecCheck config must contain one JSON object")
		}
		if err := config.Validate(); err != nil {
			return err
		}
		if runtime.GOOS != "linux" || (runtime.GOARCH != "arm64" && runtime.GOARCH != "amd64") {
			return fmt.Errorf("SecCheck reception requires Linux amd64 or arm64")
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
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		enc := json.NewEncoder(cmd.OutOrStdout())
		return telemetry.CollectSecCheck(ctx, db, paths, config, opts, func(s telemetry.SecCheckCollectStatus) error {
			if jsonOut {
				return enc.Encode(s)
			}
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "collector=%s state=%s targets=%d queued_batches=%d pending_events=%d error=%q\n", s.CollectorID, s.State, len(s.Targets), s.Spool.QueuedBatches, s.Spool.PendingEvents, s.Error)
			return err
		})
	}}
	cmd.Flags().StringVar(&path, "config", "", "trusted JSON registration file for 1..64 sandbox lifetimes")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit English JSON status updates")
	cmd.Flags().DurationVar(&opts.StatusInterval, "status-interval", 5*time.Second, "status interval (100ms to 1m)")
	cmd.Flags().DurationVar(&opts.DrainTimeout, "drain-timeout", 30*time.Second, "shutdown drain timeout (1s to 5m)")
	cmd.Flags().IntVar(&opts.Stream.BatchEvents, "batch-events", 256, "maximum records per durable batch (1 to 4096)")
	cmd.Flags().Int64Var(&opts.Stream.BatchBytes, "batch-bytes", 1<<20, "maximum batch size (1 KiB to 16 MiB)")
	cmd.Flags().Int64Var(&opts.Stream.MaxQueuedBytes, "max-queued-bytes", 256<<20, "shared spool capacity in bytes")
	cmd.Flags().IntVar(&opts.Stream.MaxQueuedBatches, "max-queued-batches", 4096, "shared spool capacity in batches")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}
