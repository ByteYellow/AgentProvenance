package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/byteyellow/agentprovenance/internal/daemon"
	"github.com/byteyellow/agentprovenance/internal/producer"
	"github.com/byteyellow/agentprovenance/internal/sensor"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
	"github.com/spf13/cobra"
)

func sensorCmd(dataDir *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sensor",
		Short: "run the self-owned eBPF system sensor (Linux, needs root/CAP_BPF)",
	}
	cmd.AddCommand(sensorStreamCmd(dataDir), sensorStatusCmd(dataDir))
	return cmd
}

// sensorStreamCmd is the per-node privileged half of supervised capture. It runs
// the eBPF sensor and persists bounded batches before asynchronous ingestion,
// where events are correlated to the scope owning their captured identity. Run ONE per
// host: every record/rollout whose process cgroup the kernel sees is then joined
// automatically at cgroup fidelity (0.98), with no per-scope sensor and no
// manual `agentprov-sensor | telemetry ingest-jsonl` pipe (which is how the demo
// wired it by hand). Runs until SIGINT/SIGTERM.
func sensorStreamCmd(dataDir *string) *cobra.Command {
	var sslLib string
	var noPolicy bool
	var keepUncorrelated bool
	var autoTLS bool
	var tlsInterval time.Duration
	var tlsTargets, tlsProcesses int
	var captureOpts telemetry.NativeStreamOptions
	stream := &cobra.Command{
		Use:   "stream",
		Short: "per-node supervisor: run the eBPF sensor and ingest+correlate its events into the local store until interrupted",
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
			daemon.WarnIfDaemonActive(*dataDir, cmd.ErrOrStderr())

			// Keep the sensor from observing (and re-ingesting, and thereby
			// amplifying) AgentProvenance's OWN I/O: its data-dir snapshot copies
			// and store DB writes. Without this, a record snapshot alone floods
			// the stream with thousands of file_writes to data-dir/snapshots that
			// bury and drop real scope events (observed on the lab VM). Two guards:
			// (1) drop file events whose path is under the data-dir; (2) drop any
			// event from the supervisor's own cgroup.
			ingOpts := telemetry.JSONLIngestOptions{Format: "native", Path: "sensor:stream", DropUncorrelated: !keepUncorrelated}
			if abs, err := filepath.Abs(*dataDir); err == nil {
				ingOpts.ExcludePathPrefixes = []string{abs}
			}
			if own := producer.SelfCgroupID(); own != "" {
				ingOpts.ExcludeCgroupIDs = []string{own}
			}

			stderr := cmd.ErrOrStderr()
			captureOpts.Ingest = ingOpts
			captureOpts.PolicyEnabled = !noPolicy
			capture, err := telemetry.NewNativeStream(db, paths, captureOpts)
			if err != nil {
				return err
			}
			defer capture.Close()
			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()
			workerErrors := make(chan error, 1)
			go func() {
				err := capture.Run(ctx, func(err error) { fmt.Fprintf(stderr, "agentprov sensor stream: spool retry: %v\n", err) })
				if err != nil {
					cancel()
				}
				workerErrors <- err
			}()
			resolvedSSLLib := sslLib
			if resolvedSSLLib == "" {
				resolvedSSLLib = os.Getenv("AGENTPROV_SSL_LIB")
			}
			fmt.Fprintln(stderr, "agentprov sensor stream: capturing kernel telemetry -> durable spool -> store (ctrl-c to stop)")
			sensorErr := sensor.RunWithOptions(capture, sensor.Options{
				SSLLib:          resolvedSSLLib,
				GoTLSBin:        os.Getenv("AGENTPROV_GO_TLS_BIN"),
				LibcLib:         os.Getenv("AGENTPROV_LIBC_LIB"),
				Context:         ctx,
				AutoTLS:         autoTLS,
				TLSScanInterval: tlsInterval,
				TLSMaxTargets:   tlsTargets,
				TLSMaxProcesses: tlsProcesses,
				Diagnostics:     stderr,
				OnReady:         func() { fmt.Fprintln(stderr, "agentprov sensor stream: ready probes-attached") },
				OnCapabilities: func(report sensor.CapabilityReport) {
					if err := saveSensorCapabilities(paths, report); err != nil {
						fmt.Fprintf(stderr, "agentprov sensor stream: persist capabilities: %v\n", err)
					}
				},
			})
			cancel()
			workerErr := <-workerErrors
			if err := capture.Flush(); err != nil {
				return err
			}
			if err := capture.Process(128); err != nil {
				fmt.Fprintf(stderr, "agentprov sensor stream: pending spool retained for retry: %v\n", err)
			}
			if err := capture.Close(); err != nil {
				return err
			}
			status, err := telemetry.ReadNativeStreamStatus(db)
			if err != nil {
				return err
			}
			encoded, err := json.Marshal(status)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "stopped %s\n", encoded)
			if workerErr != nil {
				return workerErr
			}
			if sensorErr != nil {
				return sensorErr
			}
			return nil
		},
	}
	stream.Flags().StringVar(&sslLib, "ssl-lib", "", "attach the TLS-plaintext uprobe to this libssl path (optional)")
	stream.Flags().BoolVar(&noPolicy, "no-policy", false, "skip per-batch telemetry policy evaluation")
	stream.Flags().BoolVar(&keepUncorrelated, "keep-uncorrelated", false, "retain events outside tracked scopes (default: wait pending-ttl for late bindings, then count and expire them)")
	stream.Flags().IntVar(&captureOpts.BatchEvents, "batch-events", 256, "maximum events per durable spool batch (1..4096)")
	stream.Flags().Int64Var(&captureOpts.BatchBytes, "batch-bytes", 1<<20, "maximum bytes per durable spool batch")
	stream.Flags().DurationVar(&captureOpts.FlushInterval, "flush-interval", time.Second, "interval for sealing live batches and retrying pending events")
	stream.Flags().DurationVar(&captureOpts.PendingTTL, "pending-ttl", 2*time.Minute, "maximum wait for a late binding; original event timestamps are preserved")
	stream.Flags().Int64Var(&captureOpts.MaxQueuedBytes, "max-queued-bytes", 256<<20, "maximum native spool backlog bytes; new events are counted as dropped when full")
	stream.Flags().IntVar(&captureOpts.MaxQueuedBatches, "max-queued-batches", 4096, "maximum active spool batches")
	stream.Flags().BoolVar(&autoTLS, "auto-tls", true, "discover container and host TLS libraries/binaries and reattach after replacement")
	stream.Flags().DurationVar(&tlsInterval, "tls-scan-interval", 2*time.Second, "interval for automatic TLS target discovery")
	stream.Flags().IntVar(&tlsTargets, "tls-max-targets", 128, "maximum automatically attached TLS targets")
	stream.Flags().IntVar(&tlsProcesses, "tls-max-processes", 4096, "maximum visible processes inspected per TLS discovery scan")
	return stream
}

func saveSensorCapabilities(paths store.Paths, report sensor.CapabilityReport) error {
	encoded, err := json.Marshal(report)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(paths.Logs, ".sensor-capabilities-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(encoded); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(paths.Logs, "sensor-capabilities.json"))
}

func sensorStatusCmd(dataDir *string) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{Use: "status", Short: "show durable capture counters and the latest probe capability snapshot", RunE: func(cmd *cobra.Command, args []string) error {
		paths, err := store.Init(*dataDir)
		if err != nil {
			return err
		}
		db, err := store.Open(paths)
		if err != nil {
			return err
		}
		defer db.Close()
		status, err := telemetry.ReadNativeStreamStatus(db)
		if err != nil {
			return err
		}
		running, err := telemetry.NativeStreamRunning(paths)
		if err != nil {
			return err
		}
		var capabilities any
		raw, err := os.ReadFile(filepath.Join(paths.Logs, "sensor-capabilities.json"))
		if err == nil {
			if err := json.Unmarshal(raw, &capabilities); err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		if asJSON {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"collector_running": running, "capabilities_historical": !running, "capture": status, "capabilities": capabilities})
		}
		fmt.Fprintf(cmd.OutOrStdout(), "collector_running=%t capabilities_historical=%t queued_batches=%d queued_bytes=%d pending_events=%d\n", running, !running, status.QueuedBatches, status.QueuedBytes, status.PendingEvents)
		return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"counters": status.Counters, "capabilities": capabilities})
	}}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit machine-readable capture and capability status")
	return cmd
}
