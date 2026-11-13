package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/byteyellow/agentprovenance/internal/daemon"
	"github.com/byteyellow/agentprovenance/internal/handoff"
	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/spf13/cobra"
)

func daemonCmd(dataDir *string) *cobra.Command {
	var listen string
	var sampleInterval time.Duration
	var sampleLimit int
	var sampleTimeout time.Duration
	var rawRetention time.Duration
	var maxRawSamples int
	var evidenceInterval time.Duration
	var evidenceLimit int
	var spoolInterval time.Duration
	var spoolLimit int
	var spoolMaxQueued int
	var spoolMaxBytes int64
	var spoolMaxBatchBytes int64
	var spoolDropPolicy string
	var gcInterval time.Duration
	var gcLimit int
	var authToken string
	var insecureOpen bool
	var ingestAllowDir string
	var recordAllowShell bool
	var recordTimeout time.Duration
	var executionConfig string
	serve := &cobra.Command{
		Use:   "serve",
		Short: "run the local AgentProvenance daemon/API server",
		RunE: func(cmd *cobra.Command, args []string) (runErr error) {
			server, closeFn, err := daemon.NewServer(*dataDir)
			if err != nil {
				return err
			}
			// P1 fix: take the instance lock BEFORE reading or persisting the
			// auth token. A failed startup must never rotate the credentials a
			// live daemon and its clients are still using.
			if info, active := daemon.ActiveLock(*dataDir); active {
				closeFn()
				return fmt.Errorf("another agentprov daemon (pid %d) already owns data dir %s and listens on %s; stop it first or point clients at --daemon-url http://%s", info.PID, *dataDir, info.Addr, info.Addr)
			}
			releaseLock, lockErr := daemon.AcquireLock(*dataDir, listen)
			if lockErr != nil {
				closeFn()
				return lockErr
			}
			defer closeFn()
			defer releaseLock()
			server.SampleInterval = sampleInterval
			server.SampleLimit = sampleLimit
			server.SampleTimeout = sampleTimeout
			server.RawRetention = rawRetention
			server.MaxRawSamples = maxRawSamples
			server.EvidenceInterval = evidenceInterval
			server.EvidenceLimit = evidenceLimit
			server.SpoolInterval = spoolInterval
			server.SpoolLimit = spoolLimit
			server.SpoolMaxQueued = spoolMaxQueued
			server.SpoolMaxBytes = spoolMaxBytes
			server.SpoolMaxBatchBytes = spoolMaxBatchBytes
			server.SpoolDropPolicy = spoolDropPolicy
			server.GCInterval = gcInterval
			server.GCLimit = gcLimit
			server.RecordAllowShell = recordAllowShell
			server.RecordExecTimeout = recordTimeout
			resolvedToken, tokenErr := resolveServeToken(*dataDir, authToken, insecureOpen, listen, cmd.OutOrStdout(), cmd.ErrOrStderr())
			if tokenErr != nil {
				return tokenErr
			}
			authToken = resolvedToken
			server.AuthToken = authToken
			if ingestAllowDir == "" {
				ingestAllowDir = filepath.Join(*dataDir, "ingest")
			}
			absAllow, absErr := filepath.Abs(ingestAllowDir)
			if absErr != nil {
				return absErr
			}
			if mkErr := os.MkdirAll(absAllow, 0o700); mkErr != nil {
				return mkErr
			}
			server.IngestAllowDir = absAllow
			server.ListenAddr = listen
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			if executionConfig != "" {
				if server.AuthToken == "" || insecureOpen {
					return fmt.Errorf("execution handoff requires authentication; remove --insecure-open")
				}
				f, err := os.Open(executionConfig)
				if err != nil {
					return err
				}
				config, readErr := handoff.ReadConfig(f)
				closeErr := f.Close()
				if err := errors.Join(readErr, closeErr); err != nil {
					return err
				}
				server.Execution = &handoff.Executor{Ledger: handoff.Ledger{DB: server.DB, Target: config.Target},
					Paths: server.Paths, Concurrency: config.Concurrency,
					Options: record.Options{AllowShell: recordAllowShell, Timeout: recordTimeout}}
				server.ExecutionCaller = config.Principal()
				closeExecutor, err := server.Execution.Start(ctx)
				if err != nil {
					return err
				}
				defer func() { runErr = errors.Join(runErr, closeExecutor()) }()
			}
			go server.StartSampler(ctx)
			go server.StartSpoolWorker(ctx)
			go server.StartEvidenceWorker(ctx)
			go server.StartGCWorker(ctx)
			fmt.Fprintf(cmd.ErrOrStderr(), commandText(cmd, "agentprov daemon listening on http://%s sample_interval=%s sample_limit=%d sample_timeout=%s spool_interval=%s evidence_interval=%s gc_interval=%s\n"), listen, sampleInterval, sampleLimit, sampleTimeout, spoolInterval, evidenceInterval, gcInterval)
			httpServer := &http.Server{Addr: listen, Handler: server.Handler()}
			go func() {
				<-ctx.Done()
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = httpServer.Shutdown(shutdownCtx)
			}()
			err = httpServer.ListenAndServe()
			if err == http.ErrServerClosed {
				return nil
			}
			return err
		},
	}
	serve.Flags().StringVar(&listen, "listen", "127.0.0.1:8574", "daemon listen address")
	serve.Flags().DurationVar(&sampleInterval, "sample-interval", 5*time.Second, "background Docker stats sampling interval; set 0 to disable")
	serve.Flags().IntVar(&sampleLimit, "sample-limit", 64, "maximum running sessions sampled per interval")
	serve.Flags().DurationVar(&sampleTimeout, "sample-timeout", 2*time.Second, "timeout for each Docker stats sample")
	serve.Flags().DurationVar(&rawRetention, "raw-retention", 10*time.Minute, "raw cpu sample retention duration")
	serve.Flags().IntVar(&maxRawSamples, "max-raw-samples", 512, "maximum retained raw cpu samples per session")
	serve.Flags().DurationVar(&evidenceInterval, "evidence-interval", 2*time.Second, "background evidence materialization interval; set 0 to disable")
	serve.Flags().IntVar(&evidenceLimit, "evidence-limit", 100, "maximum queued evidence events processed per interval")
	serve.Flags().DurationVar(&spoolInterval, "spool-interval", 1*time.Second, "background telemetry spool processing interval; set 0 to disable")
	serve.Flags().IntVar(&spoolLimit, "spool-limit", 100, "maximum queued telemetry spool batches processed per interval")
	serve.Flags().IntVar(&spoolMaxQueued, "spool-max-queued", 1000, "maximum queued telemetry spool batches accepted before backpressure rejects new ingest")
	serve.Flags().Int64Var(&spoolMaxBytes, "spool-max-bytes", 1<<30, "maximum total bytes held by queued/processing telemetry spool batches; set 0 to disable")
	serve.Flags().Int64Var(&spoolMaxBatchBytes, "spool-max-batch-bytes", 256<<20, "maximum bytes accepted in one telemetry spool batch; set 0 to disable")
	serve.Flags().StringVar(&spoolDropPolicy, "spool-drop-policy", "reject", "telemetry spool queue-full behavior: reject or drop_oldest")
	serve.Flags().DurationVar(&gcInterval, "gc-interval", 5*time.Second, "background async GC interval; set 0 to disable")
	serve.Flags().IntVar(&gcLimit, "gc-limit", 100, "maximum queued GC jobs processed per interval")
	serve.Flags().StringVar(&authToken, "auth-token", "", "bearer token required on API routes except GET /v1/health, /v1/ready and /v1/live (also AGENTPROV_DAEMON_TOKEN); empty = generate a strong random token, persist it to <data-dir>/auth-token (0600) and print it")
	serve.Flags().BoolVar(&insecureOpen, "insecure-open", false, "escape hatch: run the API without authentication (explicit opt-in only; a loud warning is printed)")
	serve.Flags().StringVar(&ingestAllowDir, "ingest-allow-dir", "", "only files inside this directory may be read by /v1/leases (task) and /v1/telemetry/ingest-falco (file); default <data-dir>/ingest")
	serve.Flags().BoolVar(&recordAllowShell, "record-allow-shell", false, "execution policy for the authenticated /v1/record API: running arbitrary programs for authenticated callers is the product design, this switch only controls the shell wrapper form — permit shell interpreters (sh -c ...) as argv[0]; default false = refused")
	serve.Flags().DurationVar(&recordTimeout, "record-timeout", 0, "execution policy for the authenticated /v1/record API: per-exec timeout, 0 = policy default (60s), negative = unbounded")
	serve.Flags().StringVar(&executionConfig, "execution-config", "", "trusted caller and target configuration for durable execution handoff; disabled by default")
	cmd := &cobra.Command{Use: "daemon", Short: "local daemon/API server commands"}
	cmd.AddCommand(serve)
	return cmd
}

// resolveServeToken decides the bearer token for `daemon serve`:
//
//  1. explicit --auth-token / AGENTPROV_DAEMON_TOKEN wins and is never
//     persisted (operator-managed credential);
//  2. --insecure-open runs without a token (loud warning on stderr);
//  3. otherwise a non-empty <data-dir>/auth-token is REUSED — no rotation, so
//     clients configured with the old token keep working across restarts;
//  4. only when nothing exists yet is a fresh token generated and persisted.
//
// Callers must hold the per-data-dir instance lock before step 4 can run, so a
// second serve that loses the lock race never overwrites live credentials.
// The token value itself is only ever printed at first generation.
func resolveServeToken(dataDir, explicit string, insecureOpen bool, listen string, stdout, stderr io.Writer) (string, error) {
	if explicit == "" {
		explicit = os.Getenv("AGENTPROV_DAEMON_TOKEN")
	}
	if explicit != "" {
		return explicit, nil
	}
	if insecureOpen {
		fmt.Fprintf(stderr, "WARNING: --insecure-open is set: the daemon API has NO authentication on http://%s — every local process can read the evidence store, ingest data, exec in containers and run commands as this user.\n", listen)
		return "", nil
	}
	if existing := daemon.ReadAuthToken(dataDir); existing != "" {
		fmt.Fprintf(stderr, "reusing existing auth token from %s\n", daemon.TokenPath(dataDir))
		return existing, nil
	}
	// Fail-closed default (C1): generate a strong random token, persist
	// it for API clients, and require it on every non-health route.
	token, err := daemon.GenerateAuthToken()
	if err != nil {
		return "", err
	}
	if err := daemon.WriteAuthTokenFile(dataDir, token); err != nil {
		return "", err
	}
	fmt.Fprintf(stdout, "daemon auth token generated (file %s, mode 0600):\n%s\n", daemon.TokenPath(dataDir), token)
	return token, nil
}
