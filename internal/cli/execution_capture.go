package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/byteyellow/agentprovenance/internal/handoff"
	"github.com/byteyellow/agentprovenance/internal/i18n"
	"github.com/byteyellow/agentprovenance/internal/producer"
	"github.com/byteyellow/agentprovenance/internal/sensor"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

// The caller closes the executor first so its final checkpoints can still use
// the sensor. An unexpected capture exit separately signals daemon shutdown.
type executionCaptureRuntime struct {
	Controller *handoff.NativeCapture
	failed     chan struct{}
	done       chan struct{}
	cancel     context.CancelFunc
	mu         sync.Mutex
	err        error
	once       sync.Once
	closeErr   error
}

func startExecutionCapture(ctx context.Context, db *sql.DB, paths store.Paths, config handoff.CaptureConfig,
	lang i18n.Locale, diagnostics io.Writer, runSensor func(io.Writer, sensor.Options) error) (*executionCaptureRuntime, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	ingest := telemetry.JSONLIngestOptions{Format: "native", Path: "daemon:execution", DropUncorrelated: true}
	// Workloads may legitimately write inside Paths.Workspaces. Exclude our
	// process scope, not the data-directory prefix containing those artifacts.
	if own := producer.SelfCgroupID(); own != "" {
		ingest.ExcludeCgroupIDs = []string{own}
	}
	stream, err := telemetry.NewNativeStream(db, paths, telemetry.NativeStreamOptions{Ingest: ingest, PolicyEnabled: !config.NoPolicy})
	if err != nil {
		return nil, err
	}
	// Request/daemon cancellation stops execution first; capture continues until
	// Close. During startup, the select below still observes the caller deadline.
	captureCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	r := &executionCaptureRuntime{failed: make(chan struct{}), done: make(chan struct{}), cancel: cancel}
	var capsMu sync.Mutex
	var caps sensor.CapabilityReport
	checkpointer := sensor.NewCheckpointer()
	r.Controller = &handoff.NativeCapture{Checkpointer: checkpointer, Stream: stream,
		Timeout: time.Duration(config.CloseTimeoutSeconds) * time.Second, Capabilities: func() sensor.CapabilityReport {
			capsMu.Lock()
			defer capsMu.Unlock()
			return caps
		}}
	recordError := func(err error) {
		if err == nil || err == context.Canceled {
			return
		}
		r.mu.Lock()
		r.err = errors.Join(r.err, err)
		select {
		case <-r.failed:
		default:
			close(r.failed)
		}
		r.mu.Unlock()
		cancel()
	}
	var workers sync.WaitGroup
	start := func(name string, run func() error) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			err := run()
			if err == nil && captureCtx.Err() == nil {
				err = fmt.Errorf("execution capture %s stopped unexpectedly", name)
			}
			recordError(err)
		}()
	}
	start("spool", func() error {
		return stream.Run(captureCtx, func(err error) {
			fmt.Fprintf(diagnostics, "agentprov execution capture: spool retry: %v\n", err)
		})
	})
	ready := make(chan struct{})
	var readyOnce sync.Once
	enabled := func(value *bool) bool { return value == nil || *value }
	start("sensor", func() error {
		return runSensor(stream, sensor.Options{Context: captureCtx, ContextOnly: true,
			Checkpointer:  checkpointer,
			RingBufferMiB: config.RingBufferMiB, TLSTargets: config.TLSTargets,
			SSLLib: os.Getenv("AGENTPROV_SSL_LIB"), LibcLib: os.Getenv("AGENTPROV_LIBC_LIB"), GoTLSBin: os.Getenv("AGENTPROV_GO_TLS_BIN"),
			AutoTLS: enabled(config.AutoTLS), AppArmorState: enabled(config.AppArmorState), SeccompState: enabled(config.SeccompState),
			Diagnostics: diagnostics, Language: lang,
			OnCapabilities: func(report sensor.CapabilityReport) {
				capsMu.Lock()
				caps = report
				capsMu.Unlock()
				if err := saveSensorCapabilities(paths, report); err != nil {
					recordError(fmt.Errorf("persist execution capture capabilities: %w", err))
				}
			},
			OnReady: func() { readyOnce.Do(func() { close(ready) }) },
		})
	})
	go func() { workers.Wait(); close(r.done) }()
	timeout := time.NewTimer(time.Duration(config.StartupTimeoutSeconds) * time.Second)
	defer timeout.Stop()
	select {
	case <-ready:
		if ctx.Err() != nil {
			err = ctx.Err()
		} else if !r.Controller.Capabilities().Ready {
			err = fmt.Errorf("execution capture mandatory probes are not ready")
		} else {
			select {
			case <-r.failed:
				err = r.failure()
			default:
				return r, nil
			}
		}
	case <-r.failed:
		err = r.failure()
	case <-ctx.Done():
		err = ctx.Err()
	case <-timeout.C:
		err = fmt.Errorf("execution capture readiness timed out")
	}
	return nil, errors.Join(err, r.Close())
}

func (r *executionCaptureRuntime) failure() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

func (r *executionCaptureRuntime) Close() error {
	r.once.Do(func() {
		r.cancel()
		<-r.done
		stream := r.Controller.Stream
		flushErr := stream.Flush()
		ctx, cancel := context.WithTimeout(context.Background(), r.Controller.Timeout)
		drainErr := stream.Drain(ctx)
		cancel()
		r.closeErr = errors.Join(r.failure(), flushErr, drainErr, stream.Close())
	})
	return r.closeErr
}
