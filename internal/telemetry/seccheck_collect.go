package telemetry

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/byteyellow/agentprovenance/internal/ids"
	"github.com/byteyellow/agentprovenance/internal/seccheck"
	"github.com/byteyellow/agentprovenance/internal/store"
)

type SecCheckCollectOptions struct {
	Stream         NativeStreamOptions
	StatusInterval time.Duration
	DrainTimeout   time.Duration
}

type SecCheckTargetStatus struct {
	seccheck.Target
	State                string `json:"state"`
	ConnectionID         string `json:"connection_id,omitempty"`
	LastObservationAt    string `json:"last_observation_at,omitempty"`
	AcceptedRecords      uint64 `json:"accepted_records"`
	ReportedDrops        uint64 `json:"reported_dropped_events"`
	DropCounterDecreases uint64 `json:"drop_counter_decreases"`
	IdentityGapRecords   uint64 `json:"identity_gap_records"`
	LastDiagnostic       string `json:"last_diagnostic,omitempty"`
}

type SecCheckCollectStatus struct {
	SchemaVersion          string                 `json:"schema_version"`
	CollectorID            string                 `json:"collector_id"`
	GeneratedAt            string                 `json:"generated_at"`
	State                  string                 `json:"state"`
	Error                  string                 `json:"error,omitempty"`
	LastWorkerError        string                 `json:"last_worker_error,omitempty"`
	ExpectedRuntimeRelease string                 `json:"expected_runtime_release"`
	ProtocolVersion        uint32                 `json:"protocol_version"`
	Capabilities           seccheck.Capabilities  `json:"capabilities"`
	Targets                []SecCheckTargetStatus `json:"targets"`
	Spool                  NativeStreamStatus     `json:"node_spool"`
}

// CollectSecCheck owns the receiver set and one durable writer. Receiver state
// is live for this invocation; persisted stream evidence survives its lifetime.
func CollectSecCheck(ctx context.Context, db *sql.DB, paths store.Paths, config seccheck.CollectionConfig, opts SecCheckCollectOptions, report func(SecCheckCollectStatus) error) (resultErr error) {
	if err := config.Validate(); err != nil {
		return err
	}
	if runtime.GOOS != "linux" || (runtime.GOARCH != "arm64" && runtime.GOARCH != "amd64") {
		return fmt.Errorf("SecCheck reception requires Linux amd64 or arm64")
	}
	if opts.StatusInterval == 0 {
		opts.StatusInterval = 5 * time.Second
	}
	if opts.DrainTimeout == 0 {
		opts.DrainTimeout = 30 * time.Second
	}
	if opts.StatusInterval < 100*time.Millisecond || opts.StatusInterval > time.Minute || opts.DrainTimeout < time.Second || opts.DrainTimeout > 5*time.Minute {
		return fmt.Errorf("SecCheck status interval must be 100ms..1m and drain timeout 1s..5m")
	}
	stream, err := NewSecCheckStream(db, paths, opts.Stream)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, stream.Close()) }()
	collectorID := ids.New("seccheck")
	capabilities := seccheck.ReceiverCapabilities()
	state := make([]SecCheckTargetStatus, len(config.Targets))
	for i, target := range config.Targets {
		state[i] = SecCheckTargetStatus{Target: target, State: "starting"}
	}
	var mu sync.Mutex
	var workerError string
	var reportFailed bool
	status := func(phase string, failure error) error {
		if report == nil || reportFailed {
			return nil
		}
		mu.Lock()
		targets := append([]SecCheckTargetStatus(nil), state...)
		lastWorkerError := workerError
		mu.Unlock()
		lastError := ""
		if failure != nil {
			lastError = failure.Error()
		}
		readCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		spool, err := stream.Status(readCtx)
		if err != nil {
			return err
		}
		err = report(SecCheckCollectStatus{SchemaVersion: "agentprovenance.seccheck_status/v1", CollectorID: collectorID, GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano), State: phase, Error: lastError, LastWorkerError: lastWorkerError, ExpectedRuntimeRelease: config.RuntimeRelease, ProtocolVersion: seccheck.ProtocolVersion, Capabilities: capabilities, Targets: targets, Spool: spool})
		if err != nil {
			reportFailed = true
		}
		return err
	}
	if err := status("starting", nil); err != nil {
		return err
	}
	receiveCtx, stopReceivers := context.WithCancel(ctx)
	workerCtx, stopWorker := context.WithCancel(context.Background())
	defer stopReceivers()
	defer stopWorker()
	workerDone := make(chan error, 1)
	go func() {
		workerDone <- stream.Run(workerCtx, func(err error) { mu.Lock(); workerError = err.Error(); mu.Unlock() })
	}()
	ready := make(chan int, len(state))
	done := make(chan error, len(state))
	var receivers sync.WaitGroup
	lifecycle := func(i int, reason string, sequence uint64) error {
		t := config.Targets[i]
		return stream.Sink(t.RunID, t.Registration)(context.Background(), seccheck.Record{Kind: "stream", Reason: reason, Registration: t.Registration, ConnectionID: collectorID, Sequence: sequence, ReceivedAt: time.Now().UTC(), Capabilities: &capabilities})
	}
	for i, target := range config.Targets {
		i, target := i, target
		sink := stream.Sink(target.RunID, target.Registration)
		receiver := seccheck.Receiver{SocketPath: target.SocketPath, Registration: target.Registration,
			Ready: func() error {
				if err := lifecycle(i, "receiver_ready", 0); err != nil {
					return err
				}
				mu.Lock()
				state[i].State = "listening"
				mu.Unlock()
				ready <- i
				return nil
			},
			Sink: func(ctx context.Context, rec seccheck.Record) error {
				if err := sink(ctx, rec); err != nil {
					return err
				}
				mu.Lock()
				defer mu.Unlock()
				s := &state[i]
				s.AcceptedRecords++
				s.ConnectionID, s.LastObservationAt = rec.ConnectionID, rec.ReceivedAt.UTC().Format(time.RFC3339Nano)
				if rec.DroppedDelta != nil {
					s.ReportedDrops += *rec.DroppedDelta
				}
				if rec.DropCounterDecreased {
					s.DropCounterDecreases++
				}
				if rec.Kind == "event" && len(rec.Identity.Gaps) > 0 {
					s.IdentityGapRecords++
				}
				if rec.Kind == "stream" {
					s.LastDiagnostic = rec.Reason
					switch rec.Reason {
					case "connected":
						s.State = "connected"
					case "disconnected", "read_failed", "packet_truncated":
						s.State = "disconnected"
					case "peer_uid_rejected", "handshake_read_failed", "handshake_truncated", "handshake_rejected", "handshake_write_failed":
						s.State = "listening"
					}
				}
				return nil
			},
		}
		receivers.Add(1)
		go func() {
			defer receivers.Done()
			err := receiver.Serve(receiveCtx)
			mu.Lock()
			if err != nil && !errors.Is(err, context.Canceled) {
				state[i].State, state[i].LastDiagnostic = "failed", err.Error()
			}
			mu.Unlock()
			done <- err
		}()
	}
	ticker := time.NewTicker(opts.StatusInterval)
	defer ticker.Stop()
	workerFinished := false
	phase, listening := "starting", 0
loop:
	for {
		select {
		case <-ctx.Done():
			if !errors.Is(ctx.Err(), context.Canceled) {
				resultErr = ctx.Err()
			}
			break loop
		case err := <-done:
			if err == nil {
				err = fmt.Errorf("SecCheck receiver stopped unexpectedly")
			}
			if !errors.Is(err, context.Canceled) {
				resultErr = err
			}
			break loop
		case err := <-workerDone:
			workerFinished = true
			if err == nil {
				err = fmt.Errorf("SecCheck spool worker stopped unexpectedly")
			}
			resultErr = err
			break loop
		case <-ready:
			listening++
			if listening == len(state) {
				phase = "listening"
			}
			if err := status(phase, nil); err != nil {
				resultErr = err
				break loop
			}
		case <-ticker.C:
			if err := status(phase, nil); err != nil {
				resultErr = err
				break loop
			}
		}
	}
	stopReceivers()
	receivers.Wait()
	// Receiver errors can race cancellation. Preserve every terminal failure.
	for len(done) > 0 {
		if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
			resultErr = errors.Join(resultErr, err)
		}
	}
	stopWorker()
	if !workerFinished {
		resultErr = errors.Join(resultErr, <-workerDone)
	}
	resultErr = errors.Join(resultErr, status("draining", resultErr))
	for i := range state {
		mu.Lock()
		wasReady := state[i].State != "starting" && state[i].State != "failed"
		mu.Unlock()
		if wasReady {
			resultErr = errors.Join(resultErr, lifecycle(i, "receiver_stopped", 1))
		}
	}
	drainCtx, stopDrain := context.WithTimeout(context.Background(), opts.DrainTimeout)
	defer stopDrain()
	resultErr = errors.Join(resultErr, stream.Flush())
	resultErr = errors.Join(resultErr, stream.Drain(drainCtx))
	resultErr = errors.Join(resultErr, stream.Close())
	mu.Lock()
	for i := range state {
		if state[i].State != "failed" {
			state[i].State = "stopped"
		}
	}
	mu.Unlock()
	phase = "stopped"
	if resultErr != nil {
		phase = "failed"
	}
	return errors.Join(resultErr, status(phase, resultErr))
}
