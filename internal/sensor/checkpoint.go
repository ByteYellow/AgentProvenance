package sensor

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/byteyellow/agentprovenance/internal/ids"
)

var (
	ErrCheckpointNotReady = errors.New("sensor checkpoint is not ready")
	ErrCheckpointStopped  = errors.New("sensor checkpoint collector has stopped")
)

// CaptureBoundary describes consumption through a marker in the sensor's shared
// kernel ring. Counters and pending buffers are collector-wide observations.
type CaptureBoundary struct {
	SchemaVersion     string    `json:"schema_version"`
	Boundary          string    `json:"boundary"`
	CollectorID       string    `json:"collector_id"`
	Sequence          uint64    `json:"sequence"`
	KernelTimeNS      uint64    `json:"kernel_time_ns"`
	ObservedAt        time.Time `json:"observed_at"`
	DecodedRecords    uint64    `json:"decoded_records"`
	KernelDrops       uint64    `json:"kernel_drops"`
	StateQueueDrops   uint64    `json:"state_queue_drops"`
	TLSLostStreams    uint64    `json:"tls_lost_streams"`
	TLSLostBytes      uint64    `json:"tls_lost_bytes"`
	PendingTLSStreams int       `json:"pending_tls_streams"`
	PendingTLSBytes   int       `json:"pending_tls_bytes"`
}

type checkpointResult struct {
	boundary CaptureBoundary
	err      error
}

type checkpointRequest struct {
	ctx      context.Context
	sequence uint64
	callback func(CaptureBoundary) error
	issued   chan struct{}
	issueErr error
	started  bool
	done     chan checkpointResult
}

// Checkpointer belongs to one RunWithOptions invocation. Checkpoint serializes
// callers, but does not detach probes or wait for an idle kernel ring.
type Checkpointer struct {
	mu       sync.Mutex
	serial   chan struct{}
	stopped  chan struct{}
	closed   bool
	epoch    string
	sequence uint64
	inject   func(context.Context, uint64) error
	pending  *checkpointRequest
}

func NewCheckpointer() *Checkpointer {
	return &Checkpointer{serial: make(chan struct{}, 1), stopped: make(chan struct{}), epoch: ids.New("sensor-boundary")}
}

func (c *Checkpointer) bind(inject func(context.Context, uint64) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.inject != nil || c.serial == nil || inject == nil {
		return fmt.Errorf("sensor checkpointer must be new and belong to one collector")
	}
	c.inject = inject
	return nil
}

func (c *Checkpointer) stop() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	close(c.stopped)
	c.mu.Unlock()
	// Wait for an in-flight injection before the caller releases its BPF maps.
	c.serial <- struct{}{}
	<-c.serial
}

// Checkpoint invokes callback in the decoder at the boundary, after prior JSON
// writes and scheduled procfs observations. A spool snapshot can be taken here.
// The callback must honor ctx, return promptly and not recurse into Checkpoint.
// TLS buffers remain intact and are reported separately. No callback survives
// this method's return, including on cancellation.
func (c *Checkpointer) Checkpoint(ctx context.Context, callback func(CaptureBoundary) error) (CaptureBoundary, error) {
	if c == nil || c.serial == nil {
		return CaptureBoundary{}, ErrCheckpointNotReady
	}
	if err := ctx.Err(); err != nil {
		return CaptureBoundary{}, err
	}
	if _, bounded := ctx.Deadline(); !bounded {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
	}
	select {
	case c.serial <- struct{}{}:
	case <-ctx.Done():
		return CaptureBoundary{}, ctx.Err()
	case <-c.stopped:
		return CaptureBoundary{}, ErrCheckpointStopped
	}
	defer func() { <-c.serial }()
	c.mu.Lock()
	if c.closed || c.inject == nil {
		err := ErrCheckpointNotReady
		if c.closed {
			err = ErrCheckpointStopped
		}
		c.mu.Unlock()
		return CaptureBoundary{}, err
	}
	if c.sequence == ^uint64(0) {
		c.mu.Unlock()
		return CaptureBoundary{}, fmt.Errorf("sensor checkpoint sequence exhausted")
	}
	c.sequence++
	r := &checkpointRequest{ctx: ctx, sequence: c.sequence, callback: callback,
		issued: make(chan struct{}), done: make(chan checkpointResult, 1)}
	c.pending = r
	inject := c.inject
	c.mu.Unlock()
	r.issueErr = inject(ctx, r.sequence)
	close(r.issued)
	finish := func(cause error) (CaptureBoundary, error) {
		c.mu.Lock()
		started := r.started
		if !started && c.pending == r {
			c.pending = nil
		}
		c.mu.Unlock()
		if started {
			result := <-r.done
			return result.boundary, errors.Join(cause, result.err)
		}
		return CaptureBoundary{}, cause
	}
	if r.issueErr != nil {
		return finish(r.issueErr)
	}
	select {
	case result := <-r.done:
		return result.boundary, result.err
	case <-ctx.Done():
		return finish(ctx.Err())
	case <-c.stopped:
		return finish(ErrCheckpointStopped)
	}
}

// consume runs only on the ordered decoder. A timed-out marker is discarded;
// it cannot complete a subsequent request or enter application telemetry.
func (c *Checkpointer) consume(sequence uint64, boundary CaptureBoundary, prepare func(context.Context, *CaptureBoundary, func(CaptureBoundary) error) error) {
	if c == nil {
		return
	}
	c.mu.Lock()
	r := c.pending
	if r == nil || r.sequence != sequence || r.started {
		c.mu.Unlock()
		return
	}
	r.started = true
	boundary.SchemaVersion = "agentprovenance.sensor_boundary/v1"
	boundary.Boundary, boundary.CollectorID, boundary.Sequence = "ring_and_decoder", c.epoch, sequence
	c.mu.Unlock()
	<-r.issued
	err := errors.Join(r.issueErr, r.ctx.Err())
	if err == nil {
		err = prepare(r.ctx, &boundary, r.callback)
	}
	c.mu.Lock()
	if c.pending == r {
		c.pending = nil
	}
	c.mu.Unlock()
	r.done <- checkpointResult{boundary, errors.Join(err, r.ctx.Err())}
}
