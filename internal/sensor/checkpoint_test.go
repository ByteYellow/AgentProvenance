package sensor

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func checkpointTestPrepare(ctx context.Context, b *CaptureBoundary, callback func(CaptureBoundary) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.ObservedAt = time.Now().UTC()
	if callback != nil {
		return callback(*b)
	}
	return nil
}

func TestCheckpointReadinessAndFailure(t *testing.T) {
	for _, c := range []*Checkpointer{nil, {}, NewCheckpointer()} {
		if _, err := c.Checkpoint(context.Background(), nil); !errors.Is(err, ErrCheckpointNotReady) {
			t.Fatalf("readiness error=%v", err)
		}
	}
	c := NewCheckpointer()
	if err := c.bind(func(context.Context, uint64) error { return fmt.Errorf("injection failed") }); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Checkpoint(context.Background(), func(CaptureBoundary) error { t.Fatal("failed injection ran callback"); return nil }); err == nil || err.Error() != "injection failed" {
		t.Fatalf("injection error=%v", err)
	}
	c.stop()
	c.stop()
	if _, err := c.Checkpoint(context.Background(), nil); !errors.Is(err, ErrCheckpointStopped) {
		t.Fatalf("stopped collector error=%v", err)
	}
	if err := c.bind(func(context.Context, uint64) error { return nil }); err == nil {
		t.Fatal("reused collector generation")
	}
}

func TestCheckpointLateMarkerCannotCompleteNewRequest(t *testing.T) {
	c := NewCheckpointer()
	defer c.stop()
	issued := make(chan uint64, 2)
	if err := c.bind(func(_ context.Context, seq uint64) error { issued <- seq; return nil }); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.Checkpoint(ctx, func(CaptureBoundary) error { t.Error("expired callback ran"); return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline=%v", err)
	}
	old := <-issued
	done := make(chan checkpointResult, 1)
	go func() { b, err := c.Checkpoint(context.Background(), nil); done <- checkpointResult{b, err} }()
	current := <-issued
	c.consume(old, CaptureBoundary{KernelTimeNS: 100}, checkpointTestPrepare)
	select {
	case result := <-done:
		t.Fatalf("late marker completed new request: %+v", result)
	default:
	}
	c.consume(current, CaptureBoundary{KernelTimeNS: 200}, checkpointTestPrepare)
	result := <-done
	if result.err != nil || result.boundary.Sequence != current || result.boundary.KernelTimeNS != 200 || result.boundary.CollectorID != c.epoch {
		t.Fatalf("current marker=%+v", result)
	}
}

func TestCheckpointSerializesAndRetainsCallbackErrors(t *testing.T) {
	c := NewCheckpointer()
	defer c.stop()
	if err := c.bind(func(_ context.Context, seq uint64) error {
		go c.consume(seq, CaptureBoundary{KernelTimeNS: seq}, checkpointTestPrepare)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var callbacks atomic.Uint64
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b, err := c.Checkpoint(context.Background(), func(b CaptureBoundary) error {
				if n := callbacks.Add(1); n != b.Sequence {
					return fmt.Errorf("sequence=%d callback=%d", b.Sequence, n)
				}
				return nil
			})
			if err != nil || b.Sequence == 0 || b.Boundary != "ring_and_decoder" || b.ObservedAt.IsZero() {
				t.Errorf("checkpoint=%+v error=%v", b, err)
			}
		}()
	}
	wg.Wait()
	if callbacks.Load() != 12 {
		t.Fatal("lost callbacks")
	}
	want := errors.New("snapshot write failed")
	if _, err := c.Checkpoint(context.Background(), func(CaptureBoundary) error { return want }); !errors.Is(err, want) {
		t.Fatalf("callback failure=%v", err)
	}
}

func TestCheckpointCancellationWaitsForStartedCallback(t *testing.T) {
	c := NewCheckpointer()
	defer c.stop()
	if err := c.bind(func(_ context.Context, seq uint64) error {
		go c.consume(seq, CaptureBoundary{}, checkpointTestPrepare)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, release, returned := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var callbackReturned atomic.Bool
	go func() {
		_, err := c.Checkpoint(ctx, func(CaptureBoundary) error {
			close(started)
			<-release
			callbackReturned.Store(true)
			return nil
		})
		returned <- err
	}()
	<-started
	cancel()
	select {
	case err := <-returned:
		t.Errorf("returned while callback still owned caller data: %v", err)
	default:
	}
	close(release)
	if err := <-returned; !errors.Is(err, context.Canceled) || !callbackReturned.Load() {
		t.Fatalf("callback cancellation=%v completed=%v", err, callbackReturned.Load())
	}
}

func TestCheckpointStopWakesPendingRequest(t *testing.T) {
	c := NewCheckpointer()
	issued := make(chan struct{})
	if err := c.bind(func(context.Context, uint64) error { close(issued); return nil }); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := c.Checkpoint(context.Background(), nil); done <- err }()
	<-issued
	c.stop()
	if err := <-done; !errors.Is(err, ErrCheckpointStopped) {
		t.Fatalf("stop error=%v", err)
	}
}
