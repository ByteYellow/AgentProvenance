//go:build linux && (amd64 || arm64)

package sensor

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

func TestLiveKernelCheckpointFullRingRetainsOrder(t *testing.T) {
	if os.Getenv("AGENTPROV_TEST_SENSOR_BOUNDARY") != "1" {
		t.Skip("set AGENTPROV_TEST_SENSOR_BOUNDARY=1 with Linux BPF permissions")
	}
	events, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.RingBuf, MaxEntries: 4096})
	if err != nil {
		t.Fatal(err)
	}
	defer events.Close()
	marker, err := newKernelCheckpointer(events)
	if err != nil {
		t.Fatal(err)
	}
	defer marker.close()
	rd, err := ringbuf.NewReader(events)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	rd.SetDeadline(time.Now().Add(3 * time.Second))
	for seq := uint64(1); seq <= 4; seq++ {
		if err := marker.inject(context.Background(), seq); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := marker.inject(ctx, 5); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("full ring pretended to checkpoint: %v", err)
	}
	for seq := uint64(1); seq <= 4; seq++ {
		record, err := rd.Read()
		if err != nil {
			t.Fatal(err)
		}
		e, err := decodeSensorEvent(record.RawSample)
		if err != nil || e.Kind != eventCaptureBoundary || e.Conn != seq || e.KtimeNs == 0 || e.Pid != 0 {
			t.Fatalf("marker %d: %+v %v", seq, e, err)
		}
	}
	if err := marker.inject(context.Background(), 6); err != nil {
		t.Fatal(err)
	}
	record, err := rd.Read()
	if err != nil {
		t.Fatal(err)
	}
	e, err := decodeSensorEvent(record.RawSample)
	if err != nil || e.Conn != 6 {
		t.Fatalf("timed-out marker appeared after retry: %+v %v", e, err)
	}
}
