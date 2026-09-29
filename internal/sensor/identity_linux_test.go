//go:build linux && (amd64 || arm64)

package sensor

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCapturedTimestampPrecedesDrain(t *testing.T) {
	var monotonic unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &monotonic); err != nil {
		t.Fatal(err)
	}
	at, err := time.Parse(time.RFC3339Nano, eventTimestamp(sensorbpfSensorEvent{KtimeNs: uint64(monotonic.Nano() - int64(2*time.Second))}))
	if err != nil || time.Since(at) < time.Second || time.Since(at) > 3*time.Second {
		t.Fatalf("lost kernel timestamp: %s %v", at, err)
	}
}

func TestOpenRetryRetainsObservedFailure(t *testing.T) {
	e := sensorbpfSensorEvent{Kind: eventOpen, Dport: 1, Conn: ^uint64(5)} // -ENXIO
	copy(e.Path[:], "/dev/tty")
	row := normalize(e, newCgroupResolver())
	if row["path"] != "/dev/tty" || row["path_observation"] != "syscall_exit_retry" || row["syscall_result"] != int64(-6) {
		t.Fatalf("retry became a successful write: %+v", row)
	}
}
