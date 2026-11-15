//go:build linux && (amd64 || arm64)

package sensor

import (
	"errors"
	"fmt"
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

func TestEventTimestampSurvivesClockReadPreemption(t *testing.T) {
	for _, delayedRead := range []int{1, 2} {
		t.Run(fmt.Sprintf("monotonic_read_%d", delayedRead), func(t *testing.T) {
			base := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
			elapsed := 10 * time.Second
			reads := 0
			got := eventWallTime(uint64(7*time.Second), func() time.Time { return base.Add(elapsed) }, func() (int64, error) {
				reads++
				if reads == delayedRead {
					elapsed += 8 * time.Millisecond
				}
				return int64(elapsed), nil
			})
			if !got.Equal(base.Add(7 * time.Second)) {
				t.Fatalf("scheduler delay shifted the event: got %v want %v", got, base.Add(7*time.Second))
			}
		})
	}
}

func TestEventTimestampMissingClockFallsBackToObservation(t *testing.T) {
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	for _, ktime := range []uint64{0, uint64(time.Second)} {
		reads := 0
		got := eventWallTime(ktime, func() time.Time { return now }, func() (int64, error) {
			reads++
			return 0, errors.New("clock unavailable")
		})
		if !got.Equal(now) || (ktime == 0 && reads != 0) {
			t.Fatalf("clock fallback: %v reads=%d", got, reads)
		}
	}
}

func TestNormalizedMachineIdentity(t *testing.T) {
	for _, bad := range []string{"", "uninitialized", "host-name", "00000000000000000000000000000000", "0123456789abcdef0123456789abcdeg"} {
		if got := normalizedMachineID(bad); got != "" {
			t.Fatalf("accepted invalid machine identity %q", got)
		}
	}
	if got := normalizedMachineID("0123456789ABCDEF0123456789ABCDEF\n"); got != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("machine identity=%q", got)
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
