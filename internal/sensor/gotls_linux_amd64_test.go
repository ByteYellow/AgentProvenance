package sensor

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestAMD64QueuedEventRetainsCaptureTime(t *testing.T) {
	var monotonic unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &monotonic); err != nil {
		t.Fatal(err)
	}
	want := time.Now().Add(-2 * time.Second)
	event := sensorbpfSensorEvent{Kind: eventExec, KtimeNs: uint64(monotonic.Nano() - int64(2*time.Second))}
	row := normalize(event, newCgroupResolver())
	got, err := time.Parse(time.RFC3339Nano, row["timestamp"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if delta := got.Sub(want); delta < -100*time.Millisecond || delta > 100*time.Millisecond {
		t.Fatalf("queued event timestamp = %v, want capture time near %v", got, want)
	}
}

func TestAMD64ObjectContainsSeparateGoABIProbe(t *testing.T) {
	spec, err := loadSensorbpf()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"handle_go_tls_write", "handle_ssl_write", "handle_ssl_read_exit", "handle_getaddrinfo"} {
		if spec.Programs[name] == nil {
			t.Fatalf("amd64 object lacks %s", name)
		}
	}
	if spec.Programs["handle_go_tls_write"].SectionName == spec.Programs["handle_ssl_write"].SectionName {
		t.Fatal("Go and C must use different entry probes on amd64")
	}
}
