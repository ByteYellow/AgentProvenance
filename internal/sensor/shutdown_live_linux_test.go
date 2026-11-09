//go:build linux && (amd64 || arm64)

package sensor

import (
	"bufio"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type shutdownEventCounter struct{ records atomic.Uint64 }

func (w *shutdownEventCounter) Write(p []byte) (int, error) {
	w.records.Add(1)
	return len(p), nil
}

func TestLiveSensorShutdown(t *testing.T) {
	if os.Getenv("AGENTPROV_LIVE_SHUTDOWN") != "1" {
		t.Skip("set AGENTPROV_LIVE_SHUTDOWN=1 on a disposable Linux host with eBPF privileges and cc")
	}
	bin := buildTLSCFixture(t, "sensor_shutdown.c")
	for _, autoTLS := range []bool{false, true} {
		name := "syscalls"
		if autoTLS {
			name = "syscalls-and-tls"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ready, done := make(chan struct{}), make(chan struct{})
			var sensorErr error
			out := &shutdownEventCounter{}
			go func() {
				defer close(done)
				sensorErr = RunWithOptions(out, Options{Context: ctx, RingBufferMiB: 1,
					AutoTLS: autoTLS, Diagnostics: io.Discard, OnReady: func() { close(ready) }})
			}()
			t.Cleanup(func() {
				cancel()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
					t.Error("sensor did not stop after workload cleanup")
				}
			})
			select {
			case <-ready:
			case <-done:
				t.Fatalf("sensor startup: %v", sensorErr)
			case <-time.After(15 * time.Second):
				t.Fatal("sensor startup timed out")
			}

			cmd := exec.Command(bin, filepath.Join(t.TempDir(), "load"))
			control, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer control.Close()
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			stopWorkload := sync.OnceFunc(func() { _ = control.Close(); _ = cmd.Wait() })
			defer stopWorkload()
			if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "ready\n" {
				t.Fatalf("workload startup: %q %v", line, err)
			}
			// Keep filling the ring while cancellation is handled. A flush without
			// detaching producers never reaches the end under this workload.
			time.Sleep(250 * time.Millisecond)
			before := out.records.Load()
			if before == 0 {
				t.Fatal("no events before shutdown")
			}
			started := time.Now()
			cancel()
			select {
			case <-done:
				if sensorErr != nil {
					t.Fatal(sensorErr)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("sensor kept capturing under active load: %d -> %d records", before, out.records.Load())
			}
			t.Logf("stopped under active load in %s; %d records before cancellation, %d after drain", time.Since(started), before, out.records.Load())
		})
	}
}
