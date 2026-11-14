//go:build linux || darwin

package sensor

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

func TestSensorSignalOwnership(t *testing.T) {
	if mode := os.Getenv("AGENTPROV_TEST_SENSOR_SIGNAL"); mode != "" {
		parent, stopParent := signal.NotifyContext(context.Background(), syscall.SIGTERM)
		defer stopParent()
		ctx, stop := sensorContext(Options{Context: context.WithoutCancel(parent), ContextOnly: mode == "managed"})
		defer stop()
		fmt.Println("READY")
		select {
		case <-parent.Done():
		case <-time.After(3 * time.Second):
			t.Fatal("parent did not receive signal")
		}
		if mode == "managed" {
			select {
			case <-ctx.Done():
				t.Fatal("managed sensor stopped before supervisor closed the interval")
			case <-time.After(100 * time.Millisecond):
			}
			stop()
		}
		select {
		case <-ctx.Done():
		case <-time.After(3 * time.Second):
			t.Fatal("sensor did not stop")
		}
		return
	}
	for _, mode := range []string{"standalone", "managed"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSensorSignalOwnership$")
			cmd.Env = append(os.Environ(), "AGENTPROV_TEST_SENSOR_SIGNAL="+mode)
			out, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			cmd.Stderr = os.Stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cancel(); _ = cmd.Wait() }()
			scanner := bufio.NewScanner(out)
			if !scanner.Scan() || scanner.Text() != "READY" {
				t.Fatal("sensor fixture not ready")
			}
			if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			for scanner.Scan() {
				t.Log(scanner.Text())
			}
			if err := cmd.Wait(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
