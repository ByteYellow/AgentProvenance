package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/handoff"
	"github.com/byteyellow/agentprovenance/internal/i18n"
	"github.com/byteyellow/agentprovenance/internal/sensor"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestExecutionCaptureStartupAndLifetime(t *testing.T) {
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := make(chan struct{})
	r, err := startExecutionCapture(ctx, db, paths, handoff.CaptureConfig{Mode: "native"}, i18n.English, io.Discard,
		func(out io.Writer, options sensor.Options) error {
			defer close(stopped)
			if options.Checkpointer == nil || !options.ContextOnly || !options.AutoTLS || !options.AppArmorState || !options.SeccompState || options.RingBufferMiB != 64 {
				return errors.New("incorrect native options")
			}
			options.OnCapabilities(sensor.CapabilityReport{Ready: true, Status: "ready"})
			options.OnReady()
			<-options.Context.Done()
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := os.Stat(filepath.Join(paths.Logs, "sensor-capabilities.json")); err != nil {
		t.Fatal(err)
	}
	// The executor must still be able to close its capture interval after its
	// own context is cancelled. Only explicit runtime Close stops this sensor.
	cancel()
	select {
	case <-stopped:
		t.Fatal("capture stopped before the executor could finish")
	default:
	}
	if _, err := startExecutionCapture(context.Background(), db, paths, handoff.CaptureConfig{Mode: "native"}, i18n.English,
		io.Discard, func(io.Writer, sensor.Options) error { t.Error("started a second collector"); return nil }); err == nil {
		t.Fatal("second collector accepted")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	default:
		t.Fatal("Close returned before sensor stopped")
	}
	if running, err := telemetry.NativeStreamRunning(paths); err != nil || running {
		t.Fatalf("capture lock retained: running=%t err=%v", running, err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestExecutionCaptureStartupFailuresReleaseStore(t *testing.T) {
	for _, mode := range []string{"probe_failure", "false_ready", "capability_write_failure", "cancelled", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			paths, err := store.Init(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			db, err := store.Open(paths)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if mode == "capability_write_failure" {
				if err := os.Mkdir(filepath.Join(paths.Logs, "sensor-capabilities.json"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stopped := make(chan struct{})
			_, err = startExecutionCapture(ctx, db, paths, handoff.CaptureConfig{Mode: "native", StartupTimeoutSeconds: 1}, i18n.English,
				io.Discard, func(_ io.Writer, options sensor.Options) error {
					defer close(stopped)
					switch mode {
					case "probe_failure":
						return errors.New("probe attachment failed")
					case "false_ready":
						options.OnCapabilities(sensor.CapabilityReport{Ready: false})
						options.OnReady()
					case "capability_write_failure":
						options.OnCapabilities(sensor.CapabilityReport{Ready: true})
						options.OnReady()
					case "cancelled":
						cancel()
					}
					<-options.Context.Done()
					return nil
				})
			if err == nil {
				t.Fatal("failed capture startup reported ready")
			}
			select {
			case <-stopped:
			default:
				t.Fatal("startup failure left sensor running")
			}
			if running, err := telemetry.NativeStreamRunning(paths); err != nil || running {
				t.Fatalf("startup failure retained lock: %t %v", running, err)
			}
		})
	}
}

func TestExecutionCaptureUnexpectedExitSignalsDaemon(t *testing.T) {
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exit := make(chan struct{})
	r, err := startExecutionCapture(context.Background(), db, paths, handoff.CaptureConfig{Mode: "native"}, i18n.English,
		io.Discard, func(_ io.Writer, options sensor.Options) error {
			options.OnCapabilities(sensor.CapabilityReport{Ready: true})
			options.OnReady()
			select {
			case <-exit:
			case <-options.Context.Done():
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	close(exit)
	select {
	case <-r.failed:
	case <-time.After(2 * time.Second):
		t.Fatal("capture exit did not signal daemon shutdown")
	}
	if err := r.Close(); err == nil || !strings.Contains(err.Error(), "stopped unexpectedly") {
		t.Fatalf("unexpected capture exit hidden: %v", err)
	}
}

func TestDaemonNativeCaptureRequiresLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("non-Linux startup boundary")
	}
	root := t.TempDir()
	config := filepath.Join(root, "execution.json")
	if err := os.WriteFile(config, []byte(`{"target":{"producer_id":"vm","instance_id":"one","generation":"first"},"caller":{"principal_id":"router","producer_id":"mac","namespace":"user"},"capture":{"mode":"native"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := NewRootCommand()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--data-dir", filepath.Join(root, "store"), "daemon", "serve", "--execution-config", config, "--auth-token", "fixture-token", "--listen", "127.0.0.1:0"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := cmd.ExecuteContext(ctx); err == nil || !strings.Contains(err.Error(), "requires Linux") {
		t.Fatalf("unexpected unsupported-platform result: %v", err)
	}
}
