package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/handoff"
	"github.com/byteyellow/agentprovenance/internal/runtimeadapter"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func readExecutionBackendConfig(name string) (handoff.Config, error) {
	f, err := os.Open(name)
	if err != nil {
		return handoff.Config{}, err
	}
	c, readErr := handoff.ReadConfig(f)
	if err := errors.Join(readErr, f.Close()); err != nil {
		return c, err
	}
	if c.Backend != nil && c.Backend.Mode != "native" {
		// Decode the checked descriptor's bytes, not a previous untrusted read.
		name, err = filepath.Abs(name)
		if err != nil {
			return c, err
		}
		raw, err := runtimeadapter.ReadTrustedFile(name, 64<<10)
		if err != nil {
			return c, err
		}
		return handoff.ReadConfig(bytes.NewReader(raw))
	}
	return c, nil
}

func configureExecutionBackend(e *handoff.Executor, c handoff.Config) error {
	if c.Backend == nil {
		return nil
	}
	b := runtimeadapter.Binding{Target: runtimeadapter.Target(c.Target), Mode: c.Backend.Mode}
	e.Binding = &b
	if c.Backend.Guest != nil {
		if b.Mode != "guest" {
			return fmt.Errorf("guest platform identity requires guest execution mode")
		}
		if err := c.Backend.Guest.Validate(); err != nil {
			return err
		}
		boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
		if err != nil {
			return fmt.Errorf("read guest kernel boot identity: %w", err)
		}
		if strings.TrimSpace(string(boot)) != c.Backend.Guest.GuestBootID {
			return fmt.Errorf("guest kernel boot identity does not match the trusted platform binding")
		}
		b = b.WithGuest(*c.Backend.Guest)
	}
	if b.Mode == "native" || b.Mode == "guest" {
		return nil
	}
	if b.Mode != "runsc" || c.Backend.Runsc == nil {
		return fmt.Errorf("invalid runtime execution backend configuration")
	}
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return fmt.Errorf("runsc execution requires Linux amd64 or arm64")
	}
	runsc := *c.Backend.Runsc
	b.ContainerID, b.StateCreated = runsc.ContainerID, runsc.StateCreated
	stateDir := filepath.Join(e.Paths.Root, "runtime-adapter")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	if err := runtimeadapter.ValidateTrustedPath(stateDir, true); err != nil {
		return err
	}
	e.Backend = runtimeadapter.Runsc{Binding: b, Config: runsc, Options: e.Options, StateDir: stateDir}
	if c.Backend.SecCheck != nil {
		capture := *c.Backend.SecCheck
		e.RuntimeCapture = runtimeadapter.SecCheck{Target: b.Target, Receiver: capture.Target,
			ReadStatus: func(ctx context.Context) (telemetry.SecCheckCollectStatus, error) {
				if err := ctx.Err(); err != nil {
					return telemetry.SecCheckCollectStatus{}, err
				}
				return runtimeadapter.ReadSecCheckStatus(capture.StatusFile)
			}}
	}
	return nil
}
