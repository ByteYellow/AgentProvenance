package runtimeadapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/byteyellow/agentprovenance/internal/seccheck"
)

// RunscConfig pins one container and its trusted runtime metadata creation value.
// The launcher must retire this binding before replacing/restoring the container.
type RunscConfig struct {
	Binary            string `json:"binary"`
	Root              string `json:"root"`
	ContainerID       string `json:"container_id"`
	StateCreated      string `json:"state_created"`
	RuntimeRelease    string `json:"runtime_release"`
	Workdir           string `json:"workdir"`
	AllowUncorrelated bool   `json:"allow_uncorrelated"`
}

func (c RunscConfig) Validate() error {
	if c.RuntimeRelease != seccheck.RuntimeRelease || !safeName(c.ContainerID) || !c.AllowUncorrelated {
		return fmt.Errorf("runsc requires the pinned runtime, a fixed container and allow_uncorrelated=true")
	}
	if _, err := time.Parse(time.RFC3339Nano, c.StateCreated); err != nil {
		return fmt.Errorf("runsc requires state_created from the trusted container lifecycle")
	}
	for _, p := range []string{c.Binary, c.Root, c.Workdir} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsAny(p, "\x00\r\n") {
			return fmt.Errorf("runsc configuration requires clean absolute paths")
		}
	}
	return nil
}

type Runsc struct {
	Binding Binding
	Config  RunscConfig
	Options record.Options
	// StateDir is private host-side scratch space, outside the workload mount.
	StateDir string
	// GateBinary is the root-owned agentprov executable passed by FD. Empty
	// retains the legacy PID-only adapter for existing embedded callers.
	GateBinary string
}

func (s Runsc) Admit(ctx context.Context, r Request) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if _, err := s.Binding.Resolve(ctx, r.Target); err != nil {
		return err
	}
	if err := s.Config.Validate(); err != nil {
		return err
	}
	if s.Binding.Mode != "runsc" || s.Binding.ContainerID != s.Config.ContainerID || s.Binding.StateCreated != s.Config.StateCreated {
		return fmt.Errorf("runsc platform binding mismatch")
	}
	if !r.Command.DisableSnapshot {
		return fmt.Errorf("runsc requires disable_snapshot=true; host snapshots do not describe the container workspace")
	}
	if s.Options.Foreground || s.Options.InheritFullEnv || s.Options.AllowAnyWorkdir {
		return fmt.Errorf("runsc does not support foreground, inherited host environment or unrestricted workdir")
	}
	if !s.Options.AllowShell {
		base := strings.ToLower(strings.TrimSuffix(path.Base(r.Command.Command[0]), ".exe"))
		switch base {
		case "sh", "bash", "zsh", "dash", "fish", "ksh", "csh", "tcsh", "pwsh", "powershell", "cmd":
			return fmt.Errorf("runsc policy: refusing shell interpreter without record-allow-shell")
		}
	}
	// No host-side symlink walk can establish a guest path. The fixed workdir is
	// launcher-owned; accepting subpaths would silently weaken native confinement.
	if r.Command.Workdir != "" && r.Command.Workdir != s.Config.Workdir {
		return fmt.Errorf("runsc workdir must equal the configured container workdir")
	}
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return fmt.Errorf("runsc execution requires Linux amd64 or arm64")
	}
	if err := ValidateTrustedPath(s.Config.Binary, false); err != nil {
		return err
	}
	if err := ValidateTrustedPath(s.Config.Root, true); err != nil {
		return err
	}
	if err := ValidateTrustedPath(s.StateDir, true); err != nil {
		return err
	}
	if s.GateBinary != "" {
		if err := ValidateTrustedPath(s.GateBinary, false); err != nil {
			return fmt.Errorf("runsc gate executable: %w", err)
		}
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	version, err := s.control(probeCtx, "--version")
	if err != nil || !strings.HasPrefix(string(version), "runsc version "+s.Config.RuntimeRelease+"\n") {
		return fmt.Errorf("runsc binary version does not match the pinned runtime")
	}
	state, err := s.control(probeCtx, "--root="+s.Config.Root, "state", s.Config.ContainerID)
	if err != nil {
		return fmt.Errorf("read runsc container state: %w", err)
	}
	if err := s.validateState(state); err != nil {
		return err
	}
	lifecycle, err := readRunscLifecycle(s.Config.Root, s.Config.ContainerID)
	if err != nil {
		return fmt.Errorf("read runsc container lifecycle: %w", err)
	}
	if lifecycle.CreatedAt != s.Config.StateCreated {
		return fmt.Errorf("runsc container lifecycle or generation mismatch")
	}
	return nil
}

func (s Runsc) validateState(state []byte) error {
	var current struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		PID    int    `json:"pid"`
	}
	if err := json.Unmarshal(state, &current); err != nil {
		return fmt.Errorf("decode runsc state: %w", err)
	}
	if current.ID != s.Config.ContainerID || current.PID <= 0 || current.Status != "running" {
		return fmt.Errorf("runsc container lifecycle or generation mismatch")
	}
	return nil
}

// OCI state has no creation timestamp. The pinned runsc version atomically
// replaces its root-owned metadata file and stores CreatedAt there. Decode only
// lifecycle fields: the rest of that file can contain workload environment.
type runscLifecycle struct {
	ID        string `json:"id"`
	CreatedAt string `json:"createdAt"`
	Sandbox   struct {
		ID string `json:"id"`
	} `json:"sandbox"`
}

func decodeRunscLifecycle(raw []byte, containerID, filename string) (runscLifecycle, error) {
	var lifecycle runscLifecycle
	if err := json.Unmarshal(raw, &lifecycle); err != nil {
		return lifecycle, fmt.Errorf("decode runsc lifecycle: %w", err)
	}
	if lifecycle.ID != containerID || !safeName(lifecycle.Sandbox.ID) ||
		filename != containerID+"_sandbox:"+lifecycle.Sandbox.ID+".state" {
		return lifecycle, fmt.Errorf("runsc lifecycle metadata identity mismatch")
	}
	if _, err := time.Parse(time.RFC3339Nano, lifecycle.CreatedAt); err != nil {
		return lifecycle, fmt.Errorf("runsc lifecycle metadata has no valid creation time")
	}
	return lifecycle, nil
}

func readRunscLifecycle(root, containerID string) (runscLifecycle, error) {
	if !safeName(containerID) {
		return runscLifecycle{}, fmt.Errorf("invalid runsc container identity")
	}
	if err := ValidateTrustedPath(root, true); err != nil {
		return runscLifecycle{}, err
	}
	files, err := filepath.Glob(filepath.Join(root, containerID+"_sandbox:*.state"))
	if err != nil || len(files) != 1 {
		return runscLifecycle{}, fmt.Errorf("runsc requires exactly one container lifecycle metadata file")
	}
	raw, err := ReadTrustedFile(files[0], 4<<20)
	if err != nil {
		return runscLifecycle{}, err
	}
	return decodeRunscLifecycle(raw, containerID, filepath.Base(files[0]))
}

type boundedBuffer struct{ data []byte }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > (64<<10)-len(b.data) {
		return 0, fmt.Errorf("runtime control output exceeds 64 KiB")
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

func (s Runsc) control(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, s.Config.Binary, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.WaitDelay = time.Second
	out := &boundedBuffer{}
	cmd.Stdout, cmd.Stderr = out, io.Discard
	err := cmd.Run()
	return out.data, err
}

func (s Runsc) Run(ctx context.Context, r Request, started func(Execution) error) (Execution, error) {
	if err := s.Admit(ctx, r); err != nil {
		return NewExecution(s.Binding, r), err
	}
	if s.GateBinary != "" {
		return s.runGated(ctx, r, started)
	}
	return s.run(ctx, r, started)
}

func (s Runsc) run(ctx context.Context, r Request, started func(Execution) error) (Execution, error) {
	e := NewExecution(s.Binding, r)
	e.RuntimeRelease = s.Config.RuntimeRelease
	e.Gaps = []string{"shared_call_identity_unavailable", "sentry_process_birth_unlinked", "external_container_execution_untracked"}
	timeout := s.Options.Timeout
	if timeout == 0 {
		timeout = record.DefaultExecTimeout
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	dir, err := os.MkdirTemp(s.StateDir, "runsc-exec-")
	if err != nil {
		return e, err
	}
	defer os.RemoveAll(dir)
	pidFile := filepath.Join(dir, "internal.pid")
	args := []string{"--root=" + s.Config.Root, "exec", "--new-pidns", "--internal-pid-file=" + pidFile, "--cwd=" + s.Config.Workdir, s.Config.ContainerID}
	args = append(args, r.Command.Command...)
	cmd := exec.CommandContext(ctx, s.Config.Binary, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.Stdout, cmd.Stderr = r.Command.Stdout, r.Command.Stderr
	cmd.WaitDelay = time.Second
	if err := ctx.Err(); err != nil {
		return e, err
	}
	if err := cmd.Start(); err != nil {
		return e, err
	}
	// The durable handoff claim precedes dispatch. Only the runtime's internal
	// PID file can promote the attempt to running, never the host transport PID.
	e.Started = true
	var callbackErr error
	publishPID := func() {
		if e.SentryPID != 0 {
			return
		}
		if raw, err := readPrivatePID(pidFile); err == nil {
			if pid, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 32); err == nil && pid > 0 {
				e.SentryPID, e.SentryPIDBasis = int32(pid), "runsc_internal_pid_file"
				e.State = "running"
				if started != nil {
					callbackErr = started(e)
					if callbackErr != nil {
						_ = cmd.Process.Kill()
					}
				}
			}
		}
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	var waitErr error
wait:
	for {
		select {
		case waitErr = <-done:
			publishPID()
			break wait
		case <-ticker.C:
			publishPID()
		}
	}
	if callbackErr != nil || ctx.Err() != nil || e.SentryPID == 0 || waitErr != nil {
		e.State = "unknown"
		e.Gaps = append(e.Gaps, "workload_completion_unknown")
		if ctx.Err() != nil || callbackErr != nil {
			e.Gaps = append(e.Gaps, "transport_stopped_workload_stop_unconfirmed")
		}
		if e.SentryPID == 0 {
			e.Gaps = append(e.Gaps, "runtime_task_identity_missing")
		}
		// runsc's control failure and a nonzero workload exit share an exit-code
		// channel. Do not manufacture a workload result from that ambiguity.
		if waitErr != nil && ctx.Err() == nil {
			e.Gaps = append(e.Gaps, "runtime_failure_or_workload_exit")
		}
		return e, errors.Join(callbackErr, ctx.Err(), waitErr)
	}
	zero := 0
	e.State, e.ExitCode = "succeeded", &zero
	return e, nil
}
