//go:build linux

package runtimeadapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/byteyellow/agentprovenance/internal/runtimegate"
)

// processBirth reads only the exact root-namespace PID and nanosecond birth.
// The control dump may contain environment, so it never enters logs/evidence.
func (s Runsc) processBirth(ctx context.Context, pid int32) (int64, error) {
	raw, err := s.control(ctx, "--root="+s.Config.Root, "trace", "procfs", s.Config.ContainerID)
	if err != nil {
		return 0, fmt.Errorf("read runtime process birth: %w", err)
	}
	var found int64
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var p struct {
			Start  int64 `json:"clone_ts"`
			Status struct {
				PID int32 `json:"pid"`
			} `json:"status"`
		}
		if err := json.Unmarshal([]byte(line), &p); err != nil {
			return 0, fmt.Errorf("invalid runtime process identity")
		}
		if p.Status.PID == pid {
			if found != 0 || p.Start <= 0 {
				return 0, fmt.Errorf("conflicting runtime process identity")
			}
			found = p.Start
		}
	}
	if found == 0 {
		return 0, fmt.Errorf("runtime process birth missing")
	}
	return found, nil
}

func (s Runsc) runGated(ctx context.Context, r Request, started func(Execution) error) (Execution, error) {
	return s.runPrivateGate(ctx, r, started, runtimegate.Entry)
}

func (s Runsc) runPrivateGate(ctx context.Context, r Request, started func(Execution) error, entry string) (Execution, error) {
	e := NewExecution(s.Binding, r)
	e.RuntimeRelease = s.Config.RuntimeRelease
	e.Gaps = []string{"command_capture_watermark_unavailable", "external_container_execution_untracked"}
	timeout := s.Options.Timeout
	if timeout == 0 {
		timeout = record.DefaultExecTimeout
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	dir, err := os.MkdirTemp(s.StateDir, "runsc-gated-")
	if err != nil {
		return e, err
	}
	defer os.RemoveAll(dir)
	gateRead, gateWrite, err := os.Pipe()
	if err != nil {
		return e, err
	}
	defer gateRead.Close()
	defer gateWrite.Close()
	helper, err := openTrustedFile(s.GateBinary)
	if err != nil {
		return e, err
	}
	defer helper.Close()
	pidFile := filepath.Join(dir, "internal.pid")
	args := []string{"--root=" + s.Config.Root, "exec", "--new-pidns", "--internal-pid-file=" + pidFile,
		"--cwd=" + s.Config.Workdir, "--pass-fd=3:3", "--exec-fd=4", s.Config.ContainerID, "agentprov", entry}
	args = append(args, r.Command.Command...)
	cmd := exec.CommandContext(ctx, s.Config.Binary, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.ExtraFiles = []*os.File{gateRead, helper}
	cmd.Stdout, cmd.Stderr = r.Command.Stdout, r.Command.Stderr
	cmd.WaitDelay = time.Second
	if err := cmd.Start(); err != nil {
		return e, err
	}
	gateRead.Close()
	helper.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var admissionErr error
	gateDeadline := time.Now().Add(10 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var waitErr error
wait:
	for {
		select {
		case waitErr = <-done:
			break wait
		case <-ticker.C:
			if e.GateReleased || admissionErr != nil {
				continue
			}
			if time.Now().After(gateDeadline) {
				admissionErr = fmt.Errorf("runtime identity gate exceeded 10s")
				gateWrite.Close()
				_ = cmd.Process.Kill()
				continue
			}
			raw, err := readPrivatePID(pidFile)
			if err != nil {
				continue
			}
			pid, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 32)
			if err != nil || pid <= 0 {
				continue
			}
			probeCtx, stop := context.WithTimeout(ctx, 5*time.Second)
			born, err := s.processBirth(probeCtx, int32(pid))
			stop()
			if err == nil {
				lifecycle, checkErr := readRunscLifecycle(s.Config.Root, s.Config.ContainerID)
				if checkErr != nil || lifecycle.CreatedAt != s.Config.StateCreated {
					err = fmt.Errorf("runtime container lifecycle changed before gate release")
				}
			}
			if err == nil {
				e.SentryPID, e.SentryStartNS = int32(pid), born
				e.SentryPIDBasis = "private_exec_fd_gate_and_runsc_procfs"
				e.State = "running"
				if started == nil {
					err = fmt.Errorf("controlled runtime execution requires a durable identity checkpoint")
				} else {
					err = started(e)
				}
			}
			if err == nil {
				err = ctx.Err()
			}
			if err == nil {
				_, err = gateWrite.Write([]byte{0xa5})
				if err == nil {
					e.Started, e.GateReleased = true, true
				}
			}
			gateWrite.Close()
			if err != nil {
				admissionErr = err
				// Closing the private pipe denies dispatch; killing the host
				// control transport alone is never a workload completion proof.
				_ = cmd.Process.Kill()
			}
		}
	}
	if admissionErr != nil || ctx.Err() != nil || !e.GateReleased || waitErr != nil {
		e.State = "unknown"
		if !e.GateReleased {
			e.State = "failed"
			e.Gaps = append(e.Gaps, "controlled_gate_not_released")
			if admissionErr == nil {
				admissionErr = fmt.Errorf("runtime gate did not release the workload")
			}
		} else {
			e.Gaps = append(e.Gaps, "workload_completion_unknown")
			if ctx.Err() != nil {
				e.Gaps = append(e.Gaps, "transport_stopped_workload_stop_unconfirmed")
			}
		}
		return e, errors.Join(admissionErr, ctx.Err(), waitErr)
	}
	zero := 0
	e.State, e.ExitCode = "succeeded", &zero
	return e, nil
}
