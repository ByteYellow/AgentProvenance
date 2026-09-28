package launch

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// sensorProcess is the privileged system-side half of a launch run: a child
// `agentprov sensor stream` that loads the eBPF probes and ingests+correlates
// kernel events into the same store, keyed by the agent's cgroup. Running it as
// a subprocess (rather than in-process) gives launch a clean lifecycle -- it is
// stopped with SIGTERM at seal time -- and reuses the exact supervised-capture
// path the sensor already ships.
type sensorProcess struct {
	cmd       *exec.Cmd
	done      chan struct{}
	stopped   bool
	exitErr   error
	cleanStop bool
}

// startSensor launches the kernel sensor when the host can run it and returns
// the process (or nil), the resolved system tier ("kernel"|"none"), and an
// honest reason when it degrades. The reason is what the operator sees, so it
// names the actual blocker (wrong OS, missing CAP_BPF) rather than a generic
// failure.
func startSensor(selfExe, dataDir string, stderr io.Writer, tlsEnv []string) (*sensorProcess, string, message) {
	if runtime.GOOS != "linux" {
		return nil, "none", messagef("kernel telemetry requires Linux (this host is %s)", runtime.GOOS)
	}

	args := []string{"sensor", "stream"}
	if dataDir != "" {
		args = append([]string{"--data-dir", dataDir}, args...)
	}
	cmd := exec.Command(selfExe, args...)
	// New process group so a Ctrl-C on the launch group does not race our own
	// SIGTERM; we own this child's lifecycle explicitly.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// tlsEnv carries auto-detected AGENTPROV_SSL_LIB / AGENTPROV_GO_TLS_BIN so the
	// sensor points its TLS uprobes at this agent's stack without hand config.
	if len(tlsEnv) > 0 {
		cmd.Env = append(os.Environ(), tlsEnv...)
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, "none", messagef("cannot capture sensor stderr: %s", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, "none", messagef("sensor failed to start: %s", err)
	}

	var sink strings.Builder
	ready := make(chan struct{}, 1)
	scanned := make(chan struct{})
	go func() { scanReady(stderrPipe, ready, &sink); close(scanned) }()

	done := make(chan struct{})
	sp := &sensorProcess{cmd: cmd, done: done}
	go func() { sp.exitErr = cmd.Wait(); close(done) }()

	// Readiness: the probes attach synchronously in the child; either the ready
	// banner appears, or the child exits early (no CAP_BPF/root) -- in which
	// case we degrade with its captured stderr. The timeout is a backstop.
	select {
	case <-ready:
		return sp, "kernel", message{}
	case <-done:
		<-scanned
		reason := strings.TrimSpace(sink.String())
		reason = lastLine(reason)
		if reason == "" {
			return nil, "none", messagef("no kernel telemetry: sensor exited before attaching (needs root or CAP_BPF+CAP_PERFMON)")
		}
		return nil, "none", messagef("no kernel telemetry: %s", errors.New(reason))
	case <-time.After(3 * time.Second):
		sp.stop()
		return nil, "none", messagef("kernel probe readiness was not confirmed before the startup timeout")
	}
}

func (s *sensorProcess) stop() bool {
	if s == nil {
		return false
	}
	if s.stopped {
		return s.cleanStop
	}
	s.stopped = true
	select {
	case <-s.done:
		// Even a successful early exit cannot cover the whole agent run.
		return false
	default:
	}
	if s.cmd.Process != nil {
		// SIGTERM: the sensor traps it, closes its ringbuf, flushes, and exits.
		_ = s.cmd.Process.Signal(syscall.SIGTERM)
	}
	select {
	case <-s.done:
		s.cleanStop = s.exitErr == nil
	case <-time.After(5 * time.Second):
		if s.cmd.Process != nil {
			_ = s.cmd.Process.Kill()
		}
		<-s.done
	}
	return s.cleanStop
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if t := strings.TrimSpace(lines[i]); t != "" {
			return t
		}
	}
	return ""
}
