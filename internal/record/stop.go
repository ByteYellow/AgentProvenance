package record

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"
)

// StopReport separates delivery of a stop signal from observation of the
// execution scope becoming empty. A nil ScopeEmpty means it was not observed.
type StopReport struct {
	Method      string `json:"method"`
	RequestedAt string `json:"requested_at"`
	ObservedAt  string `json:"observed_at"`
	SignalSent  bool   `json:"signal_sent"`
	ScopeEmpty  *bool  `json:"scope_empty"`
	Error       string `json:"error,omitempty"`
}

type executionCgroup struct {
	id      string
	kill    func() error
	empty   func() (bool, error)
	cleanup func()
}

func logicalCgroup(attemptID string) executionCgroup {
	return executionCgroup{id: "agentprov-record-" + attemptID, cleanup: func() {}}
}

type executionStop struct {
	once   sync.Once
	cmd    *exec.Cmd
	cgroup executionCgroup
	group  bool
	report *StopReport
	err    error
}

func (s *executionStop) signal() error {
	s.once.Do(func() {
		s.report = &StopReport{RequestedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		if s.cgroup.kill != nil {
			s.report.Method = "cgroup_kill"
			if err := s.cgroup.kill(); err == nil {
				s.report.SignalSent = true
				return
			} else {
				s.report.Error = fmt.Sprintf("cgroup stop failed: %v", err)
			}
			// The owned cgroup is still observed below. Do not substitute a
			// numeric process-group lookup after the scope operation failed.
			s.report.Method = "root_process"
			s.err = s.cmd.Process.Kill()
		} else if s.group {
			s.report.Method = "process_group"
			s.err = killProcessGroup(s.cmd.Process.Pid)
			if s.err != nil {
				s.report.addError(fmt.Errorf("process group stop failed: %w", s.err))
				s.report.Method = "root_process"
				s.err = s.cmd.Process.Kill()
			}
		} else {
			s.report.Method = "root_process"
			s.err = s.cmd.Process.Kill()
		}
		s.report.SignalSent = s.err == nil
		if s.err != nil && !errors.Is(s.err, os.ErrProcessDone) {
			s.report.addError(s.err)
		}
	})
	return s.err
}

// finish is called after Cmd.Wait has joined its cancellation callback.
func (s *executionStop) finish() *StopReport {
	if s.report == nil {
		return nil
	}
	if s.cgroup.empty != nil {
		deadline := time.Now().Add(2 * time.Second)
		for {
			empty, err := s.cgroup.empty()
			if err != nil {
				s.report.ScopeEmpty = nil
				s.report.addError(fmt.Errorf("observe stopped scope: %w", err))
				break
			}
			s.report.ScopeEmpty = &empty
			if empty || !time.Now().Before(deadline) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	s.report.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return s.report
}

func (r *StopReport) addError(err error) {
	if r.Error != "" {
		r.Error += "; "
	}
	r.Error += err.Error()
}
