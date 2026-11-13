package record

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
)

func TestExecutionStopSignalAndObservation(t *testing.T) {
	for _, test := range []struct {
		name       string
		killError  error
		observeErr error
		populated  bool
	}{
		{name: "scope_empty"},
		{name: "kill_failed", killError: os.ErrPermission},
		{name: "observation_failed", observeErr: os.ErrPermission},
		{name: "still_populated", populated: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cmd := exec.Command("sleep", "60")
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
			calls := 0
			stop := executionStop{cmd: cmd, cgroup: executionCgroup{
				kill: func() error {
					calls++
					if test.killError != nil {
						return test.killError
					}
					return cmd.Process.Kill()
				},
				empty: func() (bool, error) { return !test.populated, test.observeErr },
			}}
			var wait sync.WaitGroup
			for i := 0; i < 4; i++ {
				wait.Add(1)
				go func() { defer wait.Done(); _ = stop.signal() }()
			}
			wait.Wait()
			_ = cmd.Wait()
			r := stop.finish()
			if calls != 1 || r == nil || !r.SignalSent || r.RequestedAt == "" || r.ObservedAt == "" {
				t.Fatalf("stop was repeated or unobserved: calls=%d report=%+v", calls, r)
			}
			method := "cgroup_kill"
			if test.killError != nil {
				method = "root_process"
			}
			if r.Method != method {
				t.Fatalf("wrong stop method: %+v", r)
			}
			if test.observeErr != nil {
				if r.ScopeEmpty != nil || !strings.Contains(r.Error, test.observeErr.Error()) {
					t.Fatalf("observation failure became an empty scope: %+v", r)
				}
			} else if r.ScopeEmpty == nil || *r.ScopeEmpty == test.populated {
				t.Fatalf("wrong scope state: %+v", r)
			}
			if test.killError != nil && !strings.Contains(r.Error, test.killError.Error()) {
				t.Fatalf("scope stop failure disappeared: %+v", r)
			}
		})
	}
}

func TestLogicalScopeStopKeepsPopulationUnknown(t *testing.T) {
	for _, group := range []bool{false, true} {
		t.Run(map[bool]string{false: "root", true: "missing_group"}[group], func(t *testing.T) {
			testLogicalScopeStop(t, group)
		})
	}
}

func testLogicalScopeStop(t *testing.T, group bool) {
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	stop := executionStop{cmd: cmd, cgroup: logicalCgroup("logical"), group: group}
	if err := stop.signal(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	r := stop.finish()
	if r == nil || r.Method != "root_process" || r.ScopeEmpty != nil || !r.SignalSent {
		t.Fatalf("logical scope acquired a kernel completion claim: %+v", r)
	}
	if group && !strings.Contains(r.Error, "process group stop failed") {
		t.Fatalf("group failure was hidden by root fallback: %+v", r)
	}
	if err := cmd.Process.Signal(os.Interrupt); !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("root was not reaped: %v", err)
	}
}
