//go:build linux

package record

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestConcurrentExecutionKernelScopes(t *testing.T) {
	if os.Getenv("AGENTPROV_TEST_REQUIRE_CGROUP") != "1" {
		t.Skip("set AGENTPROV_TEST_REQUIRE_CGROUP=1 with a delegated cgroup v2 subtree")
	}
	paths, db := newPolicyTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	started := make(chan ExecutionScope, 2)
	done := make(chan error, 2)
	for i := 0; i < 2; i++ {
		run := fmt.Sprintf("concurrent-scope-%d", i)
		go func() {
			svc := Service{DB: db, Paths: paths, Lifecycle: &Lifecycle{Started: func(scope ExecutionScope) error {
				if scope.ScopeKind != "cgroup" {
					return fmt.Errorf("required kernel cgroup unavailable: %+v", scope)
				}
				raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", scope.RootPID))
				if err != nil {
					return err
				}
				if !strings.Contains(string(raw), "/"+sanitizeCgroupName(scope.AttemptID)+"\n") {
					return fmt.Errorf("root born outside its scope: %s", raw)
				}
				info, err := os.Stat(filepath.Join(scopeCgroupParent, sanitizeCgroupName(scope.AttemptID)))
				if err != nil {
					return err
				}
				if strconv.FormatUint(info.Sys().(*syscall.Stat_t).Ino, 10) != scope.CgroupID {
					return fmt.Errorf("scope ID differs from kernel inode")
				}
				started <- scope
				return nil
			}}}
			r, err := svc.RunContext(ctx, Request{RunID: run, Command: []string{"sleep", "60"}, DisableSnapshot: true,
				PostRootGraceMS: 1, Stdout: io.Discard, Stderr: io.Discard})
			if err == nil && (r.Status != "cancelled" || r.EndEventID == "") {
				err = fmt.Errorf("unexpected completion: %+v", r)
			}
			done <- err
		}()
	}
	var scopes []ExecutionScope
	finished := 0
ready:
	for len(scopes) < 2 {
		select {
		case scope := <-started:
			scopes = append(scopes, scope)
		case err := <-done:
			finished++
			if err != nil {
				t.Error(err)
			}
			break ready
		case <-ctx.Done():
			t.Errorf("scope readiness: %v", ctx.Err())
			break ready
		}
	}
	cancel()
	for ; finished < 2; finished++ {
		if err := <-done; err != nil {
			t.Error(err)
		}
	}
	if len(scopes) != 2 {
		t.Fatalf("received %d of 2 scopes", len(scopes))
	}
	if scopes[0].CgroupID == scopes[1].CgroupID || scopes[0].RootPID == scopes[1].RootPID || scopes[0].ToolCallID == scopes[1].ToolCallID {
		t.Fatalf("concurrent same-command scopes collided: %+v", scopes)
	}
	for _, scope := range scopes {
		var run, call string
		if err := db.QueryRow(`SELECT run_id,tool_call_id FROM execution_context_bindings WHERE cgroup_id=?`, scope.CgroupID).Scan(&run, &call); err != nil {
			t.Fatal(err)
		}
		if run != scope.RunID || call != scope.ToolCallID {
			t.Fatalf("scope crossed runs: %+v -> %s %s", scope, run, call)
		}
	}
}
