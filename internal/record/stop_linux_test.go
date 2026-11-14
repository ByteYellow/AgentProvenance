//go:build linux

package record

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestExecutionScopeStopHelper(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-3] != "--" {
		return
	}
	mode, dir := os.Args[len(os.Args)-2], os.Args[len(os.Args)-1]
	if mode == "parent" || mode == "parent_exit" {
		child := exec.Command(os.Args[0], "-test.run=^TestExecutionScopeStopHelper$", "--", "detached", dir)
		child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		if mode == "parent_exit" {
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := os.Stat(filepath.Join(dir, "detached.json")); err == nil {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Fatal("detached child did not become ready")
		}
	} else if mode == "detached" {
		pgid, err := syscall.Getpgid(0)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := json.Marshal(map[string]int{"pid": os.Getpid(), "pgid": pgid})
		if err := os.WriteFile(filepath.Join(dir, "detached.json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	} else {
		t.Fatalf("unexpected helper mode %q", mode)
	}
	time.Sleep(time.Minute)
}

func TestStopExecutionKillsDetachedScope(t *testing.T) {
	for _, mode := range []string{"cancel", "timeout", "checkpoint_failure"} {
		t.Run(mode, func(t *testing.T) { testStopExecutionKillsDetachedScope(t, mode) })
	}
}

func testStopExecutionKillsDetachedScope(t *testing.T, mode string) {
	if os.Getenv("AGENTPROV_TEST_REQUIRE_CGROUP") != "1" {
		t.Skip("set AGENTPROV_TEST_REQUIRE_CGROUP=1 with a delegated cgroup v2 subtree")
	}
	paths, db := newPolicyTestStore(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	scopes := make(chan ExecutionScope, 2)
	type completion struct {
		result Result
		err    error
	}
	done := make(chan completion, 2)
	controls := make([]context.CancelFunc, 2)
	failCheckpoint := make(chan struct{})
	defer close(failCheckpoint)
	checkpointError := errors.New("injected start checkpoint failure")
	for i := 0; i < 2; i++ {
		workdir := filepath.Join(paths.Workspaces, fmt.Sprintf("detached-%d", i))
		if err := os.MkdirAll(workdir, 0o700); err != nil {
			t.Fatal(err)
		}
		jobCtx, stop := context.WithCancel(ctx)
		controls[i] = stop
		go func() {
			opts := Options{}
			if i == 0 && mode == "timeout" {
				opts.Timeout = 2 * time.Second
			}
			svc := Service{DB: db, Paths: paths, Options: opts, Lifecycle: &Lifecycle{Started: func(scope ExecutionScope) error {
				if scope.ScopeKind != "cgroup" {
					return fmt.Errorf("kernel cgroup required: %+v", scope)
				}
				scopes <- scope
				if i == 0 && mode == "checkpoint_failure" {
					select {
					case <-failCheckpoint:
					case <-jobCtx.Done():
					}
					return checkpointError
				}
				return nil
			}}}
			r, err := svc.RunContext(jobCtx, Request{RunID: fmt.Sprintf("stop-scope-%d", i), Workdir: workdir,
				Command:         []string{executable, "-test.run=^TestExecutionScopeStopHelper$", "--", "parent", workdir},
				DisableSnapshot: true, PostRootGraceMS: 1, Stdout: io.Discard, Stderr: io.Discard})
			done <- completion{r, err}
		}()
	}
	var observed []ExecutionScope
	finished := 0
	defer func() {
		cancel()
		for _, scope := range observed {
			// Only clean the isolated scope created by this test, never a PID.
			dir := filepath.Join(scopeCgroupParent, sanitizeCgroupName(scope.AttemptID))
			_ = os.WriteFile(filepath.Join(dir, "cgroup.kill"), []byte("1"), 0o600)
		}
		for ; finished < 2; finished++ {
			<-done
		}
	}()
	for len(observed) < 2 {
		select {
		case scope := <-scopes:
			observed = append(observed, scope)
		case c := <-done:
			finished++
			t.Fatalf("execution ended before ready: %+v %v", c.result, c.err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	for _, scope := range observed {
		for {
			data, err := os.ReadFile(filepath.Join(scope.Workdir, "detached.json"))
			if err == nil {
				var identity struct{ PID, PGID int }
				if err := json.Unmarshal(data, &identity); err != nil {
					t.Fatal(err)
				}
				if identity.PID == int(scope.RootPID) || identity.PID != identity.PGID {
					t.Fatalf("child did not escape the root process group: %s", data)
				}
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	switch mode {
	case "cancel":
		controls[0]()
	case "checkpoint_failure":
		failCheckpoint <- struct{}{}
	}
	c := <-done
	finished++
	if mode == "checkpoint_failure" {
		if !errors.Is(c.err, checkpointError) {
			t.Fatalf("checkpoint failure disappeared: %v", c.err)
		}
	} else {
		wantStatus, wantCode := "cancelled", 130
		if mode == "timeout" {
			wantStatus, wantCode = "failed", 124
		}
		if c.err != nil || c.result.Status != wantStatus || c.result.ExitCode != wantCode {
			t.Fatalf("stop result: %+v %v", c.result, c.err)
		}
	}
	if c.result.RunID != "stop-scope-0" {
		t.Fatalf("stop result: %+v %v", c.result, c.err)
	}
	if r := c.result.Stop; r == nil || r.Method != "cgroup_kill" || !r.SignalSent || r.ScopeEmpty == nil || !*r.ScopeEmpty || r.Error != "" {
		t.Fatalf("stop lacks verified scope completion: %+v", r)
	}
	for _, scope := range observed {
		data, err := os.ReadFile(filepath.Join(scopeCgroupParent, sanitizeCgroupName(scope.AttemptID), "cgroup.events"))
		if scope.RunID == "stop-scope-0" {
			if !os.IsNotExist(err) && (err != nil || !strings.Contains(string(data), "populated 0\n")) {
				t.Errorf("stopped execution still has a detached child: %q %v", data, err)
			}
		} else if err != nil || !strings.Contains(string(data), "populated 1\n") {
			t.Errorf("stop affected the other execution: %q %v", data, err)
		}
	}
}

func TestScopeCgroupDoesNotAdoptExistingDirectory(t *testing.T) {
	parent := scopeCgroupParent
	scopeCgroupParent = t.TempDir()
	t.Cleanup(func() { scopeCgroupParent = parent })
	dir := filepath.Join(scopeCgroupParent, "existing")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	scope := prepareScopeCgroup(&exec.Cmd{}, "existing")
	defer scope.cleanup()
	if scope.kill != nil || scope.empty != nil || !strings.HasPrefix(scope.id, "agentprov-record-") {
		t.Fatal("adopted an existing directory as a kill scope")
	}
	scope.cleanup()
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("removed someone else's directory: %v", err)
	}
	cmd := &exec.Cmd{}
	fake := prepareScopeCgroup(cmd, "not-cgroupfs")
	defer fake.cleanup()
	if fake.kill != nil || !strings.HasPrefix(fake.id, "agentprov-record-") || (cmd.SysProcAttr != nil && cmd.SysProcAttr.UseCgroupFD) {
		t.Fatal("ordinary directory became a kernel scope")
	}
}

func TestScopeCgroupStopDoesNotFollowReusedPath(t *testing.T) {
	if os.Getenv("AGENTPROV_TEST_REQUIRE_CGROUP") != "1" {
		t.Skip("set AGENTPROV_TEST_REQUIRE_CGROUP=1 with a delegated cgroup v2 subtree")
	}
	name := fmt.Sprintf("path-reuse-%d-%d", os.Getpid(), time.Now().UnixNano())
	scope := prepareScopeCgroup(&exec.Cmd{}, name)
	defer scope.cleanup()
	if scope.kill == nil {
		t.Fatal("kernel cgroup required")
	}
	dir := filepath.Join(scopeCgroupParent, name)
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(dir)
	f, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cmd := exec.Command("sleep", "60")
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(f.Fd())}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	_ = scope.kill()
	data, err := os.ReadFile(filepath.Join(dir, "cgroup.events"))
	if err != nil || !strings.Contains(string(data), "populated 1\n") {
		t.Fatalf("old scope stop reached replacement: %q %v", data, err)
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	scope.cleanup()
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("old scope cleanup removed replacement: %v", err)
	}
}

func TestNormalCompletionKeepsObserveOnlyDescendants(t *testing.T) {
	if os.Getenv("AGENTPROV_TEST_REQUIRE_CGROUP") != "1" {
		t.Skip("set AGENTPROV_TEST_REQUIRE_CGROUP=1 with a delegated cgroup v2 subtree")
	}
	paths, db := newPolicyTestStore(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(paths.Workspaces, "observe-only")
	if err := os.MkdirAll(work, 0o700); err != nil {
		t.Fatal(err)
	}
	var scope ExecutionScope
	svc := Service{DB: db, Paths: paths, Lifecycle: &Lifecycle{Started: func(s ExecutionScope) error {
		scope = s
		if scope.ScopeKind != "cgroup" {
			return fmt.Errorf("kernel cgroup required")
		}
		return nil
	}}}
	defer func() {
		if scope.ScopeKind == "cgroup" {
			dir := filepath.Join(scopeCgroupParent, sanitizeCgroupName(scope.AttemptID))
			_ = os.WriteFile(filepath.Join(dir, "cgroup.kill"), []byte("1"), 0o600)
			for i := 0; i < 100; i++ {
				if err := os.Remove(dir); err == nil || os.IsNotExist(err) {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()
	r, err := svc.Run(Request{RunID: "observe-only", Workdir: work, DisableSnapshot: true, PostRootGraceMS: 1,
		Command: []string{executable, "-test.run=^TestExecutionScopeStopHelper$", "--", "parent_exit", work},
		Stdout:  io.Discard, Stderr: io.Discard})
	if err != nil || r.Status != "passed" || r.Stop != nil || r.OrphanPolicy != "observe_only" {
		t.Fatalf("normal completion changed: %+v %v", r, err)
	}
	raw, err := os.ReadFile(filepath.Join(scopeCgroupParent, sanitizeCgroupName(scope.AttemptID), "cgroup.events"))
	if err != nil || !strings.Contains(string(raw), "populated 1\n") {
		t.Fatalf("normal completion killed the observed background child: %q %v", raw, err)
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var saved struct {
		Observation *struct {
			Empty *bool `json:"empty"`
		} `json:"scope_observation"`
	}
	if err := json.Unmarshal(encoded, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Observation == nil || saved.Observation.Empty == nil || *saved.Observation.Empty {
		t.Fatalf("normal completion did not retain populated scope: %s", encoded)
	}
}
