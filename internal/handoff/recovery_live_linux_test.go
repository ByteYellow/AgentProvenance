//go:build linux

package handoff

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestExecutionCrashHelper(t *testing.T) {
	if os.Getenv("AGENTPROV_EXECUTOR_CRASH_HELPER") != "1" {
		return
	}
	paths := store.ResolvePaths(os.Getenv("AGENTPROV_EXECUTOR_CRASH_STORE"))
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	r := fixtureRequest()
	e := &Executor{Ledger: Ledger{DB: db, Target: r.Target, Now: func() time.Time { return r.ValidUntil.Add(-time.Hour) }}, Paths: paths}
	if duration := os.Getenv("AGENTPROV_EXECUTOR_CRASH_TIMEOUT"); duration != "" {
		e.Options.Timeout, err = time.ParseDuration(duration)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	report := waitExecution(t, e, fixturePrincipal(r), os.Getenv("AGENTPROV_EXECUTOR_CRASH_ATTEMPT"), Running)
	marker := filepath.Join(paths.Workspaces, "crash-task", "started")
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("command did not create its side-effect marker")
		}
		time.Sleep(10 * time.Millisecond)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(paths.Root, "crashed-report.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// The OS closes the store lock; lifecycle cleanup and child Wait do not run.
	os.Exit(73)
}

func TestExecutorRecoversLiveScope(t *testing.T) {
	if os.Getenv("AGENTPROV_TEST_REQUIRE_CGROUP") != "1" {
		t.Skip("set AGENTPROV_TEST_REQUIRE_CGROUP=1 with delegated cgroup v2 permissions")
	}
	for _, mode := range []string{"stop", "pending_stop", "natural_exit", "deadline"} {
		t.Run(mode, func(t *testing.T) { testExecutorRecoversLiveScope(t, mode) })
	}
}

func testExecutorRecoversLiveScope(t *testing.T, mode string) {
	e, p, r := testExecutor(t)
	work := filepath.Join(e.Paths.Workspaces, "crash-task")
	if err := os.MkdirAll(work, 0o700); err != nil {
		t.Fatal(err)
	}
	r.Command.Argv = []string{"python3", "-c", "import os,time; open('started','a').write('once\\n')\nwhile not os.path.exists('finish'): time.sleep(0.01)"}
	r.Command.Workdir = work
	a, _, err := e.Ledger.Admit(context.Background(), p, r)
	if err != nil {
		t.Fatal(err)
	}
	helper := exec.Command(os.Args[0], "-test.run=^TestExecutionCrashHelper$", "-test.timeout=15s")
	helper.Env = append(os.Environ(), "AGENTPROV_EXECUTOR_CRASH_HELPER=1", "AGENTPROV_EXECUTOR_CRASH_STORE="+e.Paths.Root, "AGENTPROV_EXECUTOR_CRASH_ATTEMPT="+a.ID)
	if mode == "deadline" {
		helper.Env = append(helper.Env, "AGENTPROV_EXECUTOR_CRASH_TIMEOUT=3s")
	}
	out, err := helper.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 73 {
		t.Fatalf("crash helper: %v %s", err, out)
	}
	raw, err := os.ReadFile(filepath.Join(e.Paths.Root, "crashed-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var before Report
	if err := json.Unmarshal(raw, &before); err != nil {
		t.Fatal(err)
	}
	scope := before.Checkpoint.Scope
	parent := os.Getenv("AGENTPROV_CGROUP_PARENT")
	if parent == "" {
		parent = "/sys/fs/cgroup/agentprov"
	}
	group := filepath.Join(parent, scope.AttemptID)
	t.Cleanup(func() {
		if info, err := os.Stat(group); err == nil && strconv.FormatUint(info.Sys().(*syscall.Stat_t).Ino, 10) == scope.CgroupID {
			_ = os.WriteFile(filepath.Join(group, "cgroup.kill"), []byte("1"), 0o600)
			_ = os.Remove(group)
		}
	})
	if scope.ScopeKind != "cgroup" || scope.RootPID <= 0 || syscall.Kill(int(scope.RootPID), 0) != nil {
		t.Fatalf("fixture did not leave a live owned scope: %+v", scope)
	}
	control := exec.Command("sleep", "90")
	if err := control.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Process.Kill(); _ = control.Wait() })
	if mode == "pending_stop" {
		if _, err := e.Ledger.RequestStop(context.Background(), p, a.ID, "stop-before-restart"); err != nil {
			t.Fatal(err)
		}
	}
	stop := startExecutor(t, e)
	report, err := e.Ledger.Report(context.Background(), p, a.ID)
	if err != nil || (report.Attempt.State.Execution != Running && !(mode == "pending_stop" && report.Attempt.State.Execution == Cancelled)) {
		t.Fatalf("live execution was not recovered: state=%s err=%v", report.Attempt.State.Execution, err)
	}
	if report.Checkpoint.Recovery == nil || report.Checkpoint.Recovery.Observation.Empty == nil ||
		(report.Attempt.State.Execution == Running && *report.Checkpoint.Recovery.Observation.Empty) {
		t.Fatalf("missing live scope recovery observation: %+v", report.Checkpoint)
	}
	want := Cancelled
	switch mode {
	case "stop":
		if _, err := e.Ledger.RequestStop(context.Background(), p, a.ID, "stop-recovered"); err != nil {
			t.Fatal(err)
		}
	case "natural_exit":
		want = Unknown
		if err := os.WriteFile(filepath.Join(work, "finish"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	case "deadline":
		want = Failed
	}
	report = waitExecution(t, e, p, a.ID, want)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if report.Checkpoint.Result != nil || report.Attempt.State.Capture != Incomplete {
		t.Fatalf("recovery invented an exit result or complete capture: %+v", report.Checkpoint)
	}
	recovery := report.Checkpoint.Recovery
	if recovery == nil || recovery.Observation.Empty == nil || !*recovery.Observation.Empty {
		t.Fatalf("missing recovered empty-scope observation: %+v", recovery)
	}
	if mode == "natural_exit" {
		if recovery.Stop != nil || report.Checkpoint.Reason != "recovered_scope_ended_unknown" {
			t.Fatal("natural disappearance claimed a stop or observed exit status")
		}
	} else if recovery.Stop == nil || !recovery.Stop.SignalSent || recovery.Stop.ScopeEmpty == nil || !*recovery.Stop.ScopeEmpty {
		t.Fatalf("missing recovered stop evidence: %+v", recovery)
	}
	if mode == "deadline" && report.Checkpoint.Reason != "recovered_scope_timed_out" {
		t.Fatal("lost saved execution deadline")
	}
	var closed string
	if err := e.Ledger.DB.QueryRow(`SELECT ended_at FROM execution_context_bindings WHERE id=?`, scope.BindingID).Scan(&closed); err != nil || closed != recovery.Observation.ObservedAt {
		t.Fatalf("scope binding was not closed with its observation: %q %v", closed, err)
	}
	marker, err := os.ReadFile(filepath.Join(work, "started"))
	if err != nil || string(marker) != "once\n" || rowCount(t, e.Ledger.DB, "tool_calls") != 1 {
		t.Fatalf("recovery repeated command: %q %v", marker, err)
	}
	if err := control.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("stop affected an unrelated process: %v", err)
	}
	checkRecoveryDelivery(t, deliveryFromReport(t, e, p, report, work))
	t.Logf("crashed worker recovered its scope (%s), retained one side effect, and left the control process running", mode)
}

func checkRecoveryDelivery(t *testing.T, f deliveryFixture) {
	t.Helper()
	d := f.prepare(t, "recovered-scope-evidence")
	receipt := f.receive(t, d)
	if _, err := f.sender.Acknowledge(context.Background(), f.principal, d.Manifest.ID, receipt); err != nil {
		t.Fatal(err)
	}
	if err := f.receiver.DB.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.receiver.DB, err = store.Open(f.receiver.Paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.receiver.DB.Close() })
	if err := os.RemoveAll(f.workdir); err != nil {
		t.Fatal(err)
	}
	var got Checkpoint
	if err := provenance.ReadObjectPayload(f.receiver.DB, f.report.Attempt.LocalRunID, d.Manifest.CheckpointRef, &got); err != nil {
		t.Fatal(err)
	}
	wantJSON, err := json.Marshal(f.report.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	gotJSON, err := json.Marshal(got)
	if err != nil || !bytes.Equal(gotJSON, wantJSON) {
		t.Fatalf("signed delivery changed recovery evidence: %s != %s (%v)", gotJSON, wantJSON, err)
	}
	if err := provenance.VerifyRun(f.receiver.DB, f.report.Attempt.LocalRunID, io.Discard); err != nil {
		t.Fatal(err)
	}
	after, err := f.sender.Ledger.Get(context.Background(), f.principal, f.report.Attempt.ID)
	if err != nil || after.State.Delivery != Acknowledged || after.State.Execution != f.report.Attempt.State.Execution || after.State.Capture != Incomplete {
		t.Fatalf("receipt changed recovered execution/capture: %+v %v", after.State, err)
	}
	if root := os.Getenv("AGENTPROV_TEST_RECOVERY_REPORT_DIR"); root != "" {
		dir := filepath.Join(root, strings.ReplaceAll(t.Name(), "/", "-"))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		bundle, err := os.ReadFile(d.BundlePath)
		if err != nil {
			t.Fatal(err)
		}
		for name, body := range map[string][]byte{"checkpoint.json": gotJSON, "manifest.dsse.json": d.Envelope, "receipt.dsse.json": receipt, "bundle.json": bundle} {
			if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
}
