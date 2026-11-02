package record

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func newPolicyTestStore(t *testing.T) (store.Paths, *sql.DB) {
	t.Helper()
	paths, err := store.Init(filepath.Join(t.TempDir(), ".agentprov"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return paths, db
}

// TestRecordPolicyRefusesShellByDefault pins the C2 acceptance case: a bare
// `{"command":["sh","-c","id"]}` request is refused by default (fail-closed),
// absolute interpreter paths included, with zero side effects; an explicit
// Options.AllowShell opt-in is what re-enables `sh -c`.
func TestRecordPolicyRefusesShellByDefault(t *testing.T) {
	paths, db := newPolicyTestStore(t)
	svc := Service{DB: db, Paths: paths} // zero Options = fail-closed policy
	for _, argv := range [][]string{
		{"sh", "-c", "id"},
		{"/bin/bash", "-c", "id; uname"},
		{"zsh"},
		{"/usr/bin/fish", "-c", "id"},
	} {
		result, err := svc.Run(Request{RunID: "run-shell-refused", Command: argv})
		if err == nil {
			t.Fatalf("argv %v executed under default policy: %+v", argv, result)
		}
		if !strings.Contains(err.Error(), "shell") {
			t.Fatalf("argv %v error = %v, want an explicit shell-policy refusal", argv, err)
		}
	}
	var snapshots, toolCalls int
	if err := db.QueryRow(`SELECT COUNT(*) FROM snapshots`).Scan(&snapshots); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM tool_calls`).Scan(&toolCalls); err != nil {
		t.Fatal(err)
	}
	if snapshots != 0 || toolCalls != 0 {
		t.Fatalf("refused command wrote rows: snapshots=%d tool_calls=%d", snapshots, toolCalls)
	}
	allowed := Service{DB: db, Paths: paths, Options: Options{AllowShell: true}}
	result, err := allowed.Run(Request{RunID: "run-shell-allowed", Command: []string{"sh", "-c", "echo ok"}})
	if err != nil || result.Status != "passed" || result.ExitCode != 0 {
		t.Fatalf("AllowShell opt-in run = %+v err %v, want passed exit 0", result, err)
	}
}

// TestRecordPolicyRunsPlainCommandInRunWorkspace pins the other half of the
// acceptance case: `{"command":["id"]}` still executes, inside the run's
// auto-created workspace directory (not the daemon's own cwd), which must
// exist with 0700 permissions.
func TestRecordPolicyRunsPlainCommandInRunWorkspace(t *testing.T) {
	paths, db := newPolicyTestStore(t)
	svc := Service{DB: db, Paths: paths}
	var out bytes.Buffer
	result, err := svc.Run(Request{RunID: "run-plain-id", Command: []string{"id"}, Stdout: &out})
	if err != nil {
		t.Fatalf("plain command refused by default: %v", err)
	}
	if result.Status != "passed" || result.ExitCode != 0 {
		t.Fatalf("plain command result = %+v, want passed exit 0", result)
	}
	wantWorkspace, err := filepath.EvalSymlinks(filepath.Join(paths.Workspaces, "run-plain-id"))
	if err != nil {
		t.Fatal(err)
	}
	if result.CWD != wantWorkspace || result.Workdir != wantWorkspace {
		t.Fatalf("run cwd/workdir = %s/%s, want the run workspace %s", result.CWD, result.Workdir, wantWorkspace)
	}
	info, err := os.Stat(wantWorkspace)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("workspace dir perms = %v, want 0700", info.Mode().Perm())
	}
	if !strings.Contains(out.String(), "uid=") {
		t.Fatalf("id output missing uid=: %q", out.String())
	}
}

// TestRecordPolicyConfinesWorkdirToWorkspaceRoot: a request workdir outside
// the workspace root is refused (symlink-resolved, `..` included), a nested
// one is created on demand 0700 and used verbatim.
func TestRecordPolicyConfinesWorkdirToWorkspaceRoot(t *testing.T) {
	paths, db := newPolicyTestStore(t)
	svc := Service{DB: db, Paths: paths}

	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Run(Request{RunID: "run-escape", Workdir: outside, Command: []string{"true"}}); err == nil || !strings.Contains(err.Error(), "workspace") {
		t.Fatalf("workdir outside workspace root accepted: err=%v", err)
	}

	escape := filepath.Join(paths.Workspaces, "..", "snapshots")
	if _, err := svc.Run(Request{RunID: "run-traversal", Workdir: escape, Command: []string{"true"}}); err == nil || !strings.Contains(err.Error(), "workspace") {
		t.Fatalf("workdir escaping via .. accepted: err=%v", err)
	}

	nested := filepath.Join(paths.Workspaces, "proj", "sub")
	result, err := svc.Run(Request{RunID: "run-nested", Workdir: nested, Command: []string{"true"}})
	if err != nil || result.Status != "passed" {
		t.Fatalf("nested workspace run = %+v err %v, want passed", result, err)
	}
	wantNested, err := filepath.EvalSymlinks(nested)
	if err != nil {
		t.Fatal(err)
	}
	if result.CWD != wantNested {
		t.Fatalf("nested run cwd = %s, want %s", result.CWD, wantNested)
	}
	if info, err := os.Stat(wantNested); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("nested workspace perms = %v err %v, want 0700", info.Mode().Perm(), err)
	}

	// The local CLI escape hatch must actually lift the confinement.
	unconfined := Service{DB: db, Paths: paths, Options: Options{AllowAnyWorkdir: true}}
	if _, err := unconfined.Run(Request{RunID: "run-unconfined", Workdir: outside, Command: []string{"true"}}); err != nil {
		t.Fatalf("AllowAnyWorkdir run refused: %v", err)
	}
}

// TestRecordPolicyTimeoutKillsProcessGroup: with Options.Timeout set, a
// command that never exits is killed (exit 124, explicit failure reason) and
// the kill reaches the whole process group -- the backgrounded `sleep` child
// must not survive the deadline.
func TestRecordPolicyTimeoutKillsProcessGroup(t *testing.T) {
	paths, db := newPolicyTestStore(t)
	svc := Service{DB: db, Paths: paths, Options: Options{Timeout: 400 * time.Millisecond, AllowShell: true}}
	workspace := filepath.Join(paths.Workspaces, "timeout-ws")
	var out bytes.Buffer
	start := time.Now()
	result, err := svc.Run(Request{
		RunID:   "run-timeout",
		Workdir: workspace,
		Command: []string{"sh", "-c", "sleep 60 & echo $! > child.pid; sleep 60"},
		Stdout:  &out,
	})
	if err != nil {
		t.Fatalf("timeout run returned transport error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Fatalf("timeout enforcement took %s, want ~Options.Timeout", elapsed)
	}
	if result.Status != "failed" || result.ExitCode != 124 {
		t.Fatalf("timeout result = %+v, want failed exit 124", result)
	}
	if !strings.Contains(result.FailureReason, "timed out") {
		t.Fatalf("failure reason = %q, want an explicit timeout reason", result.FailureReason)
	}
	pidFile := filepath.Join(workspace, "child.pid")
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("background child never wrote its pid: %v", err)
	}
	var childPID int
	if _, err := fmt.Sscanf(string(raw), "%d", &childPID); err != nil {
		t.Fatalf("bad child pid file %q: %v", raw, err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if syscall.Kill(childPID, 0) != nil {
			break // process gone: the group kill reached the background child
		}
		if time.Now().After(deadline) {
			t.Fatalf("backgrounded child %d survived the process-group kill", childPID)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestRecordPolicyMinimizesChildEnvironment: by default the recorded child
// must not see daemon credentials beyond the PATH/HOME/TMPDIR/TERM allowlist;
// InheritFullEnv restores the old pass-through explicitly.
func TestRecordPolicyMinimizesChildEnvironment(t *testing.T) {
	paths, db := newPolicyTestStore(t)
	t.Setenv("AGENTPROV_POLICY_CANARY", "leaked")
	svc := Service{DB: db, Paths: paths}
	var out bytes.Buffer
	result, err := svc.Run(Request{RunID: "run-env-min", Command: []string{"/usr/bin/env"}, Stdout: &out})
	if err != nil || result.Status != "passed" {
		t.Fatalf("env run = %+v err %v, want passed", result, err)
	}
	envText := out.String()
	if strings.Contains(envText, "AGENTPROV_POLICY_CANARY") {
		t.Fatalf("child inherited the full daemon environment (canary leaked)")
	}
	if !strings.Contains(envText, "PATH=") {
		t.Fatalf("child environment missing allowlisted PATH: %q", envText)
	}
	full := Service{DB: db, Paths: paths, Options: Options{InheritFullEnv: true}}
	var fullOut bytes.Buffer
	if _, err := full.Run(Request{RunID: "run-env-full", Command: []string{"/usr/bin/env"}, Stdout: &fullOut}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fullOut.String(), "AGENTPROV_POLICY_CANARY") {
		t.Fatalf("InheritFullEnv did not pass the daemon environment through")
	}
}

// TestRecordPolicyAcceptanceJSONRequest drives the exact wire shape the daemon
// decodes (`json.Decode` into record.Request) for both acceptance commands.
func TestRecordPolicyAcceptanceJSONRequest(t *testing.T) {
	paths, db := newPolicyTestStore(t)
	svc := Service{DB: db, Paths: paths}

	var shellReq Request
	if err := json.Unmarshal([]byte(`{"run_id":"acc-shell","command":["sh","-c","id"]}`), &shellReq); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Run(shellReq); err == nil {
		t.Fatal(`{"command":["sh","-c","id"]} was accepted under default policy`)
	}

	var plainReq Request
	if err := json.Unmarshal([]byte(`{"run_id":"acc-plain","command":["id"]}`), &plainReq); err != nil {
		t.Fatal(err)
	}
	result, err := svc.Run(plainReq)
	if err != nil || result.Status != "passed" || result.ExitCode != 0 {
		t.Fatalf(`{"command":["id"]} no longer executes: result=%+v err=%v`, result, err)
	}
}

// TestRecordPolicyWorkdirValidatedBeforeCreate pins the PR #34 P2 fix: a
// confined workdir request is validated BEFORE anything is created, so a
// refused path (outside the root, or escaping via `..`) leaves the filesystem
// untouched; in-root new directories, existing directories, and the
// AllowAnyWorkdir escape hatch keep working.
func TestRecordPolicyWorkdirValidatedBeforeCreate(t *testing.T) {
	paths, db := newPolicyTestStore(t)
	svc := Service{DB: db, Paths: paths}
	rootReal, err := filepath.EvalSymlinks(paths.Workspaces)
	if err != nil {
		t.Fatal(err)
	}
	assertInsideRoot := func(label, dir string) {
		t.Helper()
		rel, relErr := filepath.Rel(rootReal, dir)
		if !relInsideRoot(rel, relErr) {
			t.Fatalf("%s: workdir %q escaped root %q (rel=%q err=%v)", label, dir, rootReal, rel, relErr)
		}
	}

	// (1) New writable directory outside the root: refused, and NOT created.
	outsideRoot := t.TempDir()
	outside := filepath.Join(outsideRoot, "fresh-escape")
	if _, err := svc.resolveWorkdir(outside, "run-p2-outside", svc.Options); err == nil || !strings.Contains(err.Error(), "workspace") {
		t.Fatalf("workdir outside root accepted: err=%v", err)
	}
	if _, err := os.Stat(outside); !os.IsNotExist(err) {
		t.Fatalf("refused request still created %q (stat err=%v)", outside, err)
	}

	// (2) New nested directory inside the root: created on demand, stays inside.
	inside := filepath.Join(paths.Workspaces, "p2", "deep")
	got, err := svc.resolveWorkdir(inside, "run-p2-inside", svc.Options)
	if err != nil {
		t.Fatalf("in-root new workdir refused: %v", err)
	}
	insideReal, err := filepath.EvalSymlinks(inside)
	if err != nil {
		t.Fatal(err)
	}
	if got != insideReal {
		t.Fatalf("resolved workdir = %q, want the physical path %q", got, insideReal)
	}
	assertInsideRoot("new in-root dir", got)
	info, err := os.Stat(insideReal)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("new in-root workdir perms = %v err %v, want 0700", info.Mode().Perm(), err)
	}

	// (3) `..` traversal: refused and nothing materialized at the target.
	traversal := filepath.Join(paths.Workspaces, "..", "p2-traversal-escape")
	target := filepath.Clean(traversal)
	if _, err := svc.resolveWorkdir(traversal, "run-p2-dotdot", svc.Options); err == nil || !strings.Contains(err.Error(), "workspace") {
		t.Fatalf("traversal workdir accepted: err=%v", err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("traversal target %q was created (stat err=%v)", target, err)
	}

	// (4) An existing in-root directory passes through untouched.
	existing := filepath.Join(paths.Workspaces, "p2-existing")
	if err := os.MkdirAll(existing, 0o700); err != nil {
		t.Fatal(err)
	}
	got, err = svc.resolveWorkdir(existing, "run-p2-exists", svc.Options)
	if err != nil {
		t.Fatalf("existing in-root workdir refused: %v", err)
	}
	wantExisting, err := filepath.EvalSymlinks(existing)
	if err != nil {
		t.Fatal(err)
	}
	if got != wantExisting {
		t.Fatalf("existing workdir = %q, want %q", got, wantExisting)
	}

	// (5) An out-of-root request under an existing parent leaves that parent
	// exactly as it was (no child created, no entries added).
	parent := filepath.Join(outsideRoot, "keepme")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.resolveWorkdir(filepath.Join(parent, "must-not-appear"), "run-p2-parent", svc.Options); err == nil {
		t.Fatal("out-of-root workdir under an existing parent accepted")
	}
	after, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(after) {
		t.Fatalf("parent %q mutated by refused request: %d -> %d entries", parent, len(before), len(after))
	}
}
