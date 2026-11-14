//go:build linux

package record

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func recoveryScopeFixture(t *testing.T) (executionCgroup, ExecutionScope, *exec.Cmd) {
	t.Helper()
	if os.Getenv("AGENTPROV_TEST_REQUIRE_CGROUP") != "1" {
		t.Skip("set AGENTPROV_TEST_REQUIRE_CGROUP=1 with delegated cgroup v2 permissions")
	}
	id := fmt.Sprintf("recovery-%d", time.Now().UnixNano())
	cmd := exec.Command("sleep", "60")
	group := prepareScopeCgroup(cmd, id)
	t.Cleanup(group.cleanup)
	if group.anchor == nil || group.kill == nil {
		t.Fatal("fixture requires a real recoverable cgroup")
	}
	return group, ExecutionScope{AttemptID: id, CgroupID: group.id, ScopeKind: "cgroup", RecoveryAnchor: group.anchor}, cmd
}

func TestRecoveredScopeRequiresOriginalIdentity(t *testing.T) {
	_, original, _ := recoveryScopeFixture(t)
	for _, kind := range []string{"boot", "filesystem", "cgroup", "legacy", "logical", "traversal", "version"} {
		t.Run(kind, func(t *testing.T) {
			scope := original
			anchor := *scope.RecoveryAnchor
			scope.RecoveryAnchor = &anchor
			switch kind {
			case "boot":
				anchor.BootID = "another-boot"
			case "filesystem":
				anchor.FilesystemID = "another-filesystem"
			case "cgroup":
				scope.CgroupID = "1"
			case "legacy":
				scope.RecoveryAnchor = nil
			case "logical":
				scope.ScopeKind = "logical_process_scope"
			case "traversal":
				scope.AttemptID = "../" + scope.AttemptID
			case "version":
				anchor.SchemaVersion = "unknown"
			}
			if recovered, err := OpenRecoveredScope(scope); err == nil {
				recovered.Close()
				t.Fatal("mismatched scope was adopted")
			}
		})
	}
	live, err := OpenRecoveredScope(original)
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	if o := live.Observe(); o.Empty == nil || !*o.Empty {
		t.Fatalf("original scope unreadable: %+v", o)
	}
}

func TestRecoveredScopeNeverFollowsReplacement(t *testing.T) {
	_, original, _ := recoveryScopeFixture(t)
	live, err := OpenRecoveredScope(original)
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	dir := filepath.Join(scopeCgroupParent, original.AttemptID)
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sleep", "60")
	replacement := prepareScopeCgroup(cmd, original.AttemptID)
	defer replacement.cleanup()
	if replacement.id == original.CgroupID || replacement.anchor == nil {
		t.Fatal("fixture did not replace the original cgroup")
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = replacement.kill(); _ = cmd.Wait() }()
	if other, err := OpenRecoveredScope(original); err == nil {
		other.Close()
		t.Fatal("reused path was adopted after restart")
	}
	report := live.Stop()
	if report.SignalSent || report.Error == "" {
		t.Fatalf("removed cgroup claimed successful stopping: %+v", report)
	}
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("stale recovered handle killed replacement process: %v", err)
	}
	live.Close()
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("old cleanup removed replacement: %v", err)
	}
}
