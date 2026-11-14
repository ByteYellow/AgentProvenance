//go:build linux

package record

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func cgroupRecoveryAnchor(dir *os.File) *ScopeRecoveryAnchor {
	var fs unix.Statfs_t
	if unix.Fstatfs(int(dir.Fd()), &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(boot)) == "" {
		return nil
	}
	return &ScopeRecoveryAnchor{SchemaVersion: "agentprovenance.linux_cgroup_recovery/v1",
		BootID: strings.TrimSpace(string(boot)), FilesystemID: fmt.Sprintf("%08x:%08x", uint32(fs.Fsid.Val[0]), uint32(fs.Fsid.Val[1]))}
}

func OpenRecoveredScope(scope ExecutionScope) (*RecoveredScope, error) {
	if scope.ScopeKind != "cgroup" || scope.AttemptID == "" || scope.AttemptID != sanitizeCgroupName(scope.AttemptID) || scope.RecoveryAnchor == nil {
		return nil, fmt.Errorf("execution scope has no recoverable kernel anchor")
	}
	dir := filepath.Join(scopeCgroupParent, scope.AttemptID)
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open execution scope: %w", err)
	}
	f := os.NewFile(uintptr(fd), dir)
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	anchor := cgroupRecoveryAnchor(f)
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || anchor == nil || *anchor != *scope.RecoveryAnchor || strconv.FormatUint(st.Ino, 10) != scope.CgroupID {
		f.Close()
		return nil, fmt.Errorf("execution scope recovery identity mismatch")
	}
	return &RecoveredScope{scope: scope, cgroup: ownedScopeCgroup(f, info, dir)}, nil
}
