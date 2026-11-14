//go:build linux

package record

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// scopeCgroupParent is the cgroup v2 subtree under which each record scope gets
// its own leaf cgroup. It must be a delegated/writable cgroup v2 directory
// (running as root, or a systemd user slice delegated to us). Overridable for
// deployments that delegate a different subtree.
var scopeCgroupParent = envOr("AGENTPROV_CGROUP_PARENT", "/sys/fs/cgroup/agentprov")

// prepareScopeCgroup creates a dedicated cgroup v2 leaf for this record scope and
// arranges (via SysProcAttr.UseCgroupFD) for the child to be born inside it at
// clone time -- so the child AND every descendant it forks carry this cgroup id
// with zero race. It returns the cgroup id as the decimal cgroup inode, which is
// exactly what the eBPF sensor emits on cgroup v2. The open directory also
// anchors cancellation to this execution rather than a reused PID or path.
//
// On ANY failure (no cgroup v2, not delegated, insufficient privilege) it
// degrades to the synthetic logical id, so record still works -- it just loses
// the exact cgroup join and falls back to the pid/time tiers, same as before.
func prepareScopeCgroup(cmd *exec.Cmd, attemptID string) executionCgroup {
	fallback := logicalCgroup(attemptID)
	if err := os.MkdirAll(scopeCgroupParent, 0o755); err != nil {
		return fallback
	}
	dir := filepath.Join(scopeCgroupParent, sanitizeCgroupName(attemptID))
	// Never adopt a pre-existing scope, even after a sanitized-name collision.
	if err := os.Mkdir(dir, 0o755); err != nil {
		return fallback
	}
	// Hold the cgroup directory open: its fd is what the kernel uses to place the
	// child at clone time. Keep it through completion hooks so cancellation and
	// collector end boundaries refer to this scope until final cleanup.
	dirFile, err := os.Open(dir)
	if err != nil {
		_ = os.Remove(dir)
		return fallback
	}
	info, err := dirFile.Stat()
	if err != nil {
		_ = dirFile.Close()
		_ = os.Remove(dir)
		return fallback
	}
	_, ok := info.Sys().(*syscall.Stat_t)
	var fs unix.Statfs_t
	if !ok || unix.Fstatfs(int(dirFile.Fd()), &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		_ = dirFile.Close()
		_ = os.Remove(dir)
		return fallback
	}

	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.UseCgroupFD = true
	cmd.SysProcAttr.CgroupFD = int(dirFile.Fd())
	return ownedScopeCgroup(dirFile, info, dir)
}

func ownedScopeCgroup(dirFile *os.File, info os.FileInfo, dir string) executionCgroup {
	st := info.Sys().(*syscall.Stat_t)
	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			// Leave populated scopes for reconciliation, and never remove a
			// replacement directory created under the same name.
			if current, err := os.Stat(dir); err == nil && os.SameFile(info, current) {
				_ = os.Remove(dir)
			}
			_ = dirFile.Close()
		})
	}
	openControl := func(name string, flags int) (*os.File, error) {
		fd, err := unix.Openat(int(dirFile.Fd()), name, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(fd), name), nil
	}
	return executionCgroup{
		id: strconv.FormatUint(st.Ino, 10), cleanup: cleanup, anchor: cgroupRecoveryAnchor(dirFile),
		kill: func() error {
			f, err := openControl("cgroup.kill", unix.O_WRONLY)
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = f.WriteString("1")
			return err
		},
		empty: func() (bool, error) {
			f, err := openControl("cgroup.events", unix.O_RDONLY)
			if err != nil {
				return false, err
			}
			defer f.Close()
			raw, err := io.ReadAll(io.LimitReader(f, 4096))
			if err != nil {
				return false, err
			}
			for _, line := range strings.Split(string(raw), "\n") {
				fields := strings.Fields(line)
				if len(fields) == 2 && fields[0] == "populated" {
					switch fields[1] {
					case "0":
						return true, nil
					case "1":
						return false, nil
					}
				}
			}
			return false, fmt.Errorf("cgroup.events has no valid populated field")
		},
	}
}

// sanitizeCgroupName keeps the leaf directory name to a safe, path-component-only
// form so a crafted attempt id can never escape scopeCgroupParent.
func sanitizeCgroupName(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, s)
	if s == "" {
		return "scope"
	}
	return s
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
