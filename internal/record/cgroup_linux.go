//go:build linux

package record

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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
// exactly what the eBPF sensor emits (bpf_get_current_cgroup_id returns the
// kernfs id == the cgroup directory inode on cgroup v2). Independent kernel
// telemetry then joins to this scope through resolveByCgroup at 0.98.
//
// On ANY failure (no cgroup v2, not delegated, insufficient privilege) it
// degrades to the synthetic logical id, so record still works -- it just loses
// the exact cgroup join and falls back to the pid/time tiers, same as before.
//
// NOTE: the Linux path (real cgroup creation + UseCgroupFD placement + the
// cgroup-id==inode equivalence) must be validated end-to-end on the lab VM with
// the sensor running; it cannot be exercised on the darwin dev host. The
// fallback path is what the unit tests cover.
func prepareScopeCgroup(cmd *exec.Cmd, attemptID string) (cgroupID string, cleanup func()) {
	fallback := "agentprov-record-" + attemptID
	noop := func() {}

	dir := filepath.Join(scopeCgroupParent, sanitizeCgroupName(attemptID))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fallback, noop
	}
	// Hold the cgroup directory open: its fd is what the kernel uses to place the
	// child at clone time. It must stay open until after cmd.Start(), so the
	// caller-deferred cleanup closes it.
	dirFile, err := os.Open(dir)
	if err != nil {
		_ = os.Remove(dir)
		return fallback, noop
	}
	info, err := dirFile.Stat()
	if err != nil {
		_ = dirFile.Close()
		_ = os.Remove(dir)
		return fallback, noop
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		_ = dirFile.Close()
		_ = os.Remove(dir)
		return fallback, noop
	}

	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.UseCgroupFD = true
	cmd.SysProcAttr.CgroupFD = int(dirFile.Fd())

	cleanup = func() {
		_ = dirFile.Close()
		// Best-effort: an empty leaf cgroup can be rmdir'd once its processes
		// have exited. If it is still populated (a descendant outlived us) the
		// remove fails harmlessly and the dir is reaped on the next boot / by
		// the parent slice.
		_ = os.Remove(dir)
	}
	return strconv.FormatUint(st.Ino, 10), cleanup
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
