//go:build unix

package record

import (
	"os/exec"
	"syscall"
)

// applyExecutionAttrs puts the child into its own process group so the timeout
// path can SIGKILL the whole tree, not just the root that happened to reap.
// prepareScopeCgroup may additionally set UseCgroupFD on the same SysProcAttr.
func applyExecutionAttrs(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

func processGroupKillSupported() bool { return true }

// killProcessGroup SIGKILLs the negative pgid (whole tree) and then the leader
// itself, best effort.
func killProcessGroup(pid int) {
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	_ = syscall.Kill(pid, syscall.SIGKILL)
}
