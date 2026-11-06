//go:build unix

package record

import (
	"os/exec"
	"syscall"
)

// applyExecutionAttrs isolates noninteractive jobs for group cancellation.
// Local wrappers inherit the terminal's foreground group for input and signals.
// prepareScopeCgroup may additionally set UseCgroupFD on the same SysProcAttr.
func applyExecutionAttrs(cmd *exec.Cmd, foreground bool) bool {
	if foreground {
		return false
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	return true
}

func commandExitCode(err *exec.ExitError) int {
	if status, ok := err.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}
	return err.ExitCode()
}

// killProcessGroup SIGKILLs the negative pgid (whole tree) and then the leader
// itself, best effort.
func killProcessGroup(pid int) {
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	_ = syscall.Kill(pid, syscall.SIGKILL)
}
