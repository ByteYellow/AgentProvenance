//go:build !unix

package record

import "os/exec"

// applyExecutionAttrs is a no-op on platforms without POSIX process groups;
// the timeout still kills the root process via CommandContext's default Kill.
func applyExecutionAttrs(_ *exec.Cmd) {}

func processGroupKillSupported() bool { return false }

func killProcessGroup(_ int) {}
