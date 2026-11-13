//go:build !linux

package record

import "os/exec"

// prepareScopeCgroup is a no-op on non-Linux platforms: there is no cgroup v2 to
// place the child in, so the binding keeps the synthetic logical scope id it has
// always used ("agentprov-record-<attemptID>").
func prepareScopeCgroup(_ *exec.Cmd, attemptID string) executionCgroup {
	return logicalCgroup(attemptID)
}
