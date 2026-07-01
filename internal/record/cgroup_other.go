//go:build !linux

package record

import "os/exec"

// prepareScopeCgroup is a no-op on non-Linux platforms: there is no cgroup v2 to
// place the child in, so the binding keeps the synthetic logical scope id it has
// always used ("agentprov-record-<attemptID>"). Behavior is identical to before
// the real-cgroup seam existed, which keeps the darwin build and its tests
// unchanged. The returned cleanup is a no-op.
func prepareScopeCgroup(_ *exec.Cmd, attemptID string) (cgroupID string, cleanup func()) {
	return "agentprov-record-" + attemptID, func() {}
}
