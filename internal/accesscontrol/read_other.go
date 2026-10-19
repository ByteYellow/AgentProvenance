//go:build !linux

package accesscontrol

import "time"

func ReadTask(pid, tid int, opts Options) Snapshot {
	s := newSnapshot(pid, tid, opts)
	s.Identity.Status, s.Identity.Reason = "unsupported", "linux_required"
	for _, state := range []*State{&s.AppArmor, &s.Seccomp} {
		if state.Status != "disabled" {
			*state = State{Status: "unsupported", Reason: "linux_required"}
		}
	}
	s.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return s
}
