package record

import "time"

// ScopeRecoveryAnchor supplements the kernel cgroup ID with its boot and
// filesystem identity. It is saved before launch, not reconstructed from a PID.
type ScopeRecoveryAnchor struct {
	SchemaVersion string `json:"schema_version"`
	BootID        string `json:"boot_id"`
	FilesystemID  string `json:"filesystem_id"`
}

type RecoveredScope struct {
	scope  ExecutionScope
	cgroup executionCgroup
}

func (r *RecoveredScope) Observe() *ScopeObservation { return r.cgroup.observe(r.scope) }

func (r *RecoveredScope) Close() { r.cgroup.cleanup() }

// A recovered controller owns the reopened cgroup, not the old numeric PID.
// Signal failure never falls back to killing that PID or its process group.
func (r *RecoveredScope) Stop() *StopReport {
	s := executionStop{cgroup: r.cgroup, report: &StopReport{
		Method: "cgroup_kill", RequestedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}}
	if err := r.cgroup.kill(); err != nil {
		s.report.Error = err.Error()
	} else {
		s.report.SignalSent = true
	}
	return s.finish()
}
