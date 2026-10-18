// Package accesscontrol describes read-only security configuration and state.
// Neither declarations nor state snapshots are individual enforcement decisions.
package accesscontrol

import (
	"fmt"
	"strconv"
	"time"
)

const StateSchema = "agentprovenance.access_control_state/v1"

type Options struct {
	AppArmor bool
	Seccomp  bool
}

type State struct {
	Status      string `json:"status"`
	Source      string `json:"source,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Label       string `json:"label,omitempty"`
	Mode        string `json:"mode,omitempty"`
	ModeNumber  *int   `json:"mode_number,omitempty"`
	FilterCount *int   `json:"filter_count,omitempty"`
	NoNewPrivs  *int   `json:"no_new_privs,omitempty"`
}

type TaskIdentity struct {
	Status       string `json:"status"`
	Reason       string `json:"reason,omitempty"`
	PID          int    `json:"pid"`
	TID          int    `json:"tid"`
	StartTicks   string `json:"start_ticks,omitempty"`
	PIDNamespace string `json:"pid_namespace,omitempty"`
	CgroupID     string `json:"cgroup_id,omitempty"`
	CgroupPath   string `json:"cgroup_path,omitempty"`
	CgroupReason string `json:"cgroup_reason,omitempty"`
}

type Snapshot struct {
	SchemaVersion string       `json:"schema_version"`
	EvidenceKind  string       `json:"evidence_kind"`
	Source        string       `json:"source"`
	HostID        string       `json:"host_id,omitempty"`
	BootID        string       `json:"boot_id,omitempty"`
	StartedAt     string       `json:"started_at"`
	ObservedAt    string       `json:"observed_at"`
	Identity      TaskIdentity `json:"identity"`
	AppArmor      State        `json:"apparmor"`
	Seccomp       State        `json:"seccomp"`
}

// Declaration records the API field that was observed, including absence. The
// source path and resource version refer to configuration, not kernel state.
type Declaration struct {
	Mechanism        string  `json:"mechanism"`
	EvidenceKind     string  `json:"evidence_kind"`
	Status           string  `json:"status"`
	Source           string  `json:"source"`
	ResourceVersion  string  `json:"resource_version,omitempty"`
	ObservedAt       string  `json:"observed_at"`
	ProfileType      string  `json:"profile_type,omitempty"`
	LocalhostProfile string  `json:"localhost_profile,omitempty"`
	AnnotationValue  *string `json:"annotation_value,omitempty"`
}

func newSnapshot(pid, tid int, opts Options) Snapshot {
	s := Snapshot{SchemaVersion: StateSchema, EvidenceKind: "state_snapshot", Source: "procfs",
		StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Identity:  TaskIdentity{Status: "unavailable", PID: pid, TID: tid},
		AppArmor:  State{Status: "disabled", Reason: "collection_disabled"}, Seccomp: State{Status: "disabled", Reason: "collection_disabled"}}
	if opts.AppArmor {
		s.AppArmor = State{Status: "unavailable", Reason: "not_read"}
	}
	if opts.Seccomp {
		s.Seccomp = State{Status: "unavailable", Reason: "not_read"}
	}
	return s
}

func ValidateSnapshot(s Snapshot) error {
	if s.SchemaVersion != StateSchema || s.EvidenceKind != "state_snapshot" || s.Source != "procfs" {
		return fmt.Errorf("access control state requires versioned procfs snapshot")
	}
	start, e1 := time.Parse(time.RFC3339Nano, s.StartedAt)
	end, e2 := time.Parse(time.RFC3339Nano, s.ObservedAt)
	if e1 != nil || e2 != nil || end.Before(start) || s.Identity.PID < 1 || s.Identity.TID < 1 {
		return fmt.Errorf("access control state requires task identity and observation interval")
	}
	if s.Identity.Status != "observed" && s.Identity.Status != "unavailable" && s.Identity.Status != "unsupported" {
		return fmt.Errorf("invalid access control task status")
	}
	if s.Identity.Status == "observed" {
		if _, err := strconv.ParseUint(s.Identity.StartTicks, 10, 64); err != nil {
			return fmt.Errorf("observed task requires procfs start ticks")
		}
	} else if s.Identity.StartTicks != "" || s.Identity.CgroupID != "" || s.Identity.CgroupPath != "" {
		return fmt.Errorf("unavailable task cannot contain observed identity values")
	}
	if s.Identity.CgroupID != "" {
		if n, err := strconv.ParseUint(s.Identity.CgroupID, 10, 64); err != nil || n == 0 || s.Identity.CgroupReason != "" {
			return fmt.Errorf("invalid observed cgroup identity")
		}
	}
	for _, state := range []State{s.AppArmor, s.Seccomp} {
		switch state.Status {
		case "observed":
			if s.Identity.Status != "observed" || state.Source == "" {
				return fmt.Errorf("observed security state requires observed task and source")
			}
		case "disabled", "unavailable", "unsupported":
			if state.Label != "" || state.Mode != "" || state.ModeNumber != nil || state.FilterCount != nil || state.NoNewPrivs != nil {
				return fmt.Errorf("unavailable security state cannot contain observed values")
			}
		default:
			return fmt.Errorf("invalid security state status")
		}
	}
	if s.Seccomp.Status == "observed" {
		if s.Seccomp.Source != "status" || s.Seccomp.ModeNumber == nil || *s.Seccomp.ModeNumber < 0 || *s.Seccomp.ModeNumber > 2 ||
			s.Seccomp.Mode != []string{"disabled", "strict", "filter"}[*s.Seccomp.ModeNumber] {
			return fmt.Errorf("invalid observed seccomp mode")
		}
		if (s.Seccomp.FilterCount != nil && *s.Seccomp.FilterCount < 0) || (s.Seccomp.NoNewPrivs != nil && (*s.Seccomp.NoNewPrivs < 0 || *s.Seccomp.NoNewPrivs > 1)) {
			return fmt.Errorf("invalid observed seccomp counters")
		}
	}
	if s.AppArmor.Status == "observed" && (s.AppArmor.Source != "attr/apparmor/current" || s.AppArmor.Label == "") {
		return fmt.Errorf("observed AppArmor state requires a mechanism-specific label source")
	}
	if len(s.AppArmor.Label) > 8192 || len(s.Identity.CgroupPath) > 4096 {
		return fmt.Errorf("access control state field exceeds size limit")
	}
	return nil
}
