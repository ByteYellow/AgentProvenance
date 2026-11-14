package telemetry

import (
	"encoding/json"
	"time"

	"github.com/byteyellow/agentprovenance/internal/accesscontrol"
	"github.com/byteyellow/agentprovenance/internal/correlation"
)

// A failed read belongs to the triggering collection scope, not to a task
// independently observed in procfs. Resolve at trigger time, even if the read
// finished after the execution binding closed.
func nativeSamplingScope(db correlation.Queryer, event IngestEvent) (*correlation.Match, error) {
	if event.Source != "procfs_access_control" || event.EventType != "access_control_state" ||
		event.CgroupID != "" || event.CaptureCgroupID == "" {
		return nil, nil
	}
	var snapshot accesscontrol.Snapshot
	if err := json.Unmarshal([]byte(event.Payload), &snapshot); err != nil {
		return nil, err
	}
	if err := accesscontrol.ValidateSnapshot(snapshot); err != nil {
		return nil, err
	}
	trigger := snapshot.SamplingTrigger
	if snapshot.Identity.Status == "observed" || trigger == nil || trigger.CgroupID != event.CaptureCgroupID {
		return nil, nil
	}
	triggeredAt, _ := time.Parse(time.RFC3339Nano, trigger.ObservedAt)
	observedAt, _ := time.Parse(time.RFC3339Nano, snapshot.ObservedAt)
	if triggeredAt.After(observedAt) {
		return nil, nil
	}
	match, ok, err := correlation.Resolve(db, correlation.RawIdentity{
		RunID: event.RunID, CgroupID: trigger.CgroupID, Timestamp: trigger.ObservedAt,
	})
	if err != nil || !ok || match.Ambiguous || match.RunID == "" {
		return nil, err
	}
	match.Method, match.ScopeOnly = "sampling_trigger_scope:cgroup_id+time", true
	match.SessionID, match.AttemptID, match.ToolCallID, match.ProcessID = "", "", "", ""
	match.ContainerID, match.CgroupID, match.PID, match.RootPID = "", "", 0, 0
	return &match, nil
}

func nativeSamplingGap(event IngestEvent) bool {
	if event.Source != "procfs_access_control" || event.EventType != "access_control_state" {
		return false
	}
	var snapshot accesscontrol.Snapshot
	if json.Unmarshal([]byte(event.Payload), &snapshot) != nil {
		return false
	}
	return snapshot.Identity.Status != "observed" ||
		snapshot.AppArmor.Status == "unavailable" || snapshot.AppArmor.Status == "unsupported" ||
		snapshot.Seccomp.Status == "unavailable" || snapshot.Seccomp.Status == "unsupported"
}

func validateAccessStateBody(body map[string]any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	var snapshot accesscontrol.Snapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return err
	}
	return accesscontrol.ValidateSnapshot(snapshot)
}
