package telemetry

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/byteyellow/agentprovenance/internal/correlation"
)

const (
	RuntimeProcessGraphVersion = "agentprov.runtime_process/v3"
	RuntimeProcessGraphV2      = "agentprov.runtime_process/v2"
)

type RuntimeProcessNode struct {
	ID         string
	PID        int64
	InstanceID string
	HostID     string
	Basis      string
}

type RuntimeProcessIdentity struct {
	Version     string
	Process     RuntimeProcessNode
	Parent      RuntimeProcessNode
	ThreadGroup RuntimeProcessNode
}

// Stamp new ingests, not imported evidence. Readers retain the historical PID
// graph for unversioned records without silently rewriting their signed edges.
func stampProcessGraph(payload string) (string, error) {
	var body map[string]json.RawMessage
	if err := json.Unmarshal([]byte(payload), &body); err != nil {
		return "", err
	}
	if body == nil {
		return "", fmt.Errorf("process graph payload must be an object")
	}
	version, _ := json.Marshal(RuntimeProcessGraphVersion)
	body["runtime_process_identity"] = version
	raw, err := json.Marshal(body)
	return string(raw), err
}

// ProcessGraphIdentity is shared by ingest, verification, and query projections.
// An observation-local node preserves a captured PID/PPID/TGID without assuming
// that the same number in another event denotes the same process lifetime.
func ProcessGraphIdentity(event EventRecord) RuntimeProcessIdentity {
	body, _ := decodePayloadObject(event.Payload)
	version, _ := body["runtime_process_identity"].(string)
	body = unwrapStoredPayload(body)
	field := func(key string) string { value, _ := body[key].(string); return value }
	identity := RuntimeProcessIdentity{Version: version}
	if identity.Version == "" {
		legacy := func(kind string, pid int64) RuntimeProcessNode {
			if pid <= 0 {
				return RuntimeProcessNode{}
			}
			return RuntimeProcessNode{ID: fmt.Sprintf("runtime_process/%s/%d", kind, pid), PID: pid, Basis: "legacy_pid"}
		}
		identity.Process = legacy("pid", event.PID)
		identity.Parent = legacy("pid", event.PPID)
		identity.ThreadGroup = legacy("tgid", event.TGID)
		return identity
	}
	observation := func(role string, pid int64) RuntimeProcessNode {
		if pid <= 0 || event.ID == "" {
			return RuntimeProcessNode{}
		}
		return RuntimeProcessNode{ID: "runtime_process/observation/" + event.ID + "/" + role, PID: pid, Basis: "event_observation"}
	}
	identity.Process = observation("pid", event.PID)
	if event.PID > 0 && event.PPID != event.PID {
		identity.Parent = observation("ppid", event.PPID)
	}
	if event.PID > 0 && event.TGID != event.PID {
		identity.ThreadGroup = observation("tgid", event.TGID)
	}
	if (identity.Version != RuntimeProcessGraphVersion && identity.Version != RuntimeProcessGraphV2) || event.Source != "agentprov_ebpf" {
		return identity
	}
	instance := canonicalProcessInstance(field("process_instance_id"), event.PID)
	if instance == "" {
		return identity
	}
	if identity.Version == RuntimeProcessGraphVersion {
		if _, valid := correlation.CaptureOrigin([]map[string]any{body}, event.PID); !valid {
			return identity
		}
	}
	node := func(id string, pid int64) RuntimeProcessNode {
		prefix, host := "runtime_process/", ""
		if identity.Version == RuntimeProcessGraphVersion {
			host = field("host_id")
			if host != "" {
				prefix += fmt.Sprintf("host/%x/", sha256.Sum256([]byte(host)))
			}
		}
		return RuntimeProcessNode{ID: prefix + "instance/" + id, PID: pid, InstanceID: id, HostID: host, Basis: "kernel_process_instance"}
	}
	identity.Process = node(instance, event.PID)
	if parent := canonicalProcessInstance(field("parent_process_instance_id"), event.PPID); correlation.RelatedProcessLifetime(parent, instance) && event.PPID != event.PID {
		identity.Parent = node(parent, event.PPID)
	}
	if group := canonicalProcessInstance(field("thread_group_instance_id"), event.TGID); correlation.RelatedProcessLifetime(group, instance) && event.TGID != event.PID {
		identity.ThreadGroup = node(group, event.TGID)
	}
	return identity
}

func canonicalProcessInstance(instance string, pid int64) string {
	return correlation.CanonicalProcessInstance(instance, pid)
}
