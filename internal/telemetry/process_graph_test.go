package telemetry

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProcessGraphIdentityContract(t *testing.T) {
	child, parent := lifecycleBoot+":42:200", lifecycleBoot+":1:100"
	for _, tc := range []struct {
		name, source, instance, parent, group   string
		lifetime, parentLifetime, groupLifetime bool
	}{
		{"native", "agentprov_ebpf", child, parent, lifecycleBoot + ":40:100", true, true, true},
		{"malformed", "agentprov_ebpf", "invalid", parent, "", false, false, false},
		{"wrong pid", "agentprov_ebpf", lifecycleBoot + ":41:200", parent, "", false, false, false},
		{"zero birth", "agentprov_ebpf", lifecycleBoot + ":42:0", parent, "", false, false, false},
		{"parent newer", "agentprov_ebpf", child, lifecycleBoot + ":1:300", "", true, false, false},
		{"parent different boot", "agentprov_ebpf", child, "11234567-89ab-cdef-0123-456789abcdef:1:100", "", true, false, false},
		{"external source", "falco_jsonl", child, parent, "", false, false, false},
		{"canonical", "agentprov_ebpf", strings.ToUpper(lifecycleBoot) + ":042:0200", parent, "", true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{"process_instance_id": tc.instance, "parent_process_instance_id": tc.parent, "thread_group_instance_id": tc.group})
			for _, wrapper := range []string{string(body), `{"raw":` + string(body) + `,"correlation":{}}`, `{"attempt_id":"attempt","payload":{"raw":` + string(body) + `}}`} {
				payload, err := stampProcessGraph(wrapper)
				if err != nil {
					t.Fatal(err)
				}
				id := ProcessGraphIdentity(EventRecord{ID: "evt", Source: tc.source, PID: 42, PPID: 1, TGID: 40, Payload: payload})
				if (id.Process.InstanceID != "") != tc.lifetime || (id.Parent.InstanceID != "") != tc.parentLifetime || (id.ThreadGroup.InstanceID != "") != tc.groupLifetime {
					t.Fatalf("unexpected identity: %+v", id)
				}
				if tc.lifetime && id.Process.InstanceID != child {
					t.Fatalf("noncanonical lifetime: %+v", id)
				}
				if !tc.lifetime && id.Process.ID != "runtime_process/observation/evt/pid" {
					t.Fatalf("unsafe fallback: %+v", id)
				}
			}
		})
	}
	legacy := ProcessGraphIdentity(EventRecord{ID: "old", PID: 42, PPID: 1, TGID: 40, Payload: `{}`})
	if legacy.Process.ID != "runtime_process/pid/42" || legacy.Parent.ID != "runtime_process/pid/1" || legacy.ThreadGroup.ID != "runtime_process/tgid/40" {
		t.Fatalf("legacy changed: %+v", legacy)
	}
}

func TestStampProcessGraphPreservesIntegerPrecision(t *testing.T) {
	payload, err := stampProcessGraph(`{"length":18446744073709551615,"command":"true","runtime_process_identity":"old"}`)
	if err != nil || !strings.Contains(payload, "18446744073709551615") || !strings.Contains(payload, RuntimeProcessGraphVersion) {
		t.Fatalf("stamp: %s %v", payload, err)
	}
}

func TestProcessGraphSeparatesExplicitHosts(t *testing.T) {
	var ids []RuntimeProcessIdentity
	for _, host := range []string{"host-a", "host-b", ""} {
		raw, _ := json.Marshal(map[string]any{"host_id": host, "process_instance_id": lifecycleBoot + ":42:200",
			"parent_process_instance_id": lifecycleBoot + ":1:100", "thread_group_instance_id": lifecycleBoot + ":40:100"})
		payload, err := stampProcessGraph(string(raw))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, ProcessGraphIdentity(EventRecord{ID: "evt", Source: "agentprov_ebpf", PID: 42, PPID: 1, TGID: 40, Payload: payload}))
	}
	for i := range ids {
		for j := 0; j < i; j++ {
			if ids[i].Process.ID == ids[j].Process.ID || ids[i].Parent.ID == ids[j].Parent.ID || ids[i].ThreadGroup.ID == ids[j].ThreadGroup.ID {
				t.Fatalf("explicit host identity ignored: %+v / %+v", ids[i], ids[j])
			}
		}
	}
}

func TestProcessGraphKeepsV2IdentityAndRejectsConflictingV3Boot(t *testing.T) {
	body := map[string]any{"host_id": "host-a", "process_instance_id": lifecycleBoot + ":42:200", "parent_process_instance_id": lifecycleBoot + ":1:100"}
	for _, version := range []string{RuntimeProcessGraphV2, RuntimeProcessGraphVersion} {
		body["runtime_process_identity"] = version
		body["boot_id"] = "11234567-89ab-cdef-0123-456789abcdef"
		raw, _ := json.Marshal(body)
		id := ProcessGraphIdentity(EventRecord{ID: "evt", Source: "agentprov_ebpf", PID: 42, PPID: 1, Payload: string(raw)})
		if version == RuntimeProcessGraphV2 {
			if id.Process.ID != "runtime_process/instance/"+lifecycleBoot+":42:200" || id.Process.HostID != "" {
				t.Fatalf("historical v2 evidence reinterpreted: %+v", id)
			}
		} else if id.Process.ID != "runtime_process/observation/evt/pid" {
			t.Fatalf("contradictory boot accepted: %+v", id)
		}
	}
}
