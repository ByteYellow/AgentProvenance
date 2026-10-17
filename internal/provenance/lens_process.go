package provenance

import (
	"fmt"
	"sort"
	"time"

	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func lensProcessIdentity(ev lensEvent) telemetry.RuntimeProcessIdentity {
	if ev.processIdentity != nil {
		return *ev.processIdentity
	}
	return telemetry.ProcessGraphIdentity(telemetry.EventRecord{
		ID: ev.ID, Source: ev.Source, Payload: ev.Payload, PID: ev.PID, PPID: ev.PPID, TGID: ev.TGID,
	})
}

func addRuntimeProcessNodes(events map[string]lensEvent, add func(GraphLensNode)) {
	ordered := make([]lensEvent, 0, len(events))
	identities := make(map[string]telemetry.RuntimeProcessIdentity, len(events))
	for _, ev := range events {
		ordered = append(ordered, ev)
		identities[ev.ID] = lensProcessIdentity(ev)
	}
	sort.Slice(ordered, func(i, j int) bool {
		a, _ := time.Parse(time.RFC3339Nano, ordered[i].CreatedAt)
		b, _ := time.Parse(time.RFC3339Nano, ordered[j].CreatedAt)
		if a.Equal(b) {
			return ordered[i].ID < ordered[j].ID
		}
		return a.After(b)
	})
	nodes := map[string]GraphLensNode{}
	ensure := func(ref telemetry.RuntimeProcessNode, role string) {
		if ref.ID == "" {
			return
		}
		if _, exists := nodes[ref.ID]; exists {
			return
		}
		data := map[string]any{"pid": ref.PID, "identity_basis": ref.Basis}
		if ref.InstanceID != "" {
			data["process_instance_id"] = ref.InstanceID
		}
		if role == "tgid" {
			data["tgid"] = ref.PID
		}
		nodes[ref.ID] = GraphLensNode{ID: ref.ID, Kind: "runtime_process", Subtype: fmt.Sprintf("%s %d", role, ref.PID), Label: fmt.Sprintf("%s %d", role, ref.PID), TrustOrigin: "runtime_observed", Data: data}
	}
	for _, ev := range ordered {
		refs := identities[ev.ID]
		ensure(refs.Process, "pid")
		ensure(refs.Parent, "pid")
		ensure(refs.ThreadGroup, "tgid")
	}
	// Pick the latest label within the strongest evidence tier, always keyed by
	// the graph identity. Parent placeholders never borrow a reused PID's name.
	for _, tier := range []string{"execve", "process_observed", ""} {
		for _, ev := range ordered {
			if tier != "" && ev.Type != tier {
				continue
			}
			id := identities[ev.ID].Process.ID
			node, ok := nodes[id]
			if !ok || node.Data["command"] != nil {
				continue
			}
			if name := payloadString(ev.Payload, "command", "cmdline", "comm"); name != "" {
				node.Label, node.Data["command"] = name, name
				nodes[id] = node
			}
		}
	}
	// Only legacy graphs use a numeric TGID label cache. New thread-group nodes
	// get a name from the actual leader's lifetime, if that leader was captured.
	leaders := map[string]bool{}
	for _, ev := range ordered {
		refs := identities[ev.ID]
		if refs.Version != "" || ev.PID <= 0 || refs.ThreadGroup.ID == "" {
			continue
		}
		name := payloadString(ev.Payload, "command", "cmdline", "comm")
		if name == "" {
			continue
		}
		id := refs.ThreadGroup.ID
		node := nodes[id]
		if node.Data["command"] == nil || (ev.PID == ev.TGID && !leaders[id]) {
			node.Label, node.Data["command"] = name, name
			nodes[id], leaders[id] = node, ev.PID == ev.TGID
		}
	}
	for _, node := range nodes {
		add(node)
	}
}
