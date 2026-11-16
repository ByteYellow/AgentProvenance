package capturemanifest

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/handoff"
	"github.com/byteyellow/agentprovenance/internal/observability"
	"github.com/byteyellow/agentprovenance/internal/sensor"
)

func asJSON(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestObservationKeepsEachSensorBoundaryIdentity(t *testing.T) {
	db, paths := testStore(t)
	at := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	start, end := caps(at, "attached"), caps(at.Add(time.Second), "failed")
	start.CollectorID, start.Revision = "before", 1
	start.Producer = &sensor.CapabilityProducer{Placement: "host_kernel", PlacementBasis: "operator_config", BootID: "host-boot", Kernel: "host-kernel", Version: "before-version"}
	end.CollectorID, end.Revision = "after", 3
	end.Producer = &sensor.CapabilityProducer{Placement: "guest_kernel", PlacementBasis: "operator_config", BootID: "guest-boot", Kernel: "guest-kernel", Version: "after-version"}
	start.AccessControlState = &sensor.StateCollectionCapability{AppArmor: true, Seccomp: true, Mode: "procfs_sampling"}
	put(t, db, paths, "r", "runtime_capture", "capture/r", observability.RuntimeCaptureReport{
		SchemaVersion: observability.RuntimeCaptureSchema, RunID: "r", KernelState: "observed", Status: "partial",
		StartedAt: timestamp(at), EndedAt: timestamp(at.Add(time.Second)), CapabilitiesStart: &start, CapabilitiesEnd: &end,
	})
	r := all(t, db, "r", 1)[0]
	for i, want := range []struct{ boot, layer, version string }{{"host-boot", "host_kernel", "before-version"}, {"guest-boot", "guest_kernel", "after-version"}} {
		s := r.Snapshots[i]
		if s.Identity["boot_id"] != want.boot || s.Identity["producer_version"] != want.version {
			t.Fatalf("boundary %d lost source identity: %+v", i, s.Identity)
		}
		o, ok := asJSON(t, s)["observation"].(map[string]any)
		if !ok || o["layer"] != want.layer || o["layer_basis"] != "operator_config" || o["scope_kind"] != "collector" || o["scope_ref"] != s.Identity["collector_id"] {
			t.Fatalf("boundary %d has incorrect observation metadata: %+v", i, o)
		}
	}
	o, ok := asJSON(t, r)["observation"].(map[string]any)
	if !ok || o["layer"] != "mixed" || o["rule_version"] != "agentprov.capture_observation/v1" {
		t.Fatalf("capture boundaries collapsed: %+v", o)
	}
	for _, f := range r.Snapshots[0].Features {
		if f.Category == "access_control" {
			p, ok := asJSON(t, f)["policy_subject"].(map[string]any)
			if !ok || p["role"] != "unknown" || p["layer"] != "host_kernel" || p["basis"] != "state_collection_configuration" || f.Observed != nil {
				t.Fatalf("state collection became workload enforcement: %+v", f)
			}
		}
	}
}

func TestObservationDoesNotGuessUnspecifiedKernelPlacement(t *testing.T) {
	db, paths := testStore(t)
	at := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	c := caps(at, "attached")
	c.Producer = &sensor.CapabilityProducer{Placement: "local_kernel", BootID: "boot", Version: "old-version"}
	put(t, db, paths, "r", "runtime_capture", "capture/r", observability.RuntimeCaptureReport{
		SchemaVersion: observability.RuntimeCaptureSchema, RunID: "r", KernelState: "observed", Status: "observed", CapabilitiesStart: &c,
	})
	r := all(t, db, "r", 1)[0]
	o, ok := asJSON(t, r.Snapshots[0])["observation"].(map[string]any)
	if !ok || o["layer"] != "unknown" || o["layer_basis"] != "kernel_topology_not_recorded" || r.Snapshots[0].Identity["boot_id"] != "boot" {
		t.Fatalf("unqualified placement was guessed or producer identity discarded: %+v", r)
	}
}

func TestObservationSeparatesSentryFromReceiverPlacement(t *testing.T) {
	db, _ := testStore(t)
	sentryOpen(t, db, "r", "original", "connection", 1, 56, false, 0)
	r := all(t, db, "r", 1)[0]
	o, ok := asJSON(t, r)["observation"].(map[string]any)
	if !ok || o["layer"] != "sentry" || o["scope_kind"] != "sentry_connection" || o["scope_ref"] != "connection" || r.Placement != "host_receiver" {
		t.Fatalf("receiver placement confused with observation layer: %+v", r)
	}
	refs, ok := o["evidence_refs"].([]any)
	if !ok || len(refs) != 1 || refs[0] != r.EvidenceRef {
		t.Fatalf("observation has no source witness: %+v", o)
	}
}

func TestObservationPreservesExecutionCaptureDeliveryAxes(t *testing.T) {
	db, paths := testStore(t)
	c := handoff.Checkpoint{SchemaVersion: handoff.SchemaVersion, AttemptID: "attempt", Revision: 2, At: time.Now().UTC(),
		Source: handoff.Source{ProducerID: "caller", Namespace: "n", RunID: "source-run", Harness: "claude", SessionID: "session", ToolCallID: "call"},
		Target: handoff.Target{ProducerID: "guest", InstanceID: "instance", Generation: "generation"},
		State:  handoff.State{Execution: handoff.Succeeded, Capture: handoff.Incomplete, Delivery: handoff.Pending},
	}
	put(t, db, paths, "r", "execution_checkpoint", "checkpoint", c)
	r := all(t, db, "r", 1)[0]
	s, ok := asJSON(t, r)["execution_state"].(map[string]any)
	if !ok || s["execution"] != "succeeded" || s["capture"] != "incomplete" || s["delivery"] != "pending" {
		t.Fatalf("independent states lost: %+v", s)
	}
}
