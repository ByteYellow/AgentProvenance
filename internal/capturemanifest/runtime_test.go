package capturemanifest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/handoff"
	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/byteyellow/agentprovenance/internal/runtimeadapter"
	"github.com/byteyellow/agentprovenance/internal/seccheck"
	"github.com/byteyellow/agentprovenance/internal/sensor"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func runtimeCheckpoint() handoff.Checkpoint {
	return handoff.Checkpoint{SchemaVersion: handoff.SchemaVersion, AttemptID: "attempt", Revision: 2, At: time.Now().UTC(),
		Source: handoff.Source{ProducerID: "caller", Namespace: "n", RunID: "source-run", Harness: "claude", SessionID: "session", ToolCallID: "call"},
		Target: handoff.Target{ProducerID: "operator", InstanceID: "instance", Generation: "generation"},
		State:  handoff.State{Execution: handoff.Succeeded, Capture: handoff.Incomplete, Delivery: handoff.Pending}}
}

func sentryRuntimeCheckpoint() handoff.Checkpoint {
	c := runtimeCheckpoint()
	target := runtimeadapter.Target(c.Target)
	binding := runtimeadapter.Binding{Target: target, Mode: "runsc", ContainerID: "container", StateCreated: "2026-11-16T00:00:00Z"}
	c.PlatformBinding = &binding
	c.Runtime = &handoff.RuntimeReport{Execution: runtimeadapter.Execution{SchemaVersion: runtimeadapter.Schema,
		Binding: binding, OperationID: "operation", AttemptID: c.AttemptID, RunID: "r", State: "succeeded", RuntimeRelease: seccheck.RuntimeRelease,
		SentryPID: 44, SentryPIDBasis: "runsc_internal_pid_file"},
		Capture: &runtimeadapter.CaptureReport{ObservationLayer: "sentry", State: "incomplete", Gaps: []string{"shared_call_identity_unavailable"}}}
	for i, slot := range []**runtimeadapter.CapturePoint{&c.Runtime.Capture.Start, &c.Runtime.Capture.End} {
		connection := []string{"before", "after"}[i]
		scope := seccheck.Target{Registration: seccheck.Registration{Namespace: target.ProducerID, InstanceID: target.InstanceID,
			Generation: target.Generation, SandboxID: "sandbox", ContainerID: "container"}}
		*slot = &runtimeadapter.CapturePoint{Target: target, Scope: scope, ObservedAt: c.At.Add(time.Duration(i) * time.Second),
			Status: telemetry.SecCheckCollectStatus{CollectorID: "collector-" + connection, ProtocolVersion: seccheck.ProtocolVersion,
				ExpectedRuntimeRelease: seccheck.RuntimeRelease, Capabilities: seccheck.ReceiverCapabilities(), Targets: []telemetry.SecCheckTargetStatus{
					{Target: scope, State: "connected", ConnectionID: connection, AcceptedRecords: 20, ReportedDrops: 7}}}}
	}
	return c
}

func TestRuntimeCheckpointPreservesSentryBoundaryScope(t *testing.T) {
	db, paths := testStore(t)
	c := sentryRuntimeCheckpoint()
	put(t, db, paths, "r", "execution_checkpoint", "runtime", c)
	r := all(t, db, "r", 1)[0]
	if r.Observation.Layer != "sentry" || r.Observation.ScopeKind != "multiple_sentry_connections" || len(r.Snapshots) != 2 {
		t.Fatalf("runtime observation lost: %+v", r)
	}
	for i, connection := range []string{"before", "after"} {
		if r.Snapshots[i].Observation.ScopeRef != connection || r.Snapshots[i].Identity["collector_id"] != "collector-"+connection {
			t.Fatalf("runtime boundary identity changed: %+v", r.Snapshots[i])
		}
		for _, feature := range r.Snapshots[i].Features {
			if feature.Observed != nil || feature.Enabled != nil {
				t.Fatalf("receiver support became event coverage: %+v", feature)
			}
		}
	}
	if r.Identity["sentry_pid"] != "44" || r.Identity["pid"] != "" || r.Status != "incomplete" || r.ExecutionState.Execution != handoff.Succeeded {
		t.Fatalf("execution or PID domains collapsed: %+v", r)
	}
	for _, counter := range r.Loss {
		if counter.Scope != "sentry_connection" || counter.ScopeID == "" {
			t.Fatalf("receiver counters became command counts: %+v", counter)
		}
	}
}

func commandRuntimeCheckpoint() handoff.Checkpoint {
	c := sentryRuntimeCheckpoint()
	c.State.Capture = handoff.Sealed
	c.Runtime.Execution.SentryStartNS = 1794847878073098217
	capture := c.Runtime.Capture
	capture.State, capture.Gaps = "sealed", []string{}
	end := *capture.Start
	end.ObservedAt = c.At.Add(time.Second)
	end.Status.Targets = append([]telemetry.SecCheckTargetStatus{}, capture.Start.Status.Targets...)
	end.Status.Targets[0].AcceptedRecords = 40
	capture.End = &end
	capture.EvidenceRef = "sha256:" + strings.Repeat("a", 64)
	capture.Command = &runtimeadapter.CommandWatermark{
		Root:         runtimeadapter.SentryProcess{PID: c.Runtime.Execution.SentryPID, StartNS: c.Runtime.Execution.SentryStartNS},
		ProcessCount: 2, EventCount: 7, Basis: "controlled_birth_clone_closure_taskset_absence_and_committed_barrier",
	}
	return c
}

func TestRuntimeCommandSummaryKeepsBirthAndSeparateCounterScopes(t *testing.T) {
	db, paths := testStore(t)
	c := commandRuntimeCheckpoint()
	checkpointRef := put(t, db, paths, "r", "execution_checkpoint", "runtime", c)
	r := all(t, db, "r", 1)[0]
	if r.Identity["sentry_start_ns"] != "1794847878073098217" || r.Observation.ScopeKind != "execution_attempt" ||
		r.Observation.ScopeRef != c.AttemptID || !reflect.DeepEqual(r.Observation.EvidenceRefs, []string{checkpointRef, c.Runtime.Capture.EvidenceRef}) {
		t.Fatalf("command identity or references lost: %+v", r)
	}
	want := []Counter{
		{Name: "accepted_records", Scope: "sentry_connection", ScopeID: "before", Value: ptr("20"), Basis: "start_cumulative"},
		{Name: "accepted_records", Scope: "sentry_connection", ScopeID: "before", Value: ptr("40"), Basis: "end_cumulative"},
		{Name: "command_processes", Scope: "execution_attempt", ScopeID: "attempt", Value: ptr("2"), Basis: "saved_command_watermark"},
		{Name: "command_events", Scope: "execution_attempt", ScopeID: "attempt", Value: ptr("7"), Basis: "saved_command_watermark"},
	}
	if !reflect.DeepEqual(r.Counts, want) {
		t.Fatalf("command membership confused with receiver counters: %+v", r.Counts)
	}
	for _, snapshot := range r.Snapshots {
		if snapshot.Observation.ScopeKind != "sentry_connection" {
			t.Fatalf("receiver boundary scope changed: %+v", snapshot)
		}
	}
}

func TestRuntimeCommandSummaryRejectsWrongBirthAndMissingEvidence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*handoff.Checkpoint)
	}{
		{"reused-pid", func(c *handoff.Checkpoint) { c.Runtime.Capture.Command.Root.StartNS++ }},
		{"foreign-pid", func(c *handoff.Checkpoint) { c.Runtime.Capture.Command.Root.PID++ }},
		{"missing-evidence", func(c *handoff.Checkpoint) { c.Runtime.Capture.EvidenceRef = "" }},
		{"invalid-evidence", func(c *handoff.Checkpoint) { c.Runtime.Capture.EvidenceRef = "sha256:" + strings.Repeat("z", 64) }},
		{"missing-membership", func(c *handoff.Checkpoint) { c.Runtime.Capture.Command.ProcessCount = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, paths := testStore(t)
			c := commandRuntimeCheckpoint()
			tc.change(&c)
			put(t, db, paths, "r", "execution_checkpoint", "runtime", c)
			if _, err := (Service{DB: db}).List(context.Background(), Options{RunID: "r"}); err == nil {
				t.Fatal("incompatible command evidence accepted")
			}
		})
	}
}

func TestRuntimeCheckpointRejectsCrossBoundaryEvidence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*handoff.Checkpoint)
	}{
		{"receiver-generation", func(c *handoff.Checkpoint) { c.Runtime.Capture.End.Scope.Registration.Generation = "old" }},
		{"foreign-run", func(c *handoff.Checkpoint) { c.Runtime.Execution.RunID = "another-run" }},
		{"foreign-attempt", func(c *handoff.Checkpoint) { c.Runtime.Execution.AttemptID = "another-attempt" }},
		{"kernel-and-sentry", func(c *handoff.Checkpoint) { c.Capture = &handoff.NativeCaptureReport{} }},
		{"receiver-missing", func(c *handoff.Checkpoint) { c.Runtime.Capture.End.Status.Targets = nil }},
		{"duplicate-receiver", func(c *handoff.Checkpoint) {
			p := c.Runtime.Capture.End
			p.Status.Targets = append(p.Status.Targets, p.Status.Targets[0])
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, paths := testStore(t)
			c := sentryRuntimeCheckpoint()
			tc.mutate(&c)
			put(t, db, paths, "r", "execution_checkpoint", "runtime", c)
			if _, err := (Service{DB: db}).List(context.Background(), Options{RunID: "r"}); err == nil {
				t.Fatal("incompatible runtime evidence accepted")
			}
		})
	}
}

func TestRuntimeCheckpointSignedRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fixture func() handoff.Checkpoint
	}{{"receiver-boundaries", sentryRuntimeCheckpoint}, {"command-watermark", commandRuntimeCheckpoint}} {
		t.Run(tc.name, func(t *testing.T) {
			db, paths := testStore(t)
			c := tc.fixture()
			if c.Runtime.Capture.Command != nil {
				c.Runtime.Capture.EvidenceRef = put(t, db, paths, "r", "runtime_command_evidence", "command", c.Runtime.Capture.Command)
			}
			p := c.Runtime.Capture.End
			foreign := p.Status.Targets[0]
			foreign.Target.Registration.InstanceID = "unselected-private-instance"
			p.Status.Targets = append(p.Status.Targets, foreign)
			put(t, db, paths, "r", "execution_checkpoint", "runtime", c)
			before := all(t, db, "r", 1)
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key}).ExportBundle("r")
			if err != nil {
				t.Fatal(err)
			}
			if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, pub); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(bundle.Path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), "unselected-private-instance") {
				t.Fatal("foreign receiver identity leaked into the bundle")
			}
			dst, dest := testStore(t)
			if _, err := (forensics.Service{DB: dst, Paths: dest}).ImportBundle(bundle.Path); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(paths.Provenance, paths.Provenance+"-unavailable"); err != nil {
				t.Fatal(err)
			}
			if got := all(t, dst, "r", 1); !reflect.DeepEqual(got, before) {
				t.Fatalf("runtime boundary facts changed on import: %+v / %+v", before, got)
			}
		})
	}
}

func TestRuntimeCheckpointGuestPlatformAndSensorAreSeparate(t *testing.T) {
	db, paths := testStore(t)
	c := runtimeCheckpoint()
	binding := runtimeadapter.Binding{Target: runtimeadapter.Target(c.Target), Mode: "guest"}.WithGuest(runtimeadapter.GuestIdentity{
		RuntimeClass: "kata", RuntimeHandler: "kata-qemu-runtime-rs", PodUID: "pod-uid", ContainerID: "container", GuestBootID: "platform-boot",
	})
	c.PlatformBinding = &binding
	cap := caps(c.At, "attached")
	c.Runtime = &handoff.RuntimeReport{Execution: runtimeadapter.Execution{SchemaVersion: runtimeadapter.Schema,
		Binding: binding, OperationID: "guest-operation", AttemptID: c.AttemptID, RunID: "r", State: string(c.State.Execution)}}
	cap.Producer = &sensor.CapabilityProducer{Placement: "guest_kernel", PlacementBasis: "operator_config", BootID: "sensor-boot", Version: "observed-version"}
	c.Capture = &handoff.NativeCaptureReport{SchemaVersion: "agentprovenance.execution_native_capture/v2",
		Start: &handoff.NativeCapturePoint{Scope: record.ExecutionScope{RunID: "r"}, Capabilities: cap,
			Sensor: sensor.CaptureBoundary{CollectorID: "guest-collector", ObservedAt: c.At}}}
	put(t, db, paths, "r", "execution_checkpoint", "runtime", c)
	r := all(t, db, "r", 1)[0]
	if r.Identity["guest_boot_id"] != "platform-boot" || r.Snapshots[0].Identity["boot_id"] != "sensor-boot" ||
		r.Identity["pod_uid"] != "pod-uid" || r.Snapshots[0].Observation.Layer != "guest_kernel" {
		raw, _ := json.Marshal(r)
		t.Fatalf("platform assertion overwrote Sensor observation: %s", raw)
	}
}

func TestRuntimeCheckpointRejectsWrongGeneration(t *testing.T) {
	db, paths := testStore(t)
	c := runtimeCheckpoint()
	c.PlatformBinding = &runtimeadapter.Binding{Target: runtimeadapter.Target(c.Target), Mode: "guest"}
	c.PlatformBinding.Target.Generation = "another-generation"
	put(t, db, paths, "r", "execution_checkpoint", "runtime", c)
	_, err := (Service{DB: db}).List(context.Background(), Options{RunID: "r"})
	if err == nil || !strings.Contains(err.Error(), "platform") {
		t.Fatalf("wrong-generation platform binding accepted: %v", err)
	}
}
