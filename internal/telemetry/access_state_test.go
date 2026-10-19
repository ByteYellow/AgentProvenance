package telemetry

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/correlation"
)

const stateFixture = `{"schema_version":"agentprovenance.access_control_state/v1","evidence_kind":"state_snapshot","source":"procfs","started_at":"2026-10-19T00:00:00Z","observed_at":"2026-10-19T00:00:00.01Z","identity":{"status":"observed","pid":42,"tid":43,"start_ticks":"100","cgroup_id":"5"},"apparmor":{"status":"observed","source":"attr/apparmor/current","label":"unconfined","mode":"unconfined"},"seccomp":{"status":"observed","source":"status","mode_number":0,"mode":"disabled","filter_count":0,"no_new_privs":0}}`

func TestNativeStateIsSeparateFromDecisionsAndKernelTasks(t *testing.T) {
	var state map[string]any
	if err := json.Unmarshal([]byte(stateFixture), &state); err != nil {
		t.Fatal(err)
	}
	raw := map[string]any{"event_type": "access_control_state", "state": state, "pid": 42, "tgid": 42, "tid": 43, "ppid": 1, "cgroup_id": "5", "process_instance_id": "kernel:wrong", "timestamp": "2026-10-19T00:00:00.01Z"}
	raw["source"] = "procfs_access_control"
	if got := detectFormat(raw); got != "native" {
		t.Fatalf("state detected as %s", got)
	}
	event, ok, err := mapNative(raw)
	if err != nil || !ok || event.Source != "procfs_access_control" || event.PID != 0 || event.TGID != 0 || event.PPID != 0 || event.CgroupID != "5" {
		t.Fatalf("event=%+v %v", event, err)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(event.Payload), &body); err != nil {
		t.Fatal(err)
	}
	if body["process_instance_id"] != nil || body["decision"] != nil {
		t.Fatal("state acquired a fabricated decision or lifetime")
	}
	if err := ValidateStoredPayload(event.EventType, mustJSON(map[string]any{"raw": body})); err != nil {
		t.Fatal(err)
	}
	if !TelemetrySource(event.Source, "") || sourceFormat(event.Source) != "jsonl" || CorrelationClass(event.Source, "cgroup_time_window", "", 0.9) != "self_observed" {
		t.Fatal("source presentation misclassified")
	}
	raw["cgroup_id"], raw["container_id"] = "other-scope", "unobserved-container"
	if mapped, _, err := mapNative(raw); err != nil || mapped.CgroupID != "" || mapped.ContainerID != "" {
		t.Fatalf("unobserved scope inherited from trigger: %+v %v", mapped, err)
	}
	for _, bad := range []any{nil, map[string]any{"schema_version": "agentprovenance.access_control_state/v1"}} {
		raw["state"] = bad
		if _, _, err := mapNative(raw); err == nil {
			t.Fatal("malformed state accepted")
		}
	}
}

func TestStatePassesDurableCaptureWithScopeOnlyAttribution(t *testing.T) {
	db, paths := nativeTestStore(t)
	_, err := correlation.RecordBinding(db, correlation.Binding{RunID: "state-run", CgroupID: "5",
		ToolCallID: "not-a-procfs-tool", ProcessID: "not-a-procfs-process", StartedAt: "2026-10-18T00:00:00Z", BindingSource: correlation.BindingSourceK8sCgroup})
	if err != nil {
		t.Fatal(err)
	}
	n := nativeTestStream(t, db, paths, NativeStreamOptions{Ingest: JSONLIngestOptions{DropUncorrelated: true}, BatchEvents: 1})
	line := `{"source":"procfs_access_control","event_type":"access_control_state","cgroup_id":"5","timestamp":"2026-10-19T00:00:00.01Z","state":` + stateFixture + "}\n"
	if _, err := n.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := n.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	events, err := ListEvents(db, "state-run", "")
	if err != nil || len(events) != 1 {
		t.Fatalf("state not durably ingested: %+v %v", events, err)
	}
	event := events[0]
	if event.PID != 0 || event.ProcessID != "" || event.ToolCallID != "" || event.Source != "procfs_access_control" || event.CorrelationClass != "self_observed" {
		t.Fatalf("procfs state acquired exact process attribution: %+v", event)
	}
	if err := ValidateStoredPayload(event.EventType, event.Payload); err != nil {
		t.Fatal(err)
	}
}
