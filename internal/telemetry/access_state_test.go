package telemetry

import (
	"context"
	"encoding/json"
	"strings"
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

func TestNativeSamplingTriggerDoesNotBecomeObservedIdentity(t *testing.T) {
	var state map[string]any
	if err := json.Unmarshal([]byte(stateFixture), &state); err != nil {
		t.Fatal(err)
	}
	trigger := map[string]any{"source": "agentprov_ebpf", "cgroup_id": "6", "observed_at": "2026-10-19T00:00:00Z"}
	state["sampling_trigger"] = trigger
	raw := map[string]any{"source": "procfs_access_control", "event_type": "access_control_state", "state": state,
		"cgroup_id": "6", "timestamp": "2026-10-19T00:00:00.01Z"}
	event, _, err := mapNative(raw)
	if err != nil || event.CgroupID != "" || event.CaptureCgroupID != "6" || nativeScopeKey(event) != "6" {
		t.Fatalf("trigger scope accounting: %+v %v", event, err)
	}
	identity := eventIdentity(event)
	if identity.CgroupID != "" || identity.PID != 0 || identity.ProcessInstanceID != "" {
		t.Fatalf("trigger became event identity: %+v", identity)
	}
	// Previously serialized rows keep their original unclassified accounting.
	legacy := event
	legacy.CaptureCgroupID = ""
	if nativeScopeKey(legacy) != "" {
		t.Fatal("legacy spool payload was reinterpreted on replay")
	}
	for _, item := range []struct{ key, value string }{{"source", "other"}, {"cgroup_id", "0"}, {"cgroup_id", "invalid"}, {"observed_at", "invalid"}} {
		original := trigger[item.key]
		trigger[item.key] = item.value
		if _, _, err := mapNative(raw); err == nil {
			t.Fatalf("invalid trigger accepted: %s=%s", item.key, item.value)
		}
		trigger[item.key] = original
	}
}

func TestNativeSamplingFailurePersistsWithinTriggerScope(t *testing.T) {
	db, paths := nativeTestStore(t)
	nativeBind(t, db, "5", "run-sampling")
	n := nativeTestStream(t, db, paths, NativeStreamOptions{Ingest: JSONLIngestOptions{DropUncorrelated: true}, PendingTTL: time.Hour})
	start := scopeSnapshot(t, n)
	var snapshot map[string]any
	if err := json.Unmarshal([]byte(stateFixture), &snapshot); err != nil {
		t.Fatal(err)
	}
	snapshot["identity"] = map[string]any{"status": "unavailable", "pid": 42, "tid": 43, "reason": "not_present"}
	for _, mechanism := range []string{"apparmor", "seccomp"} {
		snapshot[mechanism] = map[string]any{"status": "unavailable", "reason": "not_present"}
	}
	snapshot["started_at"], snapshot["observed_at"] = "2026-09-19T00:00:00.6Z", "2026-09-19T00:00:00.7Z"
	snapshot["sampling_trigger"] = map[string]any{"source": "agentprov_ebpf", "cgroup_id": "5", "observed_at": "2026-09-19T00:00:00.1Z"}
	line, err := json.Marshal(map[string]any{"source": "procfs_access_control", "event_type": "access_control_state", "state": snapshot, "timestamp": snapshot["observed_at"]})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
	end := scopeSnapshot(t, n)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	prefix := scopeRange(t, n, start, end, "5")
	progress, err := n.DrainScopePrefix(ctx, prefix)
	if err != nil || progress.State != "settled" || progress.Ingested != 1 || progress.Pending != 0 || progress.SamplingGaps != 1 {
		t.Fatalf("completed sampling failure stayed pending: %+v %v", progress, err)
	}
	events, err := ListEvents(db, "run-sampling", "")
	if err != nil || len(events) != 1 {
		t.Fatalf("missing sampling diagnostic: %+v %v", events, err)
	}
	event := events[0]
	if event.ProcessID != "" || event.ToolCallID != "" || event.SessionID != "" || event.CgroupID != "" || event.PID != 0 || event.TGID != 0 || event.CorrelationMethod != "sampling_trigger_scope:cgroup_id+time" {
		t.Fatalf("sampling failure acquired observed task identity: %+v", event)
	}
	evidence, err := buildCorrelationEvidence(db, event)
	if err != nil || evidence.Match.Status != "scope_only" || !strings.Contains(evidence.Match.Reason, "procfs task identity was unavailable") {
		t.Fatalf("sampling trigger explanation lost: %+v %v", evidence, err)
	}
	if err := ValidateStoredPayload(event.EventType, event.Payload); err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(event.Payload), &body); err != nil {
		t.Fatal(err)
	}
	raw := unwrapStoredPayload(body)
	identity, _ := raw["identity"].(map[string]any)
	if identity["status"] != "unavailable" || identity["reason"] != "not_present" {
		t.Fatalf("sampling failure was hidden: %+v", raw)
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	restarted := nativeTestStream(t, db, paths, NativeStreamOptions{Ingest: JSONLIngestOptions{DropUncorrelated: true}})
	if _, err := restarted.DrainPrefix(context.Background(), end); err != nil {
		t.Fatal(err)
	}
	progress, err = ReadNativeScopePrefix(context.Background(), db, prefix)
	if err != nil || progress.Ingested != 1 || progress.SamplingGaps != 1 {
		t.Fatalf("sampling outcome changed on replay: %+v %v", progress, err)
	}
	shared, err := ReadNativePrefix(context.Background(), db, end)
	if err != nil || shared.SamplingGaps != 1 {
		t.Fatalf("shared report lost sampling gap: %+v %v", shared, err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id='run-sampling'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("sampling replay duplicated event: %d %v", count, err)
	}
}

func TestNativeSamplingGapAndEventCommitTogether(t *testing.T) {
	db, paths := nativeTestStore(t)
	nativeBind(t, db, "5", "run-gap")
	n := nativeTestStream(t, db, paths, NativeStreamOptions{Ingest: JSONLIngestOptions{DropUncorrelated: true}})
	start := scopeSnapshot(t, n)
	var snapshot map[string]any
	if err := json.Unmarshal([]byte(strings.ReplaceAll(stateFixture, "2026-10-19", "2026-09-19")), &snapshot); err != nil {
		t.Fatal(err)
	}
	snapshot["apparmor"] = map[string]any{"status": "unavailable", "reason": "permission_denied"}
	line, err := json.Marshal(map[string]any{"source": "procfs_access_control", "event_type": "access_control_state", "cgroup_id": "5", "state": snapshot, "timestamp": snapshot["observed_at"]})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
	end := scopeSnapshot(t, n)
	prefix := scopeRange(t, n, start, end, "5")
	if _, err := db.Exec(`CREATE TRIGGER reject_sampling_receipt BEFORE INSERT ON telemetry_native_rows BEGIN SELECT RAISE(ABORT,'forced sampling receipt failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := n.DrainScopePrefix(context.Background(), prefix); err == nil || !strings.Contains(err.Error(), "forced sampling receipt failure") {
		t.Fatalf("receipt failure missing: %v", err)
	}
	progress, err := ReadNativeScopePrefix(context.Background(), db, prefix)
	if err != nil || progress.Ingested != 0 || progress.SamplingGaps != 0 || progress.Pending != 1 {
		t.Fatalf("failed transaction changed accounting: %+v %v", progress, err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed transaction retained event: %d %v", count, err)
	}
	if _, err := db.Exec(`DROP TRIGGER reject_sampling_receipt`); err != nil {
		t.Fatal(err)
	}
	progress, err = n.DrainScopePrefix(context.Background(), prefix)
	if err != nil || progress.State != "settled" || progress.Ingested != 1 || progress.SamplingGaps != 1 {
		t.Fatalf("retry lost state gap: %+v %v", progress, err)
	}
}

func TestNativeSamplingScopeRequiresUnambiguousTrigger(t *testing.T) {
	for _, name := range []string{"valid", "unbound", "ambiguous", "wrong_run", "legacy", "future", "observed_task", "missing_trigger", "mismatched_trigger"} {
		t.Run(name, func(t *testing.T) {
			db, _ := nativeTestStore(t)
			if name != "unbound" {
				nativeBind(t, db, "5", "run-owner")
			}
			if name == "ambiguous" {
				nativeBind(t, db, "5", "run-other")
			}
			var snapshot map[string]any
			if err := json.Unmarshal([]byte(stateFixture), &snapshot); err != nil {
				t.Fatal(err)
			}
			snapshot["started_at"], snapshot["observed_at"] = "2026-09-19T00:00:00.6Z", "2026-09-19T00:00:00.7Z"
			if name != "observed_task" {
				snapshot["identity"] = map[string]any{"status": "unavailable", "pid": 42, "tid": 43, "reason": "not_present"}
				for _, mechanism := range []string{"apparmor", "seccomp"} {
					snapshot[mechanism] = map[string]any{"status": "unavailable", "reason": "not_present"}
				}
			}
			trigger := map[string]any{"source": "agentprov_ebpf", "cgroup_id": "5", "observed_at": "2026-09-19T00:00:00.1Z"}
			if name == "future" {
				trigger["observed_at"] = "2026-09-19T00:00:00.8Z"
			}
			if name != "missing_trigger" {
				snapshot["sampling_trigger"] = trigger
			}
			event := IngestEvent{Source: "procfs_access_control", EventType: "access_control_state", CaptureCgroupID: "5", Payload: mustJSON(snapshot)}
			if name == "legacy" {
				event.CaptureCgroupID = ""
			}
			if name == "mismatched_trigger" {
				event.CaptureCgroupID = "6"
			}
			if name == "wrong_run" {
				event.RunID = "run-other"
			}
			match, err := nativeSamplingScope(db, event)
			if err != nil {
				t.Fatal(err)
			}
			if name == "valid" {
				if match == nil || match.RunID != "run-owner" || !match.ScopeOnly || match.SessionID != "" || match.ToolCallID != "" || match.CgroupID != "" {
					t.Fatalf("bad sampling scope: %+v", match)
				}
			} else if match != nil {
				t.Fatalf("unproven sampling scope accepted: %+v", match)
			}
		})
	}
}
