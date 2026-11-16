package runtimeadapter

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/seccheck"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func fakeSecCheck() (SecCheck, *telemetry.SecCheckCollectStatus) {
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	target := testRequest().Target
	receiver := seccheck.Target{RunID: "container-run", SocketPath: "/run/agentprov/events.sock", Registration: seccheck.Registration{
		Namespace: target.ProducerID, InstanceID: target.InstanceID, Generation: target.Generation, SandboxID: "sandbox", ContainerID: "container"}}
	status := &telemetry.SecCheckCollectStatus{SchemaVersion: "agentprovenance.seccheck_status/v1", CollectorID: "collector", GeneratedAt: now.Format(time.RFC3339Nano), State: "listening",
		ExpectedRuntimeRelease: seccheck.RuntimeRelease, ProtocolVersion: seccheck.ProtocolVersion,
		Targets: []telemetry.SecCheckTargetStatus{{Target: receiver, State: "connected", ConnectionID: "connection", AcceptedRecords: 7}}}
	s := SecCheck{Target: target, Receiver: receiver, Now: func() time.Time { return now }, ReadStatus: func(context.Context) (telemetry.SecCheckCollectStatus, error) {
		copy := *status
		copy.Targets = append([]telemetry.SecCheckTargetStatus{}, status.Targets...)
		return copy, nil
	}}
	return s, status
}

func TestSecCheckSeparateCaptureHasExplicitCallGaps(t *testing.T) {
	s, status := fakeSecCheck()
	start, err := s.Probe(context.Background(), s.Target)
	if err != nil {
		t.Fatal(err)
	}
	status.Targets[0].AcceptedRecords++
	r := s.Finish(context.Background(), s.Target, start)
	if r.State != "incomplete" || r.ObservationLayer != "sentry" || r.ScopeRef == "" || len(r.Gaps) != 3 || r.End == nil {
		t.Fatalf("capture: %+v", r)
	}
}

func TestSecCheckRejectsWrongGenerationAndDisconnectedReceiver(t *testing.T) {
	for _, mode := range []string{"producer", "instance", "generation", "container", "stale", "disconnected", "worker", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			s, status := fakeSecCheck()
			target := s.Target
			switch mode {
			case "producer":
				target.ProducerID = "foreign"
			case "instance":
				target.InstanceID = "clone"
			case "generation":
				target.Generation = "restored"
			case "container":
				status.Targets[0].Registration.ContainerID = "reused"
			case "stale":
				status.GeneratedAt = s.Now().Add(-time.Minute).Format(time.RFC3339Nano)
			case "disconnected":
				status.Targets[0].State = "disconnected"
			case "worker":
				status.LastWorkerError = "spool unavailable"
			case "duplicate":
				status.Targets = append(status.Targets, status.Targets[0])
			}
			if _, err := s.Probe(context.Background(), target); err == nil {
				t.Fatal("accepted invalid receiver state")
			}
		})
	}
}

func TestSecCheckRestartLossAndLateEvidence(t *testing.T) {
	s, status := fakeSecCheck()
	start, _ := s.Probe(context.Background(), s.Target)
	status.CollectorID, status.Targets[0].ConnectionID = "restarted", "reconnected"
	status.Targets[0].ReportedDrops++
	r := s.Finish(context.Background(), s.Target, start)
	for _, want := range []string{"collector_restarted", "receiver_reconnected", "receiver_loss_or_identity_gap"} {
		if !strings.Contains(strings.Join(r.Gaps, ","), want) {
			t.Fatal(r.Gaps)
		}
	}
	status.Targets[0].Registration.Generation = "clone"
	r = s.Finish(context.Background(), s.Target, start)
	if r.End != nil || r.Error == "" || r.State != "incomplete" {
		t.Fatalf("late cross-generation evidence accepted: %+v", r)
	}
}

func TestSecCheckStatusUsesLastCompleteJSONRecord(t *testing.T) {
	_, status := fakeSecCheck()
	first, _ := json.Marshal(status)
	status.CollectorID = "new-collector"
	last, _ := json.Marshal(status)
	raw := append(append(append(append([]byte{}, first...), '\n'), last...), '\n')
	raw = append(raw, []byte(`{"partial":`)...)
	got, err := decodeSecCheckStatus(raw)
	if err != nil || got.CollectorID != "new-collector" {
		t.Fatalf("status: %+v %v", got, err)
	}
	if _, err := decodeSecCheckStatus([]byte(`{"partial":`)); err == nil {
		t.Fatal("accepted partial status")
	}
	if _, err := decodeSecCheckStatus(append(raw, '\n')); err == nil {
		t.Fatal("silently ignored malformed committed status")
	}
}

func TestSecCheckPointExcludesOtherTargetsAndNodeSpool(t *testing.T) {
	s, status := fakeSecCheck()
	foreign := status.Targets[0]
	foreign.RunID = "foreign-secret-run"
	foreign.Registration.ContainerID = "foreign-secret-container"
	foreign.SocketPath = "/run/foreign-secret.sock"
	status.Targets = append(status.Targets, foreign)
	status.Spool = telemetry.NativeStreamStatus{LastError: "foreign-secret-batch", Counters: map[string]int64{"foreign-secret-stream": 7}}
	point, err := s.Probe(context.Background(), s.Target)
	if err != nil {
		t.Fatal(err)
	}
	if len(point.Status.Targets) != 1 || point.Status.Targets[0].Target != s.Receiver || point.Status.Spool.LastError != "" {
		t.Fatal("in-memory point retained foreign status")
	}
	// Serialization is also defensive when a caller supplies a full status.
	point.Status = *status
	raw, err := json.Marshal(point)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "foreign-secret") || strings.Contains(string(raw), "node_spool") {
		t.Fatalf("cross-target status leaked: %s", raw)
	}
	var restored CapturePoint
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if len(restored.Status.Targets) != 1 || restored.Status.Targets[0].AcceptedRecords != 7 || restored.Status.CollectorID != "collector" {
		t.Fatalf("lost selected receiver boundary: %+v", restored)
	}
}
