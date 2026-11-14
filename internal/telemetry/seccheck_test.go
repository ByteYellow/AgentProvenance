package telemetry

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/seccheck"
	"github.com/byteyellow/agentprovenance/internal/seccheck/wire"
	"google.golang.org/protobuf/proto"
)

func secCheckTestRecord(t testing.TB, message proto.Message, typ wire.MessageType, seq uint64) seccheck.Record {
	t.Helper()
	raw, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, seccheck.HeaderBytes)
	binary.LittleEndian.PutUint16(packet, seccheck.HeaderBytes)
	binary.LittleEndian.PutUint16(packet[2:], uint16(typ))
	p, err := seccheck.DecodePacket(append(packet, raw...))
	if err != nil {
		t.Fatal(err)
	}
	zero := uint64(0)
	return seccheck.Record{Kind: "event", Registration: seccheck.Registration{Namespace: "lab", InstanceID: "node", Generation: "1", SandboxID: "sandbox", ContainerID: "container"}, ConnectionID: "connection", Sequence: seq, ReceivedAt: time.Unix(1800000001, 0).UTC(), ProtocolVersion: 1, Packet: &p, DroppedDelta: &zero}
}

func secCheckTestContext() *wire.ContextData {
	return &wire.ContextData{ContainerId: "container", TimeNs: 1800000000000000111, ThreadId: 7, ThreadStartTimeNs: 1800000000000000101, ThreadGroupId: 1, ThreadGroupStartTimeNs: 1800000000000000001, ParentThreadGroupId: 9, ProcessName: "cat", Cwd: "/work"}
}

func TestSecCheckProjectionStagesResultsAndRetention(t *testing.T) {
	address := make([]byte, 16)
	binary.LittleEndian.PutUint16(address, 2)
	binary.BigEndian.PutUint16(address[2:], 443)
	copy(address[4:], []byte{127, 0, 0, 1})
	c := secCheckTestContext()
	for _, tc := range []struct {
		name           string
		result         *wire.Exit
		stage, outcome string
	}{
		{"enter", nil, "attempt", "unknown"},
		{"success", &wire.Exit{}, "result", "success"},
		{"refused_zero_result", &wire.Exit{Errorno: 111}, "result", "failure"},
		{"pending", &wire.Exit{Errorno: 115}, "result", "pending"},
		{"already_pending", &wire.Exit{Errorno: 114}, "result", "pending"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := secCheckTestRecord(t, &wire.Connect{ContextData: c, Exit: tc.result, Address: address, Sysno: 203}, wire.MessageType_MESSAGE_SYSCALL_CONNECT, 1)
			e, err := MapSecCheckRecord("run", r)
			if err != nil {
				t.Fatal(err)
			}
			var body map[string]any
			if err := json.Unmarshal([]byte(e.Payload), &body); err != nil {
				t.Fatal(err)
			}
			kind := "network_connect"
			if tc.result != nil {
				kind = "syscall_result"
			}
			if e.EventType != kind || body["syscall_outcome"] != tc.outcome || body["observation_stage"] != tc.stage || body["dst_ip"] != "127.0.0.1" || body["dst_port"] != float64(443) {
				t.Fatalf("%+v %s", e, e.Payload)
			}
			if _, ok := body["syscall_result"]; ok != (tc.result != nil) {
				t.Fatal("invented/missing return value")
			}
			if e.Timestamp != "2027-01-15T08:00:00.000000111Z" {
				t.Fatalf("capture time: %s", e.Timestamp)
			}
		})
	}
	r := secCheckTestRecord(t, &wire.ExecveInfo{ContextData: c, BinaryPath: "/bin/test", Argv: []string{"test", "sk-123456789012345678901234"}, Env: []string{"PASSWORD=hidden-secret"}}, wire.MessageType_MESSAGE_SENTRY_EXEC, 2)
	e, err := MapSecCheckRecord("run", r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(e.Payload, "123456789012345678901234") || strings.Contains(e.Payload, "hidden-secret") || strings.Contains(e.Payload, `"env"`) {
		t.Fatalf("secret persisted: %s", e.Payload)
	}
	if !strings.Contains(e.Payload, "REDACTED") || !strings.Contains(e.Payload, r.Packet.SHA256) {
		t.Fatal("redaction or source digest missing")
	}
	for _, m := range []proto.Message{&wire.TaskExit{ContextData: c, ExitStatus: 256}, &wire.ExitNotifyParentInfo{ContextData: c, ExitStatus: 9}} {
		typ := wire.MessageType_MESSAGE_SENTRY_TASK_EXIT
		if _, ok := m.(*wire.ExitNotifyParentInfo); ok {
			typ = wire.MessageType_MESSAGE_SENTRY_EXIT_NOTIFY_PARENT
		}
		e, err := MapSecCheckRecord("run", secCheckTestRecord(t, m, typ, 3))
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateRawPayload(e.EventType, e.Payload); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSecCheckSpoolRestartDedupAndIndependentNativeState(t *testing.T) {
	db, paths := nativeTestStore(t)
	native := nativeTestStream(t, db, paths, NativeStreamOptions{})
	nativeWrite(t, native, "host-group", "/tmp/native")
	s, err := NewSecCheckStream(db, paths, NativeStreamOptions{BatchEvents: 1})
	if err != nil {
		t.Fatal(err)
	}
	r := secCheckTestRecord(t, &wire.Open{ContextData: secCheckTestContext(), Pathname: "/work/report.csv", Exit: &wire.Exit{Result: 3}}, wire.MessageType_MESSAGE_SYSCALL_OPEN, 1)
	sink := s.Sink("run", r.Registration)
	if err := sink(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	// Persisted evidence is recoverable even if the worker died after claiming.
	if _, err := db.Exec(`UPDATE telemetry_spool_batches SET status='processing' WHERE format='gvisor_seccheck'`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = NewSecCheckStream(db, paths, NativeStreamOptions{BatchEvents: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	// An identical accepted observation in another batch is still one event.
	if err := s.Sink("run", r.Registration)(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if err := s.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE source='gvisor_seccheck'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("events=%d err=%v", count, err)
	}
	status, err := s.Status(context.Background())
	if err != nil || status.PendingEvents != 0 || status.QueuedBytes != 0 || status.Counters["ingested"] != 1 || status.Counters["duplicates"] != 1 {
		t.Fatalf("status=%+v %v", status, err)
	}
	var windows int
	if err := db.QueryRow(`SELECT SUM(event_count) FROM telemetry_event_windows WHERE source='gvisor_seccheck'`).Scan(&windows); err != nil || windows != 2 {
		t.Fatalf("windows=%d %v", windows, err)
	}
	if err := native.Flush(); err != nil {
		t.Fatal(err)
	}
	host, err := ReadNativeStreamStatus(db)
	if err != nil || host.Counters["captured"] != 1 || host.Counters["ingested"] != 0 || host.PendingEvents != 1 {
		t.Fatalf("host status mixed: %+v %v", host, err)
	}
	if err := native.Process(32); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSecCheckStream(db, paths, NativeStreamOptions{}); err == nil {
		t.Fatal("second SecCheck owner accepted")
	}
	// A reused record identity with different content is kept for inspection.
	r.Packet.Message.(*wire.Open).Pathname = "/work/changed.csv"
	if err := s.Sink("run", r.Registration)(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if err := s.Drain(context.Background()); err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("conflict=%v", err)
	}
	status, err = s.Status(context.Background())
	if err != nil || status.PendingEvents != 1 || !strings.Contains(status.LastError, "conflicting") {
		t.Fatalf("retained conflict=%+v %v", status, err)
	}
}

func TestSecCheckQualifiedGraphPreservesBirthPrecision(t *testing.T) {
	db, _ := nativeTestStore(t)
	c := secCheckTestContext()
	r := secCheckTestRecord(t, &wire.Open{ContextData: c, Pathname: "/work/report.csv"}, wire.MessageType_MESSAGE_SYSCALL_OPEN, 1)
	seen := map[string]bool{}
	for _, change := range []string{"original", "generation", "container", "thread_birth"} {
		copy := r
		if change == "generation" {
			copy.Registration.Generation = "2"
		}
		if change == "container" {
			copy.Registration.SandboxID = "other"
		}
		if change == "thread_birth" {
			cc := proto.Clone(c).(*wire.ContextData)
			cc.ThreadStartTimeNs++
			copy = secCheckTestRecord(t, &wire.Open{ContextData: cc, Pathname: "/work/report.csv"}, wire.MessageType_MESSAGE_SYSCALL_OPEN, 2)
		}
		e, err := MapSecCheckRecord("run", copy)
		if err != nil {
			t.Fatal(err)
		}
		id, err := IngestFiltered(db, e)
		if err != nil {
			t.Fatal(err)
		}
		saved, err := eventRecordByID(db, id)
		if err != nil {
			t.Fatal(err)
		}
		identity := ProcessGraphIdentity(saved)
		if identity.Process.Basis != "sentry_process_instance" || seen[identity.Process.ID] || identity.ThreadGroup.Basis != "sentry_process_instance" || identity.Parent.Basis != "event_observation" {
			t.Fatalf("identity %s: %+v", change, identity)
		}
		seen[identity.Process.ID] = true
		file, path := SecCheckFileNode(saved)
		if !strings.HasPrefix(file, "runtime_file/gvisor/") || path != "/work/report.csv" {
			t.Fatalf("file=%q %q", file, path)
		}
		var edge int
		if err := db.QueryRow(`SELECT COUNT(*) FROM graph_edges WHERE from_id=? AND to_id=? AND edge_type='runtime_event_file'`, "runtime_event/"+id, file).Scan(&edge); err != nil || edge != 1 {
			t.Fatalf("file edge=%d %v", edge, err)
		}
	}
	var files int
	if err := db.QueryRow(`SELECT COUNT(DISTINCT to_id) FROM graph_edges WHERE edge_type='runtime_event_file'`).Scan(&files); err != nil || files != 3 {
		t.Fatalf("sandbox files merged: %d %v", files, err)
	}
}

func TestSecCheckBackpressurePropagatesAndSpoolRedacts(t *testing.T) {
	db, paths := nativeTestStore(t)
	s, err := NewSecCheckStream(db, paths, NativeStreamOptions{BatchEvents: 1, MaxQueuedBatches: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r := secCheckTestRecord(t, &wire.ExecveInfo{ContextData: secCheckTestContext(), BinaryPath: "/bin/test", Argv: []string{"test", "sk-123456789012345678901234"}, Env: []string{"PASSWORD=raw-secret"}}, wire.MessageType_MESSAGE_SENTRY_EXEC, 1)
	if err := s.Sink("run", r.Registration)(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	var path string
	if err := db.QueryRow(`SELECT spool_path FROM telemetry_spool_batches WHERE format='gvisor_seccheck'`).Scan(&path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "123456789012345678901234") || strings.Contains(string(data), "raw-secret") {
		t.Fatal("unredacted spool")
	}
	r.Sequence++
	if err := s.Sink("run", r.Registration)(context.Background(), r); err == nil {
		t.Fatal("queue overflow acknowledged")
	}
	status, err := s.Status(context.Background())
	if err != nil || status.Counters["dropped_queue_full"] != 1 {
		t.Fatalf("status=%+v %v", status, err)
	}
	if err := s.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.Sink("run", r.Registration)(context.Background(), r); err != nil {
		t.Fatal(err)
	}
}

func TestSecCheckDiagnosticsAndMissingContextSurvive(t *testing.T) {
	db, paths := nativeTestStore(t)
	s, err := NewSecCheckStream(db, paths, NativeStreamOptions{BatchEvents: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r := secCheckTestRecord(t, &wire.Open{Pathname: "/unknown", Exit: &wire.Exit{Errorno: 2}}, wire.MessageType_MESSAGE_SYSCALL_OPEN, 1)
	// The registered endpoint still supplies coarse Run scope; no missing
	// task identity may be filled from a host PID or the transport peer.
	if err := s.Sink("run", r.Registration)(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	r.Sequence++
	r.Kind, r.Reason, r.Packet = "stream", "disconnected", nil
	r.DroppedDelta = nil
	if err := s.Sink("run", r.Registration)(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if err := s.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	var payload string
	if err := db.QueryRow(`SELECT payload FROM events WHERE event_type='runtime_collection'`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload, "disconnected") || strings.Contains(payload, `"dropped_delta":0`) {
		t.Fatalf("diagnostic changed: %s", payload)
	}
	var pid int
	if err := db.QueryRow(`SELECT pid,payload FROM events WHERE event_type='syscall_result'`).Scan(&pid, &payload); err != nil {
		t.Fatal(err)
	}
	if pid != 0 || !strings.Contains(payload, "context_missing") {
		t.Fatalf("missing context changed: %d %s", pid, payload)
	}
}
