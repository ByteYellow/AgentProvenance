package runtimeadapter

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/seccheck"
	"github.com/byteyellow/agentprovenance/internal/seccheck/wire"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
	"google.golang.org/protobuf/proto"
)

func commandFixture(t *testing.T) (seccheck.Target, SentryProcess, []telemetry.EventRecord) {
	t.Helper()
	s, _ := fakeSecCheck()
	root := SentryProcess{PID: 10, StartNS: 1794839095305113409}
	context := func(pid int32, birth int64) *wire.ContextData {
		return &wire.ContextData{ContainerId: s.Receiver.Registration.ContainerID, ThreadId: pid, ThreadGroupId: pid,
			ThreadStartTimeNs: birth, ThreadGroupStartTimeNs: birth, TimeNs: root.StartNS + 100, ParentThreadGroupId: root.PID}
	}
	parent := context(root.PID, root.StartNS)
	child := context(11, root.StartNS+1)
	grandchild := context(12, root.StartNS+2)
	// Same PID/PPID and nearby times do not make this a descendant.
	foreign := context(11, root.StartNS+3)
	var events []telemetry.EventRecord
	add := func(c *wire.ContextData, message proto.Message, kind wire.MessageType) {
		seq := uint64(len(events) + 1)
		zero := uint64(0)
		e, err := telemetry.MapSecCheckRecord(s.Receiver.RunID, seccheck.Record{Kind: "event", Registration: s.Receiver.Registration,
			ConnectionID: "connection", Sequence: seq, ReceivedAt: time.Unix(0, root.StartNS+int64(seq)), ProtocolVersion: seccheck.ProtocolVersion,
			DroppedDelta: &zero, Packet: &seccheck.Packet{Context: c, Message: message, SHA256: strings.Repeat("a", 64), Size: 100,
				Header: seccheck.Header{Size: 8, MessageType: uint16(kind)}}})
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, telemetry.EventRecord{ID: fmt.Sprintf("event-%d", seq), RunID: e.RunID, RawEventID: e.RawEventID,
			CorrelationMethod: "runtime_scope", ContainerID: e.ContainerID, PID: e.PID, TGID: e.TGID, PPID: e.PPID,
			Source: e.Source, EventType: e.EventType, Payload: e.Payload, CreatedAt: e.Timestamp})
	}
	add(parent, &wire.ExecveInfo{ContextData: parent, Argv: []string{"/bin/sh", "job"}}, wire.MessageType_MESSAGE_SENTRY_EXEC)
	add(parent, &wire.CloneInfo{ContextData: parent, CreatedThreadId: 11, CreatedThreadGroupId: 11, CreatedThreadStartTimeNs: child.ThreadStartTimeNs}, wire.MessageType_MESSAGE_SENTRY_CLONE)
	add(foreign, &wire.ExecveInfo{ContextData: foreign, Argv: []string{"unrelated"}}, wire.MessageType_MESSAGE_SENTRY_EXEC)
	add(child, &wire.CloneInfo{ContextData: child, CreatedThreadId: 12, CreatedThreadGroupId: 12, CreatedThreadStartTimeNs: grandchild.ThreadStartTimeNs}, wire.MessageType_MESSAGE_SENTRY_CLONE)
	add(grandchild, &wire.ExecveInfo{ContextData: grandchild, Argv: []string{"worker"}}, wire.MessageType_MESSAGE_SENTRY_EXEC)
	add(parent, &wire.TaskExit{ContextData: parent, ExitStatus: 9}, wire.MessageType_MESSAGE_SENTRY_TASK_EXIT)
	add(parent, &wire.ExitNotifyParentInfo{ContextData: parent, ExitStatus: 7 << 8}, wire.MessageType_MESSAGE_SENTRY_EXIT_NOTIFY_PARENT)
	return s.Receiver, root, events
}

func TestSecCheckCommandUsesExactCloneBirthAndGroupExit(t *testing.T) {
	receiver, root, events := commandFixture(t)
	r, err := DeriveSecCheckCommand(receiver, "connection", root, []string{"/bin/sh", "job"}, events)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Processes) != 3 || len(r.Events) != 6 || r.RootExecRef != "event-1" || r.RootExitRef != "event-7" || r.RootWaitStatus == nil || *r.RootWaitStatus != 7<<8 {
		t.Fatalf("command projection: %+v", r)
	}
	if r.Processes[1].StartNS != root.StartNS+1 || r.Processes[2].StartNS != root.StartNS+2 {
		t.Fatal("clone birth lost nanosecond precision")
	}
	for _, e := range r.Events {
		if e.ID == "event-3" {
			t.Fatal("PID reuse or PPID borrowed another process")
		}
	}
	if r.FirstSequence != 1 || r.LastSequence != 7 || len(r.RangeSHA256) != 64 {
		t.Fatal("missing sequence commitment")
	}
	raw, _ := json.Marshal(r)
	if !strings.Contains(string(raw), `"start_ns":"1794839095305113409"`) {
		t.Fatal("root birth is not safe for JavaScript consumers")
	}
	beforeExit, err := DeriveSecCheckCommand(receiver, "connection", root, []string{"/bin/sh", "job"}, events[:6])
	if err != nil || beforeExit.RootWaitStatus != nil {
		t.Fatal("thread exit became group outcome", err)
	}
}

func TestSecCheckCommandRejectsDiscontinuityAndCrossLifecycle(t *testing.T) {
	for _, mode := range []string{"gap", "connection", "generation", "root", "drop", "reference", "child_birth"} {
		t.Run(mode, func(t *testing.T) {
			receiver, root, events := commandFixture(t)
			connection := "connection"
			switch mode {
			case "gap":
				events = append(events[:1], events[2:]...)
			case "connection":
				connection = "reconnected"
			case "generation":
				receiver.Registration.Generation = "new"
			case "root":
				root.StartNS = 0
			case "reference":
				events[1].ID = events[0].ID
			case "drop":
				events[1].Payload = strings.Replace(events[1].Payload, `"dropped_delta":0`, `"dropped_delta":1`, 1)
			case "child_birth":
				events[1].Payload = strings.Replace(events[1].Payload, `"created_thread_start_ns":1794839095305113410`, `"created_thread_start_ns":0`, 1)
			}
			if _, err := DeriveSecCheckCommand(receiver, connection, root, []string{"/bin/sh", "job"}, events); err == nil {
				t.Fatal("invalid command interval accepted")
			}
		})
	}
}
