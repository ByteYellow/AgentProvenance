package runtimeadapter

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/seccheck"
	"github.com/byteyellow/agentprovenance/internal/seccheck/wire"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
	"google.golang.org/protobuf/proto"
)

func TestCommandWatermarkWaitsForCommittedBarrierAndStableAncestry(t *testing.T) {
	for _, mode := range []string{"complete", "late_clone", "reconnect", "missing_barrier", "loss"} {
		t.Run(mode, func(t *testing.T) {
			receiver, root, events := commandFixture(t)
			s, status := fakeSecCheck()
			s.Receiver = receiver
			last := uint64(0)
			status.Targets[0].LastSequence = &last
			status.Targets[0].AcceptedRecords = 0
			start, err := s.Probe(context.Background(), s.Target)
			if err != nil {
				t.Fatal(err)
			}
			// Persisted snapshots own their value; do not mutate the start
			// boundary when the simulated collector advances.
			zero := uint64(0)
			start.Status.Targets[0].LastSequence = &zero
			last = uint64(len(events))
			status.Targets[0].AcceptedRecords = last
			request := testRequest()
			request.Command.Command = []string{"/bin/sh", "job"}
			execution := NewExecution(testRunsc().Binding, request)
			execution.SentryPID, execution.SentryStartNS = root.PID, root.StartNS
			execution.SentryPIDBasis = "private_exec_fd_gate_and_runsc_procfs"
			execution.Started, execution.GateReleased = true, true
			barriers, reads, drains := 0, 0, 0
			appendEvent := func(c *wire.ContextData, message proto.Message, kind wire.MessageType) {
				seq := uint64(len(events) + 1)
				drop := uint64(0)
				e, err := telemetry.MapSecCheckRecord(receiver.RunID, seccheck.Record{Kind: "event", Registration: receiver.Registration,
					ConnectionID: "connection", Sequence: seq, ReceivedAt: time.Unix(0, root.StartNS+int64(seq)), ProtocolVersion: 1, DroppedDelta: &drop,
					Packet: &seccheck.Packet{Context: c, Message: message, SHA256: strings.Repeat("a", 64), Size: 100, Header: seccheck.Header{Size: 8, MessageType: uint16(kind)}}})
				if err != nil {
					t.Fatal(err)
				}
				events = append(events, telemetry.EventRecord{ID: fmt.Sprintf("event-%d", seq), RunID: e.RunID, RawEventID: e.RawEventID,
					CorrelationMethod: "runtime_scope", ContainerID: e.ContainerID, PID: e.PID, TGID: e.TGID, PPID: e.PPID,
					Source: e.Source, EventType: e.EventType, Payload: e.Payload, CreatedAt: e.Timestamp})
				last = seq
				status.Targets[0].AcceptedRecords = seq
			}
			s.ReadEvents = func(_ context.Context, _ string, first uint64, count int) ([]telemetry.EventRecord, error) {
				reads++
				// Reported spool acceptance precedes database ingestion. The
				// watermark record is deliberately missing on its first read.
				if barriers > 0 && reads == 2 {
					return nil, nil
				}
				begin := int(first - 1)
				if begin >= len(events) {
					return nil, nil
				}
				return events[begin:min(begin+count, len(events))], nil
			}
			s.ObserveProcesses = func(_ context.Context, owned []SentryProcess) (ProcessDrain, error) {
				drains++
				if mode == "late_clone" && barriers == 1 && len(owned) != 4 {
					t.Fatal("late child was not added before rechecking task set")
				}
				return ProcessDrain{ObservedAt: time.Now(), Basis: "runsc_ps_root_taskset", Empty: true, Remaining: []SentryProcess{}}, nil
			}
			s.Barrier = func(context.Context, string) (RuntimeBarrier, error) {
				barriers++
				birth := root.StartNS + int64(100+barriers)
				pid := int32(50 + barriers)
				barrier := RuntimeBarrier{Process: SentryProcess{PID: pid, StartNS: birth}, Marker: fmt.Sprintf("/.agentprov-watermark-%032d", barriers)}
				c := &wire.ContextData{ContainerId: receiver.Registration.ContainerID, ThreadId: pid, ThreadGroupId: pid,
					ThreadStartTimeNs: birth, ThreadGroupStartTimeNs: birth, TimeNs: birth + 10}
				if mode == "late_clone" && barriers == 1 {
					child := proto.Clone(c).(*wire.ContextData)
					child.ThreadId, child.ThreadGroupId = 11, 11
					child.ThreadStartTimeNs, child.ThreadGroupStartTimeNs = root.StartNS+1, root.StartNS+1
					appendEvent(child, &wire.CloneInfo{ContextData: child, CreatedThreadId: 13, CreatedThreadGroupId: 13, CreatedThreadStartTimeNs: root.StartNS + 4}, wire.MessageType_MESSAGE_SENTRY_CLONE)
				}
				appendEvent(c, &wire.CloneInfo{ContextData: c, CreatedThreadId: pid + 10, CreatedThreadGroupId: pid, CreatedThreadStartTimeNs: birth + 1, Flags: 0x10000}, wire.MessageType_MESSAGE_SENTRY_CLONE)
				if mode != "missing_barrier" {
					appendEvent(c, &wire.Open{ContextData: c, Pathname: barrier.Marker, Sysno: 257, Exit: &wire.Exit{Errorno: 2}}, wire.MessageType_MESSAGE_SYSCALL_OPEN)
				}
				if mode == "reconnect" {
					status.CollectorID = "new-collector"
				}
				if mode == "loss" {
					status.Targets[0].ReportedDrops++
				}
				return barrier, nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
			defer cancel()
			r := s.FinishCommand(ctx, request, execution, start)
			if mode == "complete" || mode == "late_clone" {
				if r.State != "sealed" || r.Command == nil || r.Evidence == nil || len(r.Evidence.BoundaryEvents) != 2 || r.Evidence.Watermark == nil || reads < 3 {
					t.Fatalf("watermark: %+v", r)
				}
				if mode == "late_clone" && (barriers != 2 || drains != 2 || r.Command.ProcessCount != 4) {
					t.Fatalf("closure not repeated: barriers=%d drains=%d command=%+v", barriers, drains, r.Command)
				}
			} else if r.State != "incomplete" || r.Command != nil {
				t.Fatalf("missing durable/continuous evidence sealed: %+v", r)
			}
		})
	}
}
