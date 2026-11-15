package telemetry

import (
	"fmt"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/seccheck/wire"
	"google.golang.org/protobuf/proto"
)

func TestSecCheckPointReadsProtocolStages(t *testing.T) {
	db, _ := nativeTestStore(t)
	c := secCheckTestContext()
	for i, tc := range []struct {
		message proto.Message
		typ     wire.MessageType
		stage   string
		syscall bool
	}{
		{&wire.Start{Id: "container", ContextData: c}, wire.MessageType_MESSAGE_CONTAINER_START, "sentry_checkpoint", false},
		{&wire.CloneInfo{ContextData: c}, wire.MessageType_MESSAGE_SENTRY_CLONE, "sentry_checkpoint", false},
		{&wire.ExecveInfo{ContextData: c, BinaryPath: "/bin/test", Argv: []string{"test"}}, wire.MessageType_MESSAGE_SENTRY_EXEC, "sentry_checkpoint", false},
		{&wire.ExitNotifyParentInfo{ContextData: c}, wire.MessageType_MESSAGE_SENTRY_EXIT_NOTIFY_PARENT, "sentry_checkpoint", false},
		{&wire.TaskExit{ContextData: c}, wire.MessageType_MESSAGE_SENTRY_TASK_EXIT, "sentry_checkpoint", false},
		{&wire.Open{ContextData: c, Sysno: 56, Pathname: "/work/input"}, wire.MessageType_MESSAGE_SYSCALL_OPEN, "attempt", true},
		{&wire.Connect{ContextData: c, Sysno: 203, Exit: &wire.Exit{Errorno: 111}}, wire.MessageType_MESSAGE_SYSCALL_CONNECT, "result", true},
		{&wire.Execve{ContextData: c, Sysno: 221}, wire.MessageType_MESSAGE_SYSCALL_EXECVE, "attempt", true},
		{&wire.Clone{ContextData: c, Sysno: 220, Exit: &wire.Exit{Result: 8}}, wire.MessageType_MESSAGE_SYSCALL_CLONE, "result", true},
		{&wire.Fork{ContextData: c, Sysno: 57}, wire.MessageType_MESSAGE_SYSCALL_FORK, "attempt", true},
	} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			run := fmt.Sprint(i)
			e, err := MapSecCheckRecord(run, secCheckTestRecord(t, tc.message, tc.typ, uint64(i+1)))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := IngestFiltered(db, e); err != nil {
				t.Fatal(err)
			}
			events, err := ListEvents(db, run, "")
			if err != nil || len(events) != 1 {
				t.Fatalf("saved: %+v %v", events, err)
			}
			point, err := ReadSecCheckPoint(events[0])
			if err != nil || point.MessageType != uint16(tc.typ) || point.MessageName != tc.typ.String() || point.Stage != tc.stage || (point.SyscallNumber != nil) != tc.syscall {
				t.Fatalf("point: %+v %v", point, err)
			}
		})
	}
}
