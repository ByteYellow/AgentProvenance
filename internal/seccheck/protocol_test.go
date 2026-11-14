package seccheck

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/seccheck/wire"
	"google.golang.org/protobuf/proto"
)

func testRegistration() Registration {
	return Registration{Namespace: "lab", InstanceID: "vm-1", Generation: "generation-1", SandboxID: "sandbox-1", ContainerID: "container-1"}
}

func testContext() *wire.ContextData {
	return &wire.ContextData{TimeNs: 1_800_000_000_000_000_000, ContainerId: "container-1", ThreadId: 7, ThreadStartTimeNs: 200, ThreadGroupId: 1, ThreadGroupStartTimeNs: 100, ParentThreadGroupId: 9}
}

func packetBytes(t testing.TB, typ wire.MessageType, message proto.Message, dropped uint32) []byte {
	t.Helper()
	payload, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, HeaderBytes, HeaderBytes+len(payload))
	binary.LittleEndian.PutUint16(raw, HeaderBytes)
	binary.LittleEndian.PutUint16(raw[2:], uint16(typ))
	binary.LittleEndian.PutUint32(raw[4:], dropped)
	return append(raw, payload...)
}

func TestPacketTypesAndSyscallOutcomes(t *testing.T) {
	c := testContext()
	for _, item := range []struct {
		typ     wire.MessageType
		message proto.Message
	}{
		{wire.MessageType_MESSAGE_CONTAINER_START, &wire.Start{ContextData: c, Id: "container-1"}},
		{wire.MessageType_MESSAGE_SENTRY_CLONE, &wire.CloneInfo{ContextData: c, CreatedThreadId: 8, CreatedThreadGroupId: 1, CreatedThreadStartTimeNs: 300}},
		{wire.MessageType_MESSAGE_SENTRY_EXEC, &wire.ExecveInfo{ContextData: c, BinaryPath: "/bin/cat", Argv: []string{"cat", "a"}}},
		{wire.MessageType_MESSAGE_SENTRY_TASK_EXIT, &wire.TaskExit{ContextData: c, ExitStatus: 256}},
		{wire.MessageType_MESSAGE_SENTRY_EXIT_NOTIFY_PARENT, &wire.ExitNotifyParentInfo{ContextData: c, ExitStatus: 256}},
		{wire.MessageType_MESSAGE_SYSCALL_OPEN, &wire.Open{ContextData: c, Pathname: "file", Fd: -100}},
		{wire.MessageType_MESSAGE_SYSCALL_OPEN, &wire.Open{ContextData: c, Exit: &wire.Exit{}, Pathname: "file", Fd: -100}},
		{wire.MessageType_MESSAGE_SYSCALL_CONNECT, &wire.Connect{ContextData: c, Exit: &wire.Exit{Result: -1, Errorno: 111}}},
		{wire.MessageType_MESSAGE_SYSCALL_EXECVE, &wire.Execve{ContextData: c, Pathname: "/missing", Exit: &wire.Exit{Result: -1, Errorno: 2}}},
		{wire.MessageType_MESSAGE_SYSCALL_CLONE, &wire.Clone{ContextData: c}},
		{wire.MessageType_MESSAGE_SYSCALL_FORK, &wire.Fork{ContextData: c}},
	} {
		packet, err := DecodePacket(packetBytes(t, item.typ, item.message, 3))
		if err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(item.message, packet.Message) || !proto.Equal(c, packet.Context) || packet.Header.DroppedCount != 3 || len(packet.SHA256) != 64 {
			t.Fatalf("type or result changed: %v", packet)
		}
	}
}

func TestProtocolBoundsAndCompatibility(t *testing.T) {
	raw := packetBytes(t, wire.MessageType_MESSAGE_SYSCALL_OPEN, &wire.Open{}, 0)
	for _, size := range []uint16{0, 7, 65535} {
		bad := bytes.Clone(raw)
		binary.LittleEndian.PutUint16(bad, size)
		if _, err := DecodePacket(bad); err == nil {
			t.Fatalf("accepted header %d", size)
		}
	}
	for _, bad := range [][]byte{nil, raw[:7], make([]byte, MaxPacketBytes+1), append(bytes.Clone(raw), 0xff)} {
		if _, err := DecodePacket(bad); err == nil {
			t.Fatal("accepted invalid packet")
		}
	}
	// Future headers are skipped according to their declared length.
	extended := append(bytes.Clone(raw[:8]), 1, 2, 3, 4)
	binary.LittleEndian.PutUint16(extended, 12)
	if _, err := DecodePacket(extended); err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint16(raw[2:], 65000)
	unknown, err := DecodePacket(raw)
	if err != nil || unknown.Message != nil || unknown.Header.MessageType != 65000 {
		t.Fatalf("unknown: %+v %v", unknown, err)
	}
	for _, bad := range [][]byte{nil, {0xff}, {8, 0}, {8, 2}, make([]byte, MaxHandshakeBytes+1)} {
		if _, err := HandshakeReply(bad); err == nil {
			t.Fatalf("accepted handshake %x", bad)
		}
	}
	if got, err := HandshakeReply([]byte{8, 1}); err != nil || !bytes.Equal(got, []byte{8, 1}) {
		t.Fatalf("reply %x: %v", got, err)
	}
}

func TestSentryIdentityIsQualifiedAndKeepsThreadsSeparate(t *testing.T) {
	reg, c := testRegistration(), testContext()
	one, err := IdentityFor(reg, c)
	if err != nil {
		t.Fatal(err)
	}
	if one.Task == one.Process || one.ThreadID != 7 || one.ThreadGroupID != 1 || len(one.Gaps) != 0 {
		t.Fatalf("identity: %+v", one)
	}
	thread := proto.Clone(c).(*wire.ContextData)
	thread.ThreadId, thread.ThreadStartTimeNs = 8, 300
	two, _ := IdentityFor(reg, thread)
	if one.Process != two.Process || one.Task == two.Task {
		t.Fatal("threads merged or group separated")
	}
	for _, changed := range []Registration{
		{Namespace: "other", InstanceID: reg.InstanceID, Generation: reg.Generation, SandboxID: reg.SandboxID, ContainerID: reg.ContainerID},
		{Namespace: reg.Namespace, InstanceID: "other", Generation: reg.Generation, SandboxID: reg.SandboxID, ContainerID: reg.ContainerID},
		{Namespace: reg.Namespace, InstanceID: reg.InstanceID, Generation: "other", SandboxID: reg.SandboxID, ContainerID: reg.ContainerID},
		{Namespace: reg.Namespace, InstanceID: reg.InstanceID, Generation: reg.Generation, SandboxID: "other", ContainerID: reg.ContainerID},
	} {
		two, err := IdentityFor(changed, c)
		if err != nil || one.Task == two.Task || one.Process == two.Process {
			t.Fatalf("registration collision: %+v %v", changed, err)
		}
	}
	c.ThreadStartTimeNs++
	three, _ := IdentityFor(reg, c)
	if one.Task == three.Task {
		t.Fatal("reused TID merged")
	}
	c.ThreadGroupStartTimeNs++
	four, _ := IdentityFor(reg, c)
	if one.Process == four.Process {
		t.Fatal("reused TGID merged")
	}
	c.ThreadId, c.ThreadStartTimeNs = 0, 0
	partial, _ := IdentityFor(reg, c)
	if partial.Task != "" || partial.Process == "" || len(partial.Gaps) != 1 {
		t.Fatalf("invented thread: %+v", partial)
	}
	c.ContainerId = "foreign"
	if _, err := IdentityFor(reg, c); err == nil {
		t.Fatal("accepted foreign container")
	}
	missing, err := IdentityFor(reg, nil)
	if err != nil || missing.Task != "" || len(missing.Gaps) != 1 {
		t.Fatalf("missing: %+v %v", missing, err)
	}
}

func FuzzDecodePacket(f *testing.F) {
	f.Add(packetBytes(f, wire.MessageType_MESSAGE_SYSCALL_OPEN, &wire.Open{ContextData: testContext()}, 0))
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxPacketBytes+1 {
			t.Skip()
		}
		p, err := DecodePacket(b)
		if err == nil && (p.Header.Size < HeaderBytes || int(p.Header.Size) > len(b)) {
			t.Fatal("accepted invalid bounds")
		}
	})
}
