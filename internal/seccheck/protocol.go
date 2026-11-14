// Package seccheck receives the pinned gVisor remote trace protocol. It does not
// assign host process IDs or Tool Calls from Sentry-supplied fields.
package seccheck

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/seccheck/wire"
	"google.golang.org/protobuf/proto"
)

const (
	RuntimeRelease    = "release-20261109.0"
	UpstreamCommit    = "a0e6be6fb5e03d8ebea13592f36a097c7e9a41b9"
	ProtocolVersion   = 1
	MaxPacketBytes    = 1 << 20
	MaxHandshakeBytes = 256
	HeaderBytes       = 8
)

// Registration is supplied by the trusted runtime launcher, once per sandbox
// lifecycle. A dedicated private socket binds the connection to this scope.
// Peer credentials authenticate the local launcher, not individual Tool Calls.
type Registration struct {
	Namespace   string `json:"namespace"`
	InstanceID  string `json:"instance_id"`
	Generation  string `json:"generation"`
	SandboxID   string `json:"sandbox_id"`
	ContainerID string `json:"container_id"`
	PeerUID     uint32 `json:"peer_uid"`
}

func (r Registration) Validate() error {
	for _, field := range []struct{ name, value string }{
		{"namespace", r.Namespace}, {"instance_id", r.InstanceID},
		{"generation", r.Generation}, {"sandbox_id", r.SandboxID}, {"container_id", r.ContainerID},
	} {
		if field.value == "" || len(field.value) > 256 || strings.TrimSpace(field.value) != field.value || strings.ContainsAny(field.value, "\x00\r\n") {
			return fmt.Errorf("invalid SecCheck registration %s", field.name)
		}
	}
	return nil
}

type Header struct {
	Size         uint16 `json:"size"`
	MessageType  uint16 `json:"message_type"`
	DroppedCount uint32 `json:"dropped_count"`
}

// Packet retains the original packet digest and typed fields, including fields
// not yet projected by the consumer. Persisted content must pass the receiving
// application's retention and redaction policy before reaching storage.
type Packet struct {
	Header  Header
	SHA256  string
	Size    int
	Message proto.Message
	Context *wire.ContextData
}

func HandshakeReply(data []byte) ([]byte, error) {
	if len(data) == 0 || len(data) > MaxHandshakeBytes {
		return nil, fmt.Errorf("invalid SecCheck handshake size")
	}
	var request wire.Handshake
	if err := (proto.UnmarshalOptions{RecursionLimit: 16}).Unmarshal(data, &request); err != nil {
		return nil, fmt.Errorf("invalid SecCheck handshake: %w", err)
	}
	if request.Version != ProtocolVersion {
		return nil, fmt.Errorf("unsupported SecCheck protocol version %d", request.Version)
	}
	return proto.Marshal(&wire.Handshake{Version: ProtocolVersion})
}

func DecodePacket(data []byte) (Packet, error) {
	p := Packet{Size: len(data), SHA256: fmt.Sprintf("%x", sha256.Sum256(data))}
	if len(data) < HeaderBytes || len(data) > MaxPacketBytes {
		return p, fmt.Errorf("invalid SecCheck packet size %d", len(data))
	}
	p.Header = Header{
		Size:         binary.LittleEndian.Uint16(data[:2]),
		MessageType:  binary.LittleEndian.Uint16(data[2:4]),
		DroppedCount: binary.LittleEndian.Uint32(data[4:8]),
	}
	if p.Header.Size < HeaderBytes || int(p.Header.Size) > len(data) {
		return p, fmt.Errorf("invalid SecCheck header size %d", p.Header.Size)
	}
	switch wire.MessageType(p.Header.MessageType) {
	case wire.MessageType_MESSAGE_CONTAINER_START:
		p.Message = &wire.Start{}
	case wire.MessageType_MESSAGE_SENTRY_CLONE:
		p.Message = &wire.CloneInfo{}
	case wire.MessageType_MESSAGE_SENTRY_EXEC:
		p.Message = &wire.ExecveInfo{}
	case wire.MessageType_MESSAGE_SENTRY_EXIT_NOTIFY_PARENT:
		p.Message = &wire.ExitNotifyParentInfo{}
	case wire.MessageType_MESSAGE_SENTRY_TASK_EXIT:
		p.Message = &wire.TaskExit{}
	case wire.MessageType_MESSAGE_SYSCALL_OPEN:
		p.Message = &wire.Open{}
	case wire.MessageType_MESSAGE_SYSCALL_CONNECT:
		p.Message = &wire.Connect{}
	case wire.MessageType_MESSAGE_SYSCALL_EXECVE:
		p.Message = &wire.Execve{}
	case wire.MessageType_MESSAGE_SYSCALL_CLONE:
		p.Message = &wire.Clone{}
	case wire.MessageType_MESSAGE_SYSCALL_FORK:
		p.Message = &wire.Fork{}
	default:
		return p, nil
	}
	if err := (proto.UnmarshalOptions{RecursionLimit: 16}).Unmarshal(data[p.Header.Size:], p.Message); err != nil {
		return p, fmt.Errorf("invalid SecCheck protobuf: %w", err)
	}
	p.Context = p.Message.(interface{ GetContextData() *wire.ContextData }).GetContextData()
	return p, nil
}

type Identity struct {
	Scope               string   `json:"scope"`
	Task                string   `json:"task,omitempty"`
	Process             string   `json:"process,omitempty"`
	ThreadID            int32    `json:"thread_id,omitempty"`
	ThreadGroupID       int32    `json:"thread_group_id,omitempty"`
	ParentThreadGroupID int32    `json:"parent_thread_group_id,omitempty"`
	Gaps                []string `json:"gaps,omitempty"`
}

// IdentityFor uses root PID-namespace IDs and CLOCK_REALTIME birth values from
// SecCheck. Host boot IDs, host PIDs and numerical parents are not substituted.
func IdentityFor(reg Registration, c *wire.ContextData) (Identity, error) {
	if err := reg.Validate(); err != nil {
		return Identity{}, err
	}
	raw, _ := json.Marshal([]string{reg.Namespace, reg.InstanceID, reg.Generation, reg.SandboxID, reg.ContainerID})
	id := Identity{Scope: fmt.Sprintf("gvisor/%x", sha256.Sum256(raw))}
	if c == nil {
		id.Gaps = []string{"context_missing"}
		return id, nil
	}
	if c.ContainerId != reg.ContainerID {
		return id, fmt.Errorf("SecCheck container does not match registration")
	}
	id.ThreadID, id.ThreadGroupID, id.ParentThreadGroupID = c.ThreadId, c.ThreadGroupId, c.ParentThreadGroupId
	ref := func(kind string, pid int32, birth int64) string {
		return id.Scope + "/" + kind + "/" + strconv.FormatInt(int64(pid), 10) + ":" + strconv.FormatInt(birth, 10)
	}
	if c.ThreadId > 0 && c.ThreadStartTimeNs > 0 {
		id.Task = ref("task", c.ThreadId, c.ThreadStartTimeNs)
	} else {
		id.Gaps = append(id.Gaps, "thread_birth_missing")
	}
	if c.ThreadGroupId > 0 && c.ThreadGroupStartTimeNs > 0 {
		id.Process = ref("process", c.ThreadGroupId, c.ThreadGroupStartTimeNs)
	} else {
		id.Gaps = append(id.Gaps, "process_birth_missing")
	}
	if c.TimeNs <= 0 {
		id.Gaps = append(id.Gaps, "event_time_missing")
	}
	return id, nil
}
