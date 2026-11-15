package telemetry

import (
	"encoding/json"
	"fmt"

	"github.com/byteyellow/agentprovenance/internal/seccheck"
	"github.com/byteyellow/agentprovenance/internal/seccheck/wire"
)

// SecCheckPoint identifies the saved wire message and stage. Message families
// such as Open cover several syscalls; a reader's architecture cannot name them.
type SecCheckPoint struct {
	MessageType   uint16
	MessageName   string
	Stage         string
	SyscallNumber *uint64
}

func ReadSecCheckPoint(event EventRecord) (SecCheckPoint, error) {
	var point SecCheckPoint
	e, err := ReadSecCheckEvidence(event)
	if err != nil {
		return point, err
	}
	if e.Kind != "event" || e.Header == nil || e.RuntimeRelease != seccheck.RuntimeRelease {
		return point, fmt.Errorf("unsupported SecCheck checkpoint evidence")
	}
	body, err := readSecCheckBody(event.Payload)
	if err != nil {
		return point, err
	}
	if err := json.Unmarshal(body["observation_stage"], &point.Stage); err != nil {
		return point, fmt.Errorf("SecCheck checkpoint stage: %w", err)
	}
	point.MessageType = e.Header.MessageType
	typ := wire.MessageType(point.MessageType)
	point.MessageName = typ.String()
	syscall := false
	switch typ {
	case wire.MessageType_MESSAGE_CONTAINER_START, wire.MessageType_MESSAGE_SENTRY_CLONE,
		wire.MessageType_MESSAGE_SENTRY_EXEC, wire.MessageType_MESSAGE_SENTRY_EXIT_NOTIFY_PARENT, wire.MessageType_MESSAGE_SENTRY_TASK_EXIT:
		if point.Stage != "sentry_checkpoint" {
			return point, fmt.Errorf("SecCheck lifecycle checkpoint has incompatible stage")
		}
	case wire.MessageType_MESSAGE_SYSCALL_OPEN, wire.MessageType_MESSAGE_SYSCALL_CONNECT,
		wire.MessageType_MESSAGE_SYSCALL_EXECVE, wire.MessageType_MESSAGE_SYSCALL_CLONE, wire.MessageType_MESSAGE_SYSCALL_FORK:
		syscall = true
		if point.Stage != "attempt" && point.Stage != "result" {
			return point, fmt.Errorf("SecCheck syscall checkpoint has incompatible stage")
		}
		if err := json.Unmarshal(body["syscall_number"], &point.SyscallNumber); err != nil || point.SyscallNumber == nil {
			return point, fmt.Errorf("SecCheck checkpoint requires an unsigned syscall number")
		}
	default:
		return point, fmt.Errorf("unsupported SecCheck checkpoint message %d", point.MessageType)
	}
	if !syscall && body["syscall_number"] != nil {
		return point, fmt.Errorf("SecCheck lifecycle checkpoint has a syscall number")
	}
	return point, nil
}
