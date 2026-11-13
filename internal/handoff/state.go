package handoff

import "fmt"

type ExecutionState string
type CaptureState string
type DeliveryState string

const (
	Accepted  ExecutionState = "accepted"
	Starting  ExecutionState = "starting"
	Running   ExecutionState = "running"
	Succeeded ExecutionState = "succeeded"
	Failed    ExecutionState = "failed"
	Cancelled ExecutionState = "cancelled"
	Unknown   ExecutionState = "unknown"

	NotReady   CaptureState = "not_ready"
	Collecting CaptureState = "collecting"
	Draining   CaptureState = "draining"
	Sealed     CaptureState = "sealed"
	Incomplete CaptureState = "incomplete"

	Pending      DeliveryState = "pending"
	Transferring DeliveryState = "transferring"
	Acknowledged DeliveryState = "acknowledged"
	Conflict     DeliveryState = "conflict"
)

type State struct {
	Execution ExecutionState `json:"execution"`
	Capture   CaptureState   `json:"capture"`
	Delivery  DeliveryState  `json:"delivery"`
}

func InitialState() State {
	return State{Execution: Accepted, Capture: NotReady, Delivery: Pending}
}

func (s ExecutionState) CanTransition(next ExecutionState) bool {
	switch s {
	case Accepted:
		return next == Starting || next == Failed || next == Cancelled
	case Starting:
		return next == Running || next == Failed || next == Cancelled || next == Unknown
	case Running:
		return next == Succeeded || next == Failed || next == Cancelled || next == Unknown
	case Unknown:
		return next == Running || next == Succeeded || next == Failed || next == Cancelled
	}
	return false
}

func (s ExecutionState) CanReexecute() bool {
	return s == Succeeded || s == Failed || s == Cancelled || s == Unknown
}

func (s CaptureState) CanTransition(next CaptureState) bool {
	switch s {
	case NotReady:
		return next == Collecting || next == Incomplete
	case Collecting:
		return next == Draining || next == Incomplete
	case Draining:
		return next == Sealed || next == Incomplete
	}
	return false
}

func (s DeliveryState) CanTransition(next DeliveryState) bool {
	switch s {
	case Pending:
		return next == Transferring || next == Conflict
	case Transferring:
		return next == Pending || next == Acknowledged || next == Conflict
	}
	return false
}

func transitionError(from, to ExecutionState) error {
	return fmt.Errorf("%w: execution transition %s -> %s is not allowed", ErrConflict, from, to)
}
