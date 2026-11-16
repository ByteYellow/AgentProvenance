// Package runtimeadapter binds existing execution and capture implementations.
// Durable admission, query, cancellation requests and recovery belong to handoff.
package runtimeadapter

import (
	"context"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/byteyellow/agentprovenance/internal/record"
)

const Schema = "agentprovenance.runtime_adapter/v1"

type Target struct {
	ProducerID string `json:"producer_id"`
	InstanceID string `json:"instance_id"`
	Generation string `json:"generation"`
}

func (t Target) Validate() error {
	for _, v := range []string{t.ProducerID, t.InstanceID, t.Generation} {
		if !validIdentity(v) {
			return fmt.Errorf("invalid runtime target identity")
		}
	}
	return nil
}

func validIdentity(v string) bool {
	if v == "" || len(v) > 512 || strings.TrimSpace(v) != v || !utf8.ValidString(v) {
		return false
	}
	for _, c := range v {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

// Binding is a trusted launcher assertion. Restores and clones require a new
// Target generation; a runtime endpoint or a PID cannot assign that identity.
type Binding struct {
	Target         Target `json:"target"`
	Mode           string `json:"mode"`
	ContainerID    string `json:"container_id,omitempty"`
	StateCreated   string `json:"state_created,omitempty"`
	RuntimeClass   string `json:"runtime_class,omitempty"`
	RuntimeHandler string `json:"runtime_handler,omitempty"`
	PodUID         string `json:"pod_uid,omitempty"`
	GuestBootID    string `json:"guest_boot_id,omitempty"`
}

type PlatformBinding interface {
	Resolve(context.Context, Target) (Binding, error)
}

func (b Binding) Resolve(ctx context.Context, target Target) (Binding, error) {
	if err := ctx.Err(); err != nil {
		return Binding{}, err
	}
	if err := b.Target.Validate(); err != nil {
		return Binding{}, err
	}
	if target != b.Target {
		return Binding{}, fmt.Errorf("runtime target generation or identity mismatch")
	}
	switch b.Mode {
	case "native":
		if b.StateCreated != "" || b.guestIdentity() != (GuestIdentity{}) {
			return Binding{}, fmt.Errorf("native binding cannot specify a runtime container")
		}
	case "guest":
		if b.StateCreated != "" {
			return Binding{}, fmt.Errorf("guest binding cannot specify runsc state")
		}
		if g := b.guestIdentity(); g != (GuestIdentity{}) {
			if err := g.Validate(); err != nil {
				return Binding{}, err
			}
		}
	case "runsc":
		if b.RuntimeClass != "" || b.RuntimeHandler != "" || b.PodUID != "" || b.GuestBootID != "" {
			return Binding{}, fmt.Errorf("runsc binding cannot specify a guest identity")
		}
		if !safeName(b.ContainerID) || b.StateCreated == "" {
			return Binding{}, fmt.Errorf("runsc binding requires container_id and state_created")
		}
	default:
		return Binding{}, fmt.Errorf("unsupported execution backend %q", b.Mode)
	}
	return b, nil
}

func safeName(s string) bool {
	if s == "" || len(s) > 256 || s == "." || s == ".." || s[0] == '-' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_.-", c)) {
			return false
		}
	}
	return true
}

type Request struct {
	Target      Target
	OperationID string
	AttemptID   string
	Command     record.Request
}

func (r Request) Validate() error {
	if err := r.Target.Validate(); err != nil {
		return err
	}
	if !validIdentity(r.OperationID) || !validIdentity(r.AttemptID) || !validIdentity(r.Command.RunID) || len(r.Command.Command) == 0 || len(r.Command.Command) > 256 || r.Command.Command[0] == "" {
		return fmt.Errorf("runtime execution requires operation, attempt, run and command")
	}
	for _, s := range append(append([]string{}, r.Command.Command...), r.Command.Workdir) {
		if !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
			return fmt.Errorf("runtime command contains invalid text")
		}
	}
	return nil
}

type Execution struct {
	SchemaVersion  string   `json:"schema_version"`
	Binding        Binding  `json:"binding"`
	OperationID    string   `json:"operation_id"`
	AttemptID      string   `json:"attempt_id"`
	RunID          string   `json:"run_id"`
	State          string   `json:"state"`
	Started        bool     `json:"started"`
	ExitCode       *int     `json:"exit_code,omitempty"`
	RuntimeRelease string   `json:"runtime_release,omitempty"`
	SentryPID      int32    `json:"sentry_pid,omitempty"`
	SentryPIDBasis string   `json:"sentry_pid_basis,omitempty"`
	SentryStartNS  int64    `json:"sentry_start_ns,string,omitempty"`
	GateReleased   bool     `json:"gate_released,omitempty"`
	Gaps           []string `json:"gaps"`
	// Native evidence remains in record's existing objects, not a second journal.
	Record *record.Result `json:"-"`
}

func NewExecution(b Binding, r Request) Execution {
	return Execution{SchemaVersion: Schema, Binding: b, OperationID: r.OperationID, AttemptID: r.AttemptID, RunID: r.Command.RunID, State: "starting", Gaps: []string{}}
}

func (e Execution) Matches(r Request) bool {
	return e.SchemaVersion == Schema && e.Binding.Target == r.Target && e.OperationID == r.OperationID && e.AttemptID == r.AttemptID && e.RunID == r.Command.RunID
}

// Run is invoked once, only after the ledger has claimed an attempt. Context
// cancellation stops the owned execution transport; the result says whether
// workload termination was observed. Query never calls this interface.
type ExecutionBackend interface {
	Admit(context.Context, Request) error
	Run(context.Context, Request, func(Execution) error) (Execution, error)
}

type CaptureBackend interface {
	Probe(context.Context, Target) (CapturePoint, error)
	Finish(context.Context, Target, CapturePoint) CaptureReport
}

type CommandCaptureBackend interface {
	FinishCommand(context.Context, Request, Execution, CapturePoint) CaptureReport
}
