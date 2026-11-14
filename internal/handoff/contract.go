// Package handoff records authenticated execution handoffs between producers.
// Admission is durable; execution is a separate, explicitly claimed operation.
package handoff

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	SchemaVersion = "agentprovenance.execution_handoff/v1"
	DigestVersion = "agentprovenance.execution_request_sha256/v1"
	MaxValidity   = 24 * time.Hour
)

var (
	ErrInvalid         = errors.New("invalid_execution_request")
	ErrForbidden       = errors.New("execution_source_forbidden")
	ErrConflict        = errors.New("execution_conflict")
	ErrExpired         = errors.New("execution_request_expired")
	ErrNotFound        = errors.New("execution_not_found")
	ErrStale           = errors.New("execution_revision_conflict")
	ErrDeliveryRetired = errors.New("execution_delivery_retired")
)

type Source struct {
	ProducerID string `json:"producer_id"`
	Namespace  string `json:"namespace"`
	RunID      string `json:"run_id"`
	Harness    string `json:"harness"`
	SessionID  string `json:"session_id"`
	ToolCallID string `json:"tool_call_id"`
}

// Generation is assigned outside the guest, including after snapshot restore.
type Target struct {
	ProducerID string `json:"producer_id"`
	InstanceID string `json:"instance_id"`
	Generation string `json:"generation"`
}

// Principal comes from trusted transport configuration, never from a request
// body. Its namespace is owned by a tool router, not by model-supplied arguments.
type Principal struct {
	ID             string
	ProducerID     string
	Namespace      string
	AllowedTargets []Target
}

func (p Principal) Authorize(source Source, target Target) error {
	if !validID(p.ID) || !validID(p.ProducerID) || !validID(p.Namespace) ||
		p.ProducerID != source.ProducerID || p.Namespace != source.Namespace {
		return ErrForbidden
	}
	for _, allowed := range p.AllowedTargets {
		if allowed == target && target.Validate() == nil {
			return nil
		}
	}
	return ErrForbidden
}

func (s Source) Validate() error {
	for _, id := range []string{s.ProducerID, s.Namespace, s.RunID, s.Harness, s.SessionID, s.ToolCallID} {
		if !validID(id) {
			return fmt.Errorf("%w: source identity is required", ErrInvalid)
		}
	}
	return nil
}

func (t Target) Validate() error {
	for _, id := range []string{t.ProducerID, t.InstanceID, t.Generation} {
		if !validID(id) {
			return fmt.Errorf("%w: target identity is required", ErrInvalid)
		}
	}
	return nil
}

type Command struct {
	Argv             []string `json:"argv"`
	Workdir          string   `json:"workdir"`
	DisableSnapshot  bool     `json:"disable_snapshot"`
	SampleIntervalMS int64    `json:"sample_interval_ms"`
	PostRootGraceMS  int64    `json:"post_root_grace_ms"`
	CapturePreset    string   `json:"capture_preset"`
	ToolResults      *bool    `json:"tool_results,omitempty"`
}

type Request struct {
	SchemaVersion     string    `json:"schema_version"`
	Source            Source    `json:"source"`
	Target            Target    `json:"target"`
	DispatchID        string    `json:"dispatch_id"`
	OperationID       string    `json:"operation_id"`
	PreviousAttemptID string    `json:"previous_attempt_id,omitempty"`
	ValidUntil        time.Time `json:"valid_until"`
	Command           Command   `json:"command"`
}

// Canonical normalizes only explicit protocol defaults. It does not rewrite
// argv, paths or native IDs; those distinctions can change executed behavior.
func (r Request) Canonical() (Request, []byte, string, error) {
	invalid := func(why string) (Request, []byte, string, error) {
		return Request{}, nil, "", fmt.Errorf("%w: %s", ErrInvalid, why)
	}
	if r.SchemaVersion != SchemaVersion {
		return invalid("unsupported schema_version")
	}
	if err := r.Source.Validate(); err != nil {
		return invalid("invalid source")
	}
	if err := r.Target.Validate(); err != nil {
		return invalid("invalid target")
	}
	if !validID(r.DispatchID) || !validID(r.OperationID) ||
		(r.PreviousAttemptID != "" && !validID(r.PreviousAttemptID)) {
		return invalid("invalid dispatch or operation identity")
	}
	if r.ValidUntil.IsZero() || r.ValidUntil.Year() < 2000 || r.ValidUntil.Year() > 2200 {
		return invalid("valid_until is required")
	}
	r.ValidUntil = r.ValidUntil.UTC()
	if len(r.Command.Argv) == 0 || len(r.Command.Argv) > 256 || r.Command.Argv[0] == "" {
		return invalid("argv must contain between 1 and 256 entries")
	}
	for _, arg := range append(append([]string{}, r.Command.Argv...), r.Command.Workdir) {
		if !utf8.ValidString(arg) || strings.ContainsRune(arg, 0) {
			return invalid("command contains invalid text")
		}
	}
	if r.Command.SampleIntervalMS == 0 {
		r.Command.SampleIntervalMS = 25
	}
	if r.Command.PostRootGraceMS == 0 {
		r.Command.PostRootGraceMS = 250
	}
	if r.Command.SampleIntervalMS < 1 || r.Command.SampleIntervalMS > 60000 ||
		r.Command.PostRootGraceMS < 1 || r.Command.PostRootGraceMS > 30000 {
		return invalid("invalid process sampling interval")
	}
	if r.Command.CapturePreset == "" {
		r.Command.CapturePreset = "detailed"
	}
	if r.Command.CapturePreset != "basic" && r.Command.CapturePreset != "detailed" {
		return invalid("capture_preset must be basic or detailed")
	}
	// Detach the admitted request from caller-owned mutable slices and pointers.
	r.Command.Argv = append([]string(nil), r.Command.Argv...)
	if r.Command.ToolResults != nil {
		value := *r.Command.ToolResults
		r.Command.ToolResults = &value
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return Request{}, nil, "", err
	}
	if len(raw) > 1<<20 {
		return invalid("request exceeds 1 MiB")
	}
	return r, raw, digest(DigestVersion, string(raw)), nil
}

func validID(id string) bool {
	if id == "" || len(id) > 512 || strings.TrimSpace(id) != id || !utf8.ValidString(id) {
		return false
	}
	for _, r := range id {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// JSON arrays provide unambiguous field boundaries even for native IDs that
// contain separators. Domain tags prevent keys for different entities colliding.
func digest(parts ...string) string {
	raw, _ := json.Marshal(parts)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func sourceKey(source Source) string {
	return digest("source/v1", source.ProducerID, source.Namespace, source.RunID,
		source.Harness, source.SessionID, source.ToolCallID)
}

func dispatchKey(r Request) string {
	return digest("dispatch/v1", r.Source.ProducerID, r.Source.Namespace, r.DispatchID)
}

func operationKey(r Request) string {
	return digest("operation/v1", r.Source.ProducerID, r.Source.Namespace, r.OperationID)
}
