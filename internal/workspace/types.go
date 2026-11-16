package workspace

import (
	"context"
	"errors"
	"io/fs"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/substrate/state"
)

const (
	SchemaVersion       = "agentprovenance.workspace/v1"
	RemoteAuthoritative = "remote-authoritative"
	Absent              = "absent"
)

var (
	ErrInvalid     = errors.New("invalid_workspace_request")
	ErrConflict    = errors.New("workspace_conflict")
	ErrStaleTarget = errors.New("workspace_stale_target")
	ErrForbidden   = errors.New("workspace_operation_forbidden")
	ErrUnsafePath  = errors.New("workspace_unsafe_path")
	ErrLimit       = errors.New("workspace_limit")
	ErrChanged     = errors.New("workspace_changed_during_observation")
	ErrRecovery    = errors.New("workspace_recovery_required")
)

type Operation string

const (
	Read    Operation = "read"
	Write   Operation = "write"
	Edit    Operation = "edit"
	Rename  Operation = "rename"
	Delete  Operation = "delete"
	Chmod   Operation = "chmod"
	Execute Operation = "execute"
)

type Target struct {
	ProducerID string `json:"producer_id"`
	InstanceID string `json:"instance_id"`
	Generation string `json:"generation"`
}

type WorkspaceBinding struct {
	WorkspaceID       string      `json:"workspace_id"`
	Target            Target      `json:"target"`
	Root              string      `json:"root"`
	Mode              string      `json:"mode"`
	AllowedOperations []Operation `json:"allowed_operations"`
	Revision          uint64      `json:"revision"`
	ManifestDigest    string      `json:"manifest_digest"`
	ManifestRef       string      `json:"manifest_ref"`
	EvidenceRef       string      `json:"evidence_ref"`
}

// Limits may narrow, but not exceed, the hard bounds in normalizeLimits.
type Limits struct {
	FileBytes   int64 `json:"file_bytes"`
	TotalBytes  int64 `json:"total_bytes"`
	Entries     int   `json:"entries"`
	OutputBytes int64 `json:"output_bytes"`
}

type Config struct {
	StateDir      string
	Binding       WorkspaceBinding
	RunID         string
	Limits        Limits
	Objects       provenance.ObjectStore
	CurrentTarget func(context.Context) (Target, error)
}

// Request identity is mandatory on every call. Mutations require a revision or
// source digest. Absent means create-only; SHA256 values are lowercase hex.
// When both preconditions are supplied, both must match.
type Request struct {
	WorkspaceID      string
	Target           Target
	ExpectedRevision *uint64
	ExpectedDigest   string
	Path             string
	ToolCallID       string
}

type Content struct {
	State        string `json:"state"`
	SourceSHA256 string `json:"source_sha256,omitempty"`
	SourceBytes  int64  `json:"source_bytes"`
	Ref          string `json:"ref,omitempty"`
	StoredSHA256 string `json:"stored_sha256,omitempty"`
	Redacted     bool   `json:"redacted"`
}

// FileEntry reuses state file hashes, sizes and mode spelling. Directory entries
// are included explicitly so empty directories and their modes affect revision.
type Entry struct {
	state.FileEntry
	Directory bool    `json:"directory"`
	Content   Content `json:"content"`
}

type Snapshot struct {
	Digest  string  `json:"digest"`
	Entries []Entry `json:"entries"`
	Bytes   int64   `json:"bytes"`
}

type Change struct {
	Path   string           `json:"path"`
	Kind   string           `json:"kind"`
	Before *state.FileEntry `json:"before,omitempty"`
	After  *state.FileEntry `json:"after,omitempty"`
}

// RecordReference names independently collected record evidence. The parent
// supplies these IDs from its runner, not from model-authored tool arguments.
type RecordReference struct {
	RunID          string `json:"run_id"`
	RolloutID      string `json:"rollout_id"`
	AttemptID      string `json:"attempt_id"`
	BaseSnapshotID string `json:"base_snapshot_id"`
}

type ExecutionInput struct {
	Binding  WorkspaceBinding
	Snapshot Snapshot
}

type ExecutionResult struct {
	Record   *RecordReference `json:"record,omitempty"`
	ExitCode int              `json:"exit_code"`
	Stdout   []byte           `json:"-"`
	Stderr   []byte           `json:"-"`
}

type Receipt struct {
	ID                string           `json:"id"`
	Kind              string           `json:"kind"`
	Operation         Operation        `json:"operation,omitempty"`
	Outcome           string           `json:"outcome"`
	Claim             string           `json:"claim"`
	ToolCallID        string           `json:"tool_call_id,omitempty"`
	Path              string           `json:"path,omitempty"`
	Destination       string           `json:"destination,omitempty"`
	InputRevision     uint64           `json:"input_revision"`
	OutputRevision    uint64           `json:"output_revision"`
	InputManifest     string           `json:"input_manifest"`
	OutputManifest    string           `json:"output_manifest"`
	PlannedManifest   string           `json:"planned_manifest,omitempty"`
	InputManifestRef  string           `json:"input_manifest_ref"`
	OutputManifestRef string           `json:"output_manifest_ref"`
	Changes           []Change         `json:"changes"`
	StartedAt         string           `json:"started_at"`
	EndedAt           string           `json:"ended_at"`
	Record            *RecordReference `json:"record,omitempty"`
	ExitCode          *int             `json:"exit_code,omitempty"`
	Stdout            Content          `json:"stdout"`
	Stderr            Content          `json:"stderr"`
	Ref               string           `json:"ref,omitempty"`
}

type View struct {
	Binding     WorkspaceBinding `json:"binding"`
	Snapshot    Snapshot         `json:"snapshot"`
	LastReceipt Receipt          `json:"last_receipt"`
}

type ReadResult struct {
	View   View
	Data   []byte
	SHA256 string
}

type WriteRequest struct {
	Request
	Data []byte
	// Mode applies to creates only. Existing file permissions are preserved;
	// use ChmodFile for an explicit permission change.
	Mode *fs.FileMode
}

type EditRequest struct {
	Request
	Old []byte
	New []byte
	// Count must be positive and equal the number of non-overlapping matches.
	Count int
}

type RenameRequest struct {
	Request
	Destination string
}

type ChmodRequest struct {
	Request
	Mode fs.FileMode
}
