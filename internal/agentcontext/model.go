// Package agentcontext preserves source-asserted agent records separately from
// kernel observations and analysis. Missing source information remains unknown.
package agentcontext

import (
	"github.com/byteyellow/agentprovenance/internal/observability"
	"github.com/byteyellow/agentprovenance/internal/provenance"
)

const SchemaVersion = "agentprovenance.agent_context/v1"

type Status string

const (
	Disabled          Status = "disabled"
	NoInput           Status = "no_input"
	Empty             Status = "empty"
	OK                Status = "ok"
	Partial           Status = "partial"
	Failed            Status = "failed"
	Ambiguous         Status = "ambiguous"
	LegacyNotRecorded Status = "legacy_not_recorded"
)

type Source struct {
	ID                 string   `json:"id"`
	Harness            string   `json:"harness"`
	Channel            string   `json:"channel,omitempty"`
	SessionID          string   `json:"session_id"`
	ParentSessionID    string   `json:"parent_session_id,omitempty"`
	AgentID            string   `json:"agent_id,omitempty"`
	Path               string   `json:"path,omitempty"`
	ParserVersion      string   `json:"parser_version"`
	ApplicationVersion string   `json:"application_version,omitempty"`
	FormatVersion      string   `json:"format_version,omitempty"`
	Binding            string   `json:"binding"`
	BindingEvidence    []string `json:"binding_evidence,omitempty"`
	Workdir            string   `json:"workdir,omitempty"`
}

// Counts are observations over one processing range, not estimates of all
// activity. Nil means unknown; a successful empty scan can explicitly report 0.
type Counts struct {
	Discovered   *int64 `json:"discovered"`
	Matched      *int64 `json:"matched"`
	Read         *int64 `json:"read"`
	Parsed       *int64 `json:"parsed"`
	Stored       *int64 `json:"stored"`
	Duplicates   *int64 `json:"duplicates"`
	Truncated    *int64 `json:"truncated"`
	Failed       *int64 `json:"failed"`
	Unrecognized *int64 `json:"unrecognized"`
	Deferred     *int64 `json:"deferred"`
}

type Issue struct {
	Code  string `json:"code"`
	Line  int64  `json:"line,omitempty"`
	Field string `json:"field,omitempty"`
}

type Coverage struct {
	SchemaVersion string   `json:"schema_version"`
	ID            string   `json:"id"`
	RunID         string   `json:"run_id"`
	Source        Source   `json:"source"`
	Status        Status   `json:"status"`
	ObservedAt    string   `json:"observed_at"`
	LastSuccessAt string   `json:"last_success_at,omitempty"`
	StartedAt     string   `json:"started_at,omitempty"`
	EndedAt       string   `json:"ended_at,omitempty"`
	FirstLine     int64    `json:"first_line,omitempty"`
	LastLine      int64    `json:"last_line,omitempty"`
	Counts        Counts   `json:"counts"`
	Issues        []Issue  `json:"issues"`
	MissingFields []string `json:"missing_fields"`
	ObjectHash    string   `json:"object_hash,omitempty"`
}

type ContentRef struct {
	Ref       string `json:"ref,omitempty"`
	Bytes     *int64 `json:"bytes"`
	SHA256    string `json:"sha256,omitempty"`
	MediaType string `json:"media_type,omitempty"`
	Redacted  bool   `json:"redacted"`
	State     string `json:"state"`
	Reason    string `json:"reason,omitempty"`
}

type Entry struct {
	SchemaVersion string     `json:"schema_version"`
	ID            string     `json:"id"`
	RunID         string     `json:"run_id"`
	Source        Source     `json:"source"`
	SourceKey     string     `json:"source_key"`
	Sequence      int64      `json:"sequence"`
	Kind          string     `json:"kind"`
	Role          string     `json:"role,omitempty"`
	AgentID       string     `json:"agent_id,omitempty"`
	ToolCallID    string     `json:"tool_call_id,omitempty"`
	ToolName      string     `json:"tool_name,omitempty"`
	Status        string     `json:"status,omitempty"`
	RecordedAt    string     `json:"recorded_at,omitempty"`
	Content       ContentRef `json:"content"`
	RawContent    ContentRef `json:"raw_content"`
	MissingFields []string   `json:"missing_fields,omitempty"`
	EvidenceRefs  []string   `json:"evidence_refs,omitempty"`
	ObjectHash    string     `json:"object_hash,omitempty"`
	CreatedAt     string     `json:"created_at,omitempty"`
}

// Record is a parser's transient output. Body never appears in the entry index
// or diagnostics: it is redacted and stored as bounded content-addressed chunks.
type Record struct {
	Key           string
	Sequence      int64
	Kind          string
	Role          string
	AgentID       string
	ToolCallID    string
	ToolName      string
	Status        string
	RecordedAt    string
	Body          *string
	RawBody       *string
	MediaType     string
	MissingReason string
	MissingFields []string
	// Parsed values are position-specific, including unknown values. Nil lets
	// explicit Record callers use the source defaults.
	Workdir            *string
	ApplicationVersion *string
}

type SaveResult struct {
	Stored     int      `json:"stored"`
	Duplicates int      `json:"duplicates"`
	Coverage   Coverage `json:"coverage"`
}

type PageOptions struct {
	RunID            string
	SessionID        string
	SourceID         string
	Kind             string
	ToolCallID       string
	EntryID          string
	NodeID           string
	Group            string
	Cursor           string
	Limit            int
	IncludeRevisions bool
}

type Page struct {
	SchemaVersion string  `json:"schema_version"`
	RunID         string  `json:"run_id"`
	Entries       []Entry `json:"entries"`
	NextCursor    string  `json:"next_cursor,omitempty"`
	HasMore       bool    `json:"has_more"`
	Limit         int     `json:"limit"`
}

type Overview struct {
	SchemaVersion   string                        `json:"schema_version"`
	RunID           string                        `json:"run_id"`
	Coverage        []Coverage                    `json:"coverage"`
	Messages        *int64                        `json:"messages"`
	ToolCalls       *int64                        `json:"tool_calls"`
	ToolResults     *int64                        `json:"tool_results"`
	Snapshots       *int64                        `json:"snapshots"`
	HasMoreSources  bool                          `json:"has_more_sources"`
	RuntimeCoverage observability.RuntimeCoverage `json:"runtime_coverage"`
}

func Number(n int64) *int64 { return &n }

func contentReference(c provenance.TextContent) ContentRef {
	return ContentRef{Ref: c.Ref, Bytes: Number(c.Bytes), SHA256: c.SHA256,
		MediaType: c.MediaType, Redacted: c.Redacted, State: "stored"}
}
