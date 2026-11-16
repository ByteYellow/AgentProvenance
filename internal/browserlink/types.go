// Package browserlink projects layered Browser relations from retained native
// evidence. It does not collect events, authenticate receipts, or infer causes
// from timestamps, URLs, context membership, or numeric PIDs.
package browserlink

import (
	"encoding/json"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

const (
	NativeRule     = "agentprov.browser_native_refs/v1"
	RuntimeRule    = "agentprov.browser_runtime_custody/v1"
	MaxRecords     = 25000
	MaxRecordBytes = 2 << 20
	MaxInputBytes  = 64 << 20
)

// Scope is the identity projection of the existing Browser capture scope, not
// a separate capture format. Every component participates in matching.
type Scope struct {
	ProducerID string `json:"producer_id"`
	Namespace  string `json:"namespace"`
	InstanceID string `json:"instance_id"`
	Generation string `json:"generation"`
	BrowserID  string `json:"browser_id"`
	ContextID  string `json:"context_id"`
}

func (s Scope) complete() bool {
	for _, id := range []string{s.ProducerID, s.Namespace, s.InstanceID, s.Generation, s.BrowserID, s.ContextID} {
		if id == "" || !validID(id) {
			return false
		}
	}
	return true
}

func validID(id string) bool {
	return len(id) <= 512 && strings.TrimSpace(id) == id && utf8.ValidString(id) && strings.IndexFunc(id, unicode.IsControl) < 0
}

// Record contains an existing agent_context object's verified payload and hash.
// The caller checks the content address and run ownership before projecting it.
type Record struct {
	Ref     string
	Payload json.RawMessage
}

type Input struct {
	RunID   string
	Records []Record
	Events  []telemetry.EventRecord
	// Custody is supplied by a trusted local caller after independent receipt
	// verification and operator runtime mapping. It is never read from entries.
	Custody []RuntimeCustody
}

type Node struct {
	ID    string
	Kind  string
	Label string
	Data  map[string]any
}

type Relation struct {
	ID            string   `json:"id"`
	From          string   `json:"from"`
	To            string   `json:"to"`
	Kind          string   `json:"kind"`
	Rule          string   `json:"rule"`
	Basis         string   `json:"basis"`
	Status        string   `json:"status"`
	Scope         Scope    `json:"scope"`
	SourceRefs    []string `json:"source_refs"`
	EvidenceGrade string   `json:"evidence_grade"`
	SourceEventID string   `json:"source_event_id,omitempty"`
}

type Issue struct {
	NodeID     string   `json:"node_id"`
	Rule       string   `json:"rule"`
	Status     string   `json:"status"`
	Reason     string   `json:"reason"`
	SourceRefs []string `json:"source_refs"`
}

type Projection struct {
	Nodes     []Node
	Relations []Relation
	Issues    []Issue
}

// These private wire views read only fields of the existing agent_context
// schema needed by the rules. Keeping this package independent of agentcontext
// avoids its existing agentcontext -> provenance dependency cycle.
type entry struct {
	RunID          string `json:"run_id"`
	ExecutionScope string `json:"execution_scope"`
	Source         struct {
		ID        string `json:"id"`
		SessionID string `json:"session_id"`
		Harness   string `json:"harness"`
		Browser   *Scope `json:"browser"`
	} `json:"source"`
	Browser *native `json:"browser"`
}

type native struct {
	EventID            string `json:"event_id"`
	Kind               string `json:"kind"`
	TargetID           string `json:"target_id"`
	TargetType         string `json:"target_type"`
	CDPSessionID       string `json:"cdp_session_id"`
	FrameID            string `json:"frame_id"`
	LoaderID           string `json:"loader_id"`
	RequestID          string `json:"request_id"`
	RedirectIndex      int    `json:"redirect_index"`
	InitiatorRequestID string `json:"initiator_request_id"`
	OperationID        string `json:"operation_id"`
	Operation          string `json:"operation"`
	DownloadID         string `json:"download_id"`
}

type observation struct {
	ref     string
	scope   Scope
	scopeID string
	entry   entry
	native
}
