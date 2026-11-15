// Package capturemanifest projects saved capture evidence without consulting
// the reader's host or the current producer capability catalog.
package capturemanifest

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const SchemaVersion = "agentprovenance.capture_manifest/v1"

var ErrInvalid = errors.New("invalid_capture_manifest_query")

type Options struct {
	RunID  string
	Cursor string
	Limit  int
}

type Page struct {
	SchemaVersion string   `json:"schema_version"`
	RunID         string   `json:"run_id"`
	Basis         string   `json:"basis"`
	Records       []Record `json:"records"`
	Limit         int      `json:"limit"`
	HasMore       bool     `json:"has_more"`
	NextCursor    string   `json:"next_cursor,omitempty"`
}

// Records are immutable observations, not a synthesized continuous-coverage
// claim. Consumers retain the interval basis and source-qualified identities.
type Record struct {
	ID              string            `json:"id"`
	EvidenceRef     string            `json:"evidence_ref"`
	EvidenceKind    string            `json:"evidence_kind"`
	Source          string            `json:"source"`
	ProducerVersion string            `json:"producer_version"`
	ProducerCommit  string            `json:"producer_commit"`
	Placement       string            `json:"placement"`
	IdentityDomain  string            `json:"identity_domain"`
	Identity        map[string]string `json:"identity"`
	ObservedAt      string            `json:"observed_at,omitempty"`
	StartedAt       string            `json:"started_at,omitempty"`
	EndedAt         string            `json:"ended_at,omitempty"`
	IntervalBasis   string            `json:"interval_basis"`
	Status          string            `json:"status"`
	Snapshots       []Snapshot        `json:"snapshots"`
	Retention       []Retention       `json:"retention"`
	Loss            []Counter         `json:"loss"`
	Issues          []string          `json:"issues"`
}

type Snapshot struct {
	ObservedAt string            `json:"observed_at,omitempty"`
	Boundary   string            `json:"boundary"`
	Status     string            `json:"status"`
	Reason     string            `json:"reason,omitempty"`
	Identity   map[string]string `json:"identity,omitempty"`
	Ready      *bool             `json:"ready"`
	Features   []Feature         `json:"features"`
}

// Unknown support/enabled values are intentionally separate from false.
type Feature struct {
	Name      string `json:"name"`
	Category  string `json:"category"`
	Target    string `json:"target,omitempty"`
	Supported *bool  `json:"supported"`
	Enabled   *bool  `json:"enabled"`
	State     string `json:"state"`
	Basis     string `json:"basis"`
	Reason    string `json:"reason,omitempty"`
}

type Retention struct {
	Category string `json:"category"`
	Enabled  *bool  `json:"enabled"`
	Basis    string `json:"basis"`
}

type Counter struct {
	Name    string  `json:"name"`
	Scope   string  `json:"scope"`
	ScopeID string  `json:"scope_id,omitempty"`
	Value   *string `json:"value"` // Decimal text preserves uint64 precision in browser readers.
	Basis   string  `json:"basis"`
}

type Service struct{ DB *sql.DB }

type cursor struct {
	Version string `json:"version"`
	RunID   string `json:"run_id"`
	Kind    string `json:"kind"`
	ID      string `json:"id"`
}

type evidence struct{ kind, id, objectType, recordedAt string }

// List uses keyset pagination over source evidence. A frozen export supplies a
// frozen DB; live pagination may observe new evidence and keeps all revisions.
func (s Service) List(ctx context.Context, opts Options) (Page, error) {
	p := Page{SchemaVersion: SchemaVersion, RunID: opts.RunID, Basis: "saved_observations", Records: []Record{}}
	if opts.RunID == "" || len(opts.RunID) > 1024 || strings.TrimSpace(opts.RunID) != opts.RunID || strings.ContainsAny(opts.RunID, "\x00\r\n") || opts.Limit < 0 || opts.Limit > 200 {
		return p, ErrInvalid
	}
	p.Limit = opts.Limit
	if p.Limit == 0 {
		p.Limit = 50
	}
	c := cursor{Version: SchemaVersion, RunID: opts.RunID}
	if opts.Cursor != "" {
		if len(opts.Cursor) > 8192 {
			return p, ErrInvalid
		}
		raw, err := base64.RawURLEncoding.DecodeString(opts.Cursor)
		if err != nil || json.Unmarshal(raw, &c) != nil || c.Version != SchemaVersion || c.RunID != opts.RunID ||
			(c.Kind != "object" && c.Kind != "event") || c.ID == "" || len(c.ID) > 1024 {
			return p, ErrInvalid
		}
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT kind,id,object_type,created_at FROM (
		SELECT 'object' AS kind,hash AS id,object_type,created_at FROM provenance_objects
		WHERE run_id=? AND object_type IN ('runtime_capture','execution_checkpoint','agent_context_coverage','context_capture_policy','run_capture_settings')
		UNION ALL SELECT 'event',id,'sentry_stream',created_at FROM events
		WHERE run_id=? AND source='gvisor_seccheck' AND event_type='runtime_collection')
		WHERE (kind,id) > (?,?) ORDER BY kind,id LIMIT ?`, opts.RunID, opts.RunID, c.Kind, c.ID, p.Limit+1)
	if err != nil {
		return p, err
	}
	refs := []evidence{}
	for rows.Next() {
		var e evidence
		if err := rows.Scan(&e.kind, &e.id, &e.objectType, &e.recordedAt); err != nil {
			rows.Close()
			return p, err
		}
		refs = append(refs, e)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return p, err
	}
	p.HasMore = len(refs) > p.Limit
	if p.HasMore {
		refs = refs[:p.Limit]
	}
	for _, e := range refs {
		if err := ctx.Err(); err != nil {
			return p, err
		}
		r, err := s.read(ctx, opts.RunID, e)
		if err != nil {
			return p, fmt.Errorf("capture evidence %s: %w", e.id, err)
		}
		p.Records = append(p.Records, r)
	}
	if p.HasMore {
		last := refs[len(refs)-1]
		raw, err := json.Marshal(cursor{Version: SchemaVersion, RunID: opts.RunID, Kind: last.kind, ID: last.id})
		if err != nil {
			return p, err
		}
		p.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
	}
	return p, nil
}

func initial(e evidence) Record {
	return Record{ID: e.kind + "/" + e.id, EvidenceRef: e.id, EvidenceKind: e.kind,
		Source: e.objectType, ProducerVersion: "unknown", ProducerCommit: "unknown", Placement: "unknown", IdentityDomain: "unknown",
		Identity: map[string]string{}, ObservedAt: e.recordedAt, IntervalBasis: "recorded_observation", Status: "unknown",
		Snapshots: []Snapshot{}, Retention: []Retention{}, Loss: []Counter{}, Issues: []string{}}
}
