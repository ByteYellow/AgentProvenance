// Package signals is the unified, graph-attached signal model - the single
// row type that every observability dimension lands on.
//
// AgentProvenance observes sandboxed agent execution along two pillars over one
// causality graph - behavior and quality/security - plus cost as a cross-cutting
// dimension that feeds both. Historically each dimension had its own storage
// silo (risk_signals, baseline_deviations, cost_samples, and a Python-only
// EvalSignal export). This package collapses them into one `signals` table keyed
// to the same graph, so consumers
// (collectors, evaluators, policies, audit) build against one contract instead
// of N silos.
package signals

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/ids"
)

// Dimension is the observability lens a signal belongs to.
type Dimension string

const (
	// Behavior is the factual substrate (what happened, who caused it).
	Behavior Dimension = "behavior"
	// Cost is the cross-cutting resource/economic dimension (not a peer pillar).
	Cost Dimension = "cost"
	// Quality scores task success / reward.
	Quality Dimension = "quality"
	// Security scores safety-policy / baseline deviation.
	Security Dimension = "security"
)

// Valid reports whether d is one of the four known dimensions.
func (d Dimension) Valid() bool {
	switch d {
	case Behavior, Cost, Quality, Security:
		return true
	default:
		return false
	}
}

// SchemaVersion identifies the unified signal wire format. It is the versioned
// contract external collectors, evaluators, policies, and auditors build
// against. Bump it only with a documented migration.
const SchemaVersion = "agentprovenance.signals/v1"

// Signal is one graph-attached observation. The graph reference fields locate
// the node/edge this signal annotates; the scoring fields carry the judgment.
// JSON tags define the stable wire form; keep them and SchemaVersion in sync.
type Signal struct {
	ID                string    `json:"id"`
	Dimension         Dimension `json:"dimension"`
	Type              string    `json:"type"`
	GraphRefKind      string    `json:"graph_ref_kind"`
	GraphRefID        string    `json:"graph_ref_id"`
	RunID             string    `json:"run_id"`
	SessionID         string    `json:"session_id,omitempty"`
	ToolCallID        string    `json:"tool_call_id,omitempty"`
	ProcessID         string    `json:"process_id,omitempty"`
	EventID           string    `json:"event_id,omitempty"`
	ObjectRef         string    `json:"object_ref,omitempty"`
	Severity          string    `json:"severity,omitempty"` // security/risk only
	Label             string    `json:"label,omitempty"`    // categorical tag (e.g. quality pass/reject)
	Value             float64   `json:"value"`
	Reference         string    `json:"reference,omitempty"`
	Confidence        float64   `json:"confidence"`
	RecommendedAction string    `json:"recommended_action,omitempty"`
	ProducedBy        string    `json:"produced_by"`
	EvidenceRefs      string    `json:"evidence_refs"` // JSON array; defaults to "[]"
	Payload           string    `json:"payload"`       // JSON object; defaults to "{}"
	SourceTable       string    `json:"source_table,omitempty"`
	SourceID          string    `json:"source_id,omitempty"`
	CreatedAt         string    `json:"created_at"`
}

// SignalSet is the versioned export envelope for a run's signals - the unit a
// downstream consumer ingests. Counts is the per-dimension breakdown so an RL
// reward shaper or a security reviewer can see the shape at a glance.
type SignalSet struct {
	SchemaVersion string         `json:"schema_version"`
	RunID         string         `json:"run_id"`
	Count         int            `json:"count"`
	Counts        map[string]int `json:"counts"`
	Signals       []Signal       `json:"signals"`
}

// Export returns the versioned signal set for a run (all dimensions).
func Export(db *sql.DB, runID string) (SignalSet, error) {
	sigs, err := Query(db, Filter{RunID: runID})
	if err != nil {
		return SignalSet{}, err
	}
	counts := map[string]int{}
	for _, s := range sigs {
		counts[string(s.Dimension)]++
	}
	if sigs == nil {
		sigs = []Signal{}
	}
	return SignalSet{
		SchemaVersion: SchemaVersion,
		RunID:         runID,
		Count:         len(sigs),
		Counts:        counts,
		Signals:       sigs,
	}, nil
}

// Record validates and persists a single signal. It fills in id, confidence,
// created_at, and JSON defaults when unset. Records projected from a legacy
// silo (SourceTable+SourceID set) are idempotent: re-projecting the same source
// row is a no-op rather than a duplicate.
func Record(db *sql.DB, s Signal) (string, error) {
	id, _, err := record(db, s)
	return id, err
}

// RecordCounting persists a signal and reports whether a new row was inserted
// (false when an idempotent projection/import hit an existing source row).
func RecordCounting(db *sql.DB, s Signal) (bool, error) {
	_, inserted, err := record(db, s)
	return inserted, err
}

func record(db *sql.DB, s Signal) (string, bool, error) {
	if !s.Dimension.Valid() {
		return "", false, fmt.Errorf("signals: invalid dimension %q", s.Dimension)
	}
	if strings.TrimSpace(s.Type) == "" {
		return "", false, fmt.Errorf("signals: empty signal type")
	}
	// Source provenance is all-or-nothing: SourceTable drives the partial unique
	// index (idempotent projection), so a SourceTable with an empty SourceID
	// would make every such row collide on ('table',''). Reject the half-set case.
	if (s.SourceTable == "") != (s.SourceID == "") {
		return "", false, fmt.Errorf("signals: source_table and source_id must both be set or both empty (got table=%q id=%q)", s.SourceTable, s.SourceID)
	}
	if s.ID == "" {
		s.ID = ids.New("sig")
	}
	if s.Confidence <= 0 {
		s.Confidence = 1
	}
	if s.EvidenceRefs == "" {
		s.EvidenceRefs = "[]"
	}
	if s.Payload == "" {
		s.Payload = "{}"
	}
	if s.CreatedAt == "" {
		s.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	// Idempotent upsert keyed on the legacy source row when projecting.
	conflict := ""
	if s.SourceTable != "" {
		// Matches the partial unique index idx_signals_source; the WHERE clause
		// must be echoed so SQLite resolves the partial-index conflict target.
		conflict = " ON CONFLICT(source_table, source_id) WHERE source_table != '' DO NOTHING"
	}
	res, err := db.Exec(`INSERT INTO signals
		(id, dimension, signal_type, graph_ref_kind, graph_ref_id, run_id, session_id, tool_call_id,
		 process_id, event_id, object_ref, severity, label, value, reference, confidence, recommended_action,
		 produced_by, evidence_refs, payload, source_table, source_id, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`+conflict,
		s.ID, string(s.Dimension), s.Type, s.GraphRefKind, s.GraphRefID, s.RunID, s.SessionID, s.ToolCallID,
		s.ProcessID, s.EventID, s.ObjectRef, s.Severity, s.Label, s.Value, s.Reference, s.Confidence, s.RecommendedAction,
		s.ProducedBy, s.EvidenceRefs, s.Payload, s.SourceTable, s.SourceID, s.CreatedAt)
	if err != nil {
		return "", false, fmt.Errorf("signals: record: %w", err)
	}
	affected, _ := res.RowsAffected()
	return s.ID, affected > 0, nil
}

// Filter narrows a Query. Empty fields are ignored.
type Filter struct {
	RunID        string
	Dimension    Dimension
	GraphRefKind string
	GraphRefID   string
	ProcessID    string
}

// Query returns signals matching the filter, newest first.
func Query(db *sql.DB, f Filter) ([]Signal, error) {
	var (
		where []string
		args  []any
	)
	add := func(col, val string) {
		if val != "" {
			where = append(where, col+" = ?")
			args = append(args, val)
		}
	}
	add("run_id", f.RunID)
	add("dimension", string(f.Dimension))
	add("graph_ref_kind", f.GraphRefKind)
	add("graph_ref_id", f.GraphRefID)
	add("process_id", f.ProcessID)

	query := `SELECT id, dimension, signal_type, graph_ref_kind, graph_ref_id, run_id, session_id, tool_call_id,
		process_id, event_id, object_ref, severity, label, value, reference, confidence, recommended_action,
		produced_by, evidence_refs, payload, source_table, source_id, created_at FROM signals`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY created_at DESC, id DESC"

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("signals: query: %w", err)
	}
	defer rows.Close()

	var out []Signal
	for rows.Next() {
		var s Signal
		var dim string
		if err := rows.Scan(&s.ID, &dim, &s.Type, &s.GraphRefKind, &s.GraphRefID, &s.RunID, &s.SessionID, &s.ToolCallID,
			&s.ProcessID, &s.EventID, &s.ObjectRef, &s.Severity, &s.Label, &s.Value, &s.Reference, &s.Confidence, &s.RecommendedAction,
			&s.ProducedBy, &s.EvidenceRefs, &s.Payload, &s.SourceTable, &s.SourceID, &s.CreatedAt); err != nil {
			return nil, fmt.Errorf("signals: scan: %w", err)
		}
		s.Dimension = Dimension(dim)
		out = append(out, s)
	}
	return out, rows.Err()
}

// Counts returns the number of signals per dimension for a run.
func Counts(db *sql.DB, runID string) (map[Dimension]int, error) {
	rows, err := db.Query(`SELECT dimension, COUNT(*) FROM signals WHERE run_id = ? GROUP BY dimension`, runID)
	if err != nil {
		return nil, fmt.Errorf("signals: counts: %w", err)
	}
	defer rows.Close()
	out := map[Dimension]int{}
	for rows.Next() {
		var dim string
		var n int
		if err := rows.Scan(&dim, &n); err != nil {
			return nil, fmt.Errorf("signals: counts scan: %w", err)
		}
		out[Dimension(dim)] = n
	}
	return out, rows.Err()
}
