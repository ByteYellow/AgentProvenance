package agentcontext

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

var ErrInvalidArgument = errors.New("invalid context argument")

const latestEntry = `NOT EXISTS (SELECT 1 FROM agent_context_entries newer
	WHERE newer.run_id = e.run_id AND newer.source_id = e.source_id
	AND newer.source_key = e.source_key AND newer.kind = e.kind
	AND (newer.source_sequence > e.source_sequence OR
	(newer.source_sequence = e.source_sequence AND (newer.created_at > e.created_at OR
	(newer.created_at = e.created_at AND newer.id > e.id)))))`

type pageCursor struct {
	Query    string `json:"query"`
	Source   string `json:"source"`
	Sequence int64  `json:"sequence"`
	ID       string `json:"id"`
}

func (s Service) Entries(ctx context.Context, opts PageOptions) (Page, error) {
	if opts.RunID == "" {
		return Page{}, fmt.Errorf("%w: run id is required", ErrInvalidArgument)
	}
	if opts.Limit <= 0 {
		opts.Limit = 50
	}
	if opts.Limit > 200 {
		return Page{}, fmt.Errorf("%w: page limit must not exceed 200", ErrInvalidArgument)
	}
	where := []string{"e.run_id = ?"}
	args := []any{opts.RunID}
	for _, filter := range []struct{ column, value string }{
		{"session_id", opts.SessionID}, {"source_id", opts.SourceID},
		{"kind", opts.Kind}, {"tool_call_id", opts.ToolCallID},
	} {
		if filter.value != "" {
			where = append(where, "e."+filter.column+" = ?")
			args = append(args, filter.value)
		}
	}
	if !opts.IncludeRevisions {
		where = append(where, latestEntry)
	}
	queryOpts := opts
	queryOpts.Cursor, queryOpts.Limit = "", 0
	fingerprint := digest(queryOpts)
	if opts.Cursor != "" {
		if len(opts.Cursor) > 8192 {
			return Page{}, fmt.Errorf("%w: cursor is too long", ErrInvalidArgument)
		}
		raw, err := base64.RawURLEncoding.DecodeString(opts.Cursor)
		var cursor pageCursor
		if err != nil || len(raw) > 4096 || json.Unmarshal(raw, &cursor) != nil || cursor.Query != fingerprint {
			return Page{}, fmt.Errorf("%w: cursor does not match this query", ErrInvalidArgument)
		}
		where = append(where, `(e.source_id > ? OR (e.source_id = ? AND e.source_sequence > ?)
			OR (e.source_id = ? AND e.source_sequence = ? AND e.id > ?))`)
		args = append(args, cursor.Source, cursor.Source, cursor.Sequence, cursor.Source, cursor.Sequence, cursor.ID)
	}
	args = append(args, opts.Limit+1)
	rows, err := s.DB.QueryContext(ctx, `SELECT e.id, e.object_hash, e.created_at FROM agent_context_entries e
		WHERE `+strings.Join(where, " AND ")+` ORDER BY e.source_id, e.source_sequence, e.id LIMIT ?`, args...)
	if err != nil {
		return Page{}, err
	}
	type ref struct{ id, hash, created string }
	refs := []ref{}
	for rows.Next() {
		var r ref
		if err := rows.Scan(&r.id, &r.hash, &r.created); err != nil {
			rows.Close()
			return Page{}, err
		}
		refs = append(refs, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return Page{}, err
	}
	page := Page{SchemaVersion: SchemaVersion, RunID: opts.RunID, Entries: []Entry{}, Limit: opts.Limit}
	if len(refs) > opts.Limit {
		page.HasMore = true
		refs = refs[:opts.Limit]
	}
	for _, r := range refs {
		var e Entry
		if err := provenance.ReadObjectPayload(s.DB, opts.RunID, r.hash, &e); err != nil {
			return Page{}, fmt.Errorf("context entry %s: %w", r.id, err)
		}
		if e.ID != r.id || e.RunID != opts.RunID || e.SchemaVersion != SchemaVersion {
			return Page{}, fmt.Errorf("context entry identity mismatch")
		}
		e.ObjectHash, e.CreatedAt = r.hash, r.created
		page.Entries = append(page.Entries, e)
	}
	if page.HasMore {
		last := page.Entries[len(page.Entries)-1]
		raw, err := json.Marshal(pageCursor{Query: fingerprint, Source: last.Source.ID, Sequence: last.Sequence, ID: last.ID})
		if err != nil {
			return Page{}, err
		}
		page.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
	}
	return page, nil
}

func (s Service) Overview(ctx context.Context, runID string) (Overview, error) {
	if runID == "" {
		return Overview{}, fmt.Errorf("run id is required")
	}
	result := Overview{SchemaVersion: SchemaVersion, RunID: runID, Coverage: []Coverage{}}
	rows, err := s.DB.QueryContext(ctx, `SELECT r.object_hash FROM agent_context_reports r
		WHERE r.run_id = ? AND NOT EXISTS (SELECT 1 FROM agent_context_reports n
		WHERE n.run_id = r.run_id AND n.source_id = r.source_id
		AND (n.created_at > r.created_at OR (n.created_at = r.created_at AND n.id > r.id)))
		ORDER BY r.source_id LIMIT 257`, runID)
	if err != nil {
		return result, err
	}
	refs := []string{}
	for rows.Next() {
		var ref string
		if err := rows.Scan(&ref); err != nil {
			rows.Close()
			return result, err
		}
		refs = append(refs, ref)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	if len(refs) == 0 {
		result.Coverage = append(result.Coverage, Coverage{
			SchemaVersion: SchemaVersion, RunID: runID, Status: LegacyNotRecorded,
			Source: Source{Harness: "unknown", Binding: "unknown"},
			Issues: []Issue{{Code: "legacy_not_recorded"}}, MissingFields: []string{"agent_log_coverage"},
		})
		return result, nil
	}
	if len(refs) > 256 {
		result.HasMoreSources = true
		refs = refs[:256]
	}
	for _, ref := range refs {
		var c Coverage
		if err := provenance.ReadObjectPayload(s.DB, runID, ref, &c); err != nil {
			return result, err
		}
		c.ObjectHash = ref
		result.Coverage = append(result.Coverage, c)
	}
	var messages, tools, results, snapshots int64
	err = s.DB.QueryRowContext(ctx, `SELECT
		COALESCE(SUM(kind = 'message'),0), COALESCE(SUM(kind = 'tool_call'),0),
		COALESCE(SUM(kind = 'tool_result'),0), COALESCE(SUM(kind IN ('configuration','approval')),0)
		FROM agent_context_entries e WHERE e.run_id = ? AND `+latestEntry, runID).
		Scan(&messages, &tools, &results, &snapshots)
	if err != nil {
		return result, err
	}
	result.Messages, result.ToolCalls, result.ToolResults, result.Snapshots = &messages, &tools, &results, &snapshots
	return result, nil
}
