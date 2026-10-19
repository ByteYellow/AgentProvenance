package agentcontext

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

// SessionGraphScope selects existing tool and event links. A shared process,
// working directory or cgroup never expands the session's event membership.
func (s Service) SessionGraphScope(ctx context.Context, run, harness, session string) (*provenance.GraphSessionScope, error) {
	if run == "" || harness == "" || session == "" || len(harness) > 128 || len(session) > 512 {
		return nil, fmt.Errorf("%w: run, harness and session are required", ErrInvalidArgument)
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT r.source_id, r.object_hash FROM agent_context_reports r
		WHERE r.run_id=? AND r.harness=? AND r.session_id=? AND NOT EXISTS (
		 SELECT 1 FROM agent_context_reports n WHERE n.run_id=r.run_id AND n.source_id=r.source_id
		 AND (n.created_at, n.id) > (r.created_at, r.id)) ORDER BY r.source_id LIMIT 257`, run, harness, session)
	if err != nil {
		return nil, err
	}
	type ref struct{ id, hash string }
	refs := []ref{}
	for rows.Next() {
		var r ref
		if err := rows.Scan(&r.id, &r.hash); err != nil {
			rows.Close()
			return nil, err
		}
		refs = append(refs, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(refs) > 256 {
		return nil, fmt.Errorf("%w: session source limit exceeded", ErrInvalidArgument)
	}
	scope := &provenance.GraphSessionScope{Harness: harness, SessionID: session, SourceIDs: []string{}, ToolIDs: []string{}, EventIDs: []string{}}
	for _, r := range refs {
		var c Coverage
		if err := provenance.ReadObjectPayload(s.DB, run, r.hash, &c); err != nil {
			return nil, err
		}
		if c.RunID != run || c.Source.ID != r.id || c.Source.Harness != harness || c.Source.SessionID != session {
			return nil, fmt.Errorf("session source identity mismatch")
		}
		if harness == "unknown" || harness == "launch" || c.Source.Channel == "processing" || c.Source.Channel == "discovery" || c.Source.Channel == "runtime_correlation" {
			continue
		}
		scope.SourceIDs = append(scope.SourceIDs, r.id)
	}
	if len(scope.SourceIDs) == 0 {
		return nil, sql.ErrNoRows
	}
	sources, _ := json.Marshal(scope.SourceIDs)
	rows, err = s.DB.QueryContext(ctx, `SELECT DISTINCT e.id, e.object_hash FROM agent_context_entries e
		JOIN graph_edges g ON g.run_id=e.run_id AND g.from_id=e.object_hash
		 AND g.edge_type IN ('context_tool_call','context_tool_result')
		WHERE e.run_id=? AND e.source_id IN (SELECT value FROM json_each(?)) AND `+latestEntry+`
		ORDER BY e.id LIMIT 10001`, run, string(sources))
	if err != nil {
		return nil, err
	}
	refs = nil
	for rows.Next() {
		var r ref
		if err := rows.Scan(&r.id, &r.hash); err != nil {
			rows.Close()
			return nil, err
		}
		refs = append(refs, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(refs) > 10000 {
		return nil, fmt.Errorf("%w: session tool-record limit exceeded", ErrInvalidArgument)
	}
	// Check the immutable record's identity and execution range before using its
	// graph projection. Prior transcript history is not execution in this run.
	hashes := []string{}
	for _, r := range refs {
		var e Entry
		if err := provenance.ReadObjectPayload(s.DB, run, r.hash, &e); err != nil {
			return nil, err
		}
		if e.ID != r.id || e.RunID != run || e.SchemaVersion != SchemaVersion || e.Source.Harness != harness || e.Source.SessionID != session {
			return nil, fmt.Errorf("session entry identity mismatch")
		}
		if e.ExecutionScope != PriorContext && (e.Kind == "tool_call" || e.Kind == "tool_result") {
			hashes = append(hashes, r.hash)
		}
	}
	encoded, _ := json.Marshal(hashes)
	rows, err = s.DB.QueryContext(ctx, `SELECT DISTINCT g.to_id FROM graph_edges g
		JOIN tool_calls t ON t.run_id=g.run_id AND t.id=g.to_id
		WHERE g.run_id=? AND g.from_id IN (SELECT value FROM json_each(?))
		AND g.edge_type IN ('context_tool_call','context_tool_result') ORDER BY g.to_id`, run, string(encoded))
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		scope.ToolIDs = append(scope.ToolIDs, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	encoded, _ = json.Marshal(scope.ToolIDs)
	rows, err = s.DB.QueryContext(ctx, `SELECT DISTINCT e.id FROM graph_edges g
		JOIN events e ON e.run_id=g.run_id AND g.to_id='runtime_event/' || e.id
		WHERE g.run_id=? AND g.from_id IN (SELECT value FROM json_each(?))
		AND g.edge_type IN ('agent_syscall','runtime_tool_call_event') ORDER BY e.id`, run, string(encoded))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		scope.EventIDs = append(scope.EventIDs, id)
	}
	sort.Strings(scope.SourceIDs)
	return scope, rows.Err()
}
