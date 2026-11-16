package provenance

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/browserlink"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

// BuildGraphLensWithBrowserCustody adds only independently authorized runtime
// mappings. The default query never grants custody from imported object JSON.
func BuildGraphLensWithBrowserCustody(db *sql.DB, opts GraphLensOptions, custody []browserlink.RuntimeCustody) (GraphLensManifest, error) {
	return buildGraphLensWithBrowserCustody(db, opts, custody)
}

func addBrowserLens(db *sql.DB, runID string, scope *GraphSessionScope, nodes map[string]GraphLensNode, events map[string]lensEvent, edges []GraphLensEdge, custody []browserlink.RuntimeCustody) ([]GraphLensEdge, error) {
	// Match agentcontext's latestEntry ordering before applying scope/budgets.
	// Updated manifest pins create revisions, not competing native events.
	query := `SELECT e.object_hash FROM (
		SELECT object_hash, parser_version, source_id, session_id,
		ROW_NUMBER() OVER (PARTITION BY source_id, source_key, kind
		ORDER BY source_sequence DESC, source_ordinal DESC, created_at DESC, id DESC) AS browser_revision_rank
		FROM agent_context_entries WHERE run_id = ?
	) e WHERE e.browser_revision_rank = 1 AND e.parser_version = 'chromium-cdp/v1'`
	args := []any{runID}
	if scope != nil {
		var clauses []string
		if scope.Harness == "browser" && scope.SessionID != "" {
			clauses = append(clauses, "e.session_id = ?")
			args = append(args, scope.SessionID)
		}
		if len(scope.SourceIDs) > browserlink.MaxRecords {
			return nil, fmt.Errorf("browser session source limit exceeded")
		}
		if len(scope.SourceIDs) > 0 {
			clauses = append(clauses, "e.source_id IN ("+strings.TrimSuffix(strings.Repeat("?,", len(scope.SourceIDs)), ",")+")")
			for _, id := range scope.SourceIDs {
				args = append(args, id)
			}
		}
		if len(clauses) == 0 {
			return edges, nil
		}
		query += " AND (" + strings.Join(clauses, " OR ") + ")"
	}
	query += " ORDER BY e.object_hash LIMIT ?"
	args = append(args, browserlink.MaxRecords+1)
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	var refs []string
	for rows.Next() {
		var ref string
		if err := rows.Scan(&ref); err != nil {
			rows.Close()
			return nil, err
		}
		refs = append(refs, ref)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(refs) == 0 {
		return edges, nil
	}
	if len(refs) > browserlink.MaxRecords {
		return nil, fmt.Errorf("browser graph record limit exceeded")
	}
	input := browserlink.Input{RunID: runID, Custody: custody}
	total := 0
	for _, ref := range refs {
		var raw json.RawMessage
		if err := ReadObjectPayload(db, runID, ref, &raw); err != nil {
			return nil, fmt.Errorf("browser graph object %s: %w", ref, err)
		}
		total += len(raw)
		if total > browserlink.MaxInputBytes {
			return nil, fmt.Errorf("browser graph byte limit exceeded")
		}
		input.Records = append(input.Records, browserlink.Record{Ref: ref, Payload: raw})
	}
	if len(custody) > 0 {
		for _, ev := range events {
			input.Events = append(input.Events, telemetry.EventRecord{ID: ev.ID, RunID: runID, Source: ev.Source, EventType: ev.Type,
				PID: ev.PID, PPID: ev.PPID, TGID: ev.TGID, Payload: ev.Payload})
		}
	}
	projection, err := browserlink.Project(context.Background(), input)
	if err != nil {
		return nil, err
	}
	for _, n := range projection.Nodes {
		nodes[n.ID] = GraphLensNode{ID: n.ID, Kind: n.Kind, Label: n.Label, TrustOrigin: "application_observed", Data: n.Data}
	}
	for _, issue := range projection.Issues {
		n, exists := nodes[issue.NodeID]
		if !exists {
			continue
		}
		if n.Data == nil {
			n.Data = map[string]any{}
		}
		issues, _ := n.Data["browser_link_issues"].([]browserlink.Issue)
		n.Data["browser_link_issues"] = append(issues, issue)
		nodes[n.ID] = n
	}
	for _, relation := range projection.Relations {
		edges = append(edges, GraphLensEdge{ID: relation.ID, FromID: relation.From, ToID: relation.To, EdgeType: relation.Kind,
			Derived: true, DerivationRule: relation.Rule, EvidenceRefs: relation.SourceRefs, SourceEventID: relation.SourceEventID,
			Data: map[string]any{"scope": relation.Scope, "basis": relation.Basis, "status": relation.Status,
				"evidence_grade": relation.EvidenceGrade, "source_refs": relation.SourceRefs}})
	}
	return edges, nil
}
