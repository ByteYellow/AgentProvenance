package dashboard

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

const sessionAuditRule = "agentprov.session_audit_operation/v1"

// Resolve against the complete source before intersecting a sharing selection.
// Excluding a rival or a tool must never create a new Session association.
func (s Server) sessionGraphScope(ctx context.Context, run, harness, session string) (*provenance.GraphSessionScope, error) {
	source := s.DB
	if s.replayProjection != nil {
		source = s.replayProjection.auditSource
		if source == nil {
			return nil, fmt.Errorf("original session audit evidence unavailable")
		}
	}
	scope, err := (agentcontext.Service{DB: source}).SessionGraphScope(ctx, run, harness, session)
	if err != nil {
		return nil, err
	}
	if err := addSessionAudit(ctx, source, run, scope); err != nil {
		return nil, err
	}
	if p := s.replayProjection; p != nil {
		selected, err := (agentcontext.Service{DB: s.DB}).SessionGraphScope(ctx, run, harness, session)
		if err != nil {
			return nil, err
		}
		admitted := map[string]bool{}
		for _, r := range p.plan.Records {
			if r.Included {
				admitted[r.Node] = true
			}
		}
		selected.Audit = scope.Audit
		selected.AuditEvents = map[string]provenance.SessionAuditRelation{}
		for id, relation := range scope.AuditEvents {
			if !admitted["runtime_event/"+id] {
				continue
			}
			for _, ref := range relation.EvidenceRefs {
				if !admitted[ref] {
					relation.Status, relation.Reason = "unavailable", "replay_evidence_excluded"
					relation.EvidenceRefs = nil
					selected.Audit.Status = "incomplete"
					selected.Audit.Issues = appendUniqueAuditIssue(selected.Audit.Issues, relation.Reason)
					break
				}
			}
			selected.AuditEvents[id] = relation
			selected.EventIDs = append(selected.EventIDs, id)
		}
		scope = selected
	}
	scope.EventIDs = sortedReplayStrings(scope.EventIDs)
	if scope.Audit != nil {
		scope.Audit.RelatedCount = len(scope.AuditEvents)
	}
	return scope, nil
}

func addSessionAudit(ctx context.Context, db *sql.DB, run string, scope *provenance.GraphSessionScope) error {
	if len(scope.EventIDs) == 0 {
		return nil
	}
	events := map[string]bool{}
	tools := map[string]bool{}
	for _, id := range scope.ToolIDs {
		tools[id] = true
	}
	for _, id := range scope.EventIDs {
		events["runtime_event/"+id] = true
	}
	for cursor := ""; ; {
		page, err := telemetry.BuildAuditAssociations(ctx, db, telemetry.AuditAssociationOptions{RunID: run, Limit: 500, Cursor: cursor})
		if err != nil {
			return err
		}
		if len(page.Items) > 0 && scope.Audit == nil {
			scope.Audit = &provenance.SessionAuditScope{Status: "complete", Rule: sessionAuditRule}
			scope.AuditEvents = map[string]provenance.SessionAuditRelation{}
		}
		if page.Status != "complete" && scope.Audit != nil {
			scope.Audit.Status = "incomplete"
			for _, issue := range page.Issues {
				scope.Audit.Issues = appendUniqueAuditIssue(scope.Audit.Issues, issue)
			}
		}
		candidates := map[string]provenance.SessionAuditRelation{}
		operationRefs := map[string][]string{}
		var refs []string
		for _, item := range page.Items {
			relation, operations, ok := sessionAuditCandidate(item, events)
			if !ok {
				continue
			}
			candidates[item.EventID], operationRefs[item.EventID] = relation, operations
			refs = append(refs, operations...)
		}
		links, err := auditOperationTools(ctx, db, run, sortedReplayStrings(refs))
		if err != nil {
			return err
		}
		for id, relation := range candidates {
			conflict := false
			for _, ref := range operationRefs[id] {
				for _, tool := range links[ref] {
					if !tools[tool] {
						conflict = true
					}
					relation.EvidenceRefs = append(relation.EvidenceRefs, tool)
				}
			}
			if !conflict {
				relation.EvidenceRefs = sortedReplayStrings(relation.EvidenceRefs)
				scope.AuditEvents[id] = relation
				scope.EventIDs = append(scope.EventIDs, id)
			}
		}
		if !page.HasMore {
			return nil
		}
		cursor = page.NextCursor
	}
}

func sessionAuditCandidate(item telemetry.AuditAssociationItem, events map[string]bool) (provenance.SessionAuditRelation, []string, bool) {
	r := provenance.SessionAuditRelation{Status: "inferred", Rule: sessionAuditRule, Basis: "recorded_tool_runtime_and_unique_audit_operation"}
	for _, a := range []telemetry.AuditAssociation{item.Process, item.Operation} {
		if a.Status != "inferred" || a.CandidateCount != 1 || a.CandidatesTruncated || len(a.Candidates) != 1 {
			return r, nil, false
		}
		r.EvidenceRefs = append(r.EvidenceRefs, a.Candidates[0].EvidenceRefs...)
	}
	if len(item.Operations) != 1 {
		return r, nil, false
	}
	op := item.Operations[0]
	if op.ID != item.Operation.Candidates[0].ID || op.ProcessInstance != item.Process.Candidates[0].ID || op.RefsTruncated || op.AttemptState == "conflicting" || op.ResultState == "conflicting" {
		return r, nil, false
	}
	refs := append(slices.Clone(op.AttemptRefs), op.ResultRefs...)
	anchored := false
	for _, ref := range refs {
		anchored = anchored || events[ref]
	}
	if !anchored {
		return r, nil, false
	}
	r.EvidenceRefs = append(r.EvidenceRefs, "runtime_event/"+item.EventID)
	r.EvidenceRefs = append(r.EvidenceRefs, refs...)
	return r, refs, true
}

// Query all observed operation records together, including late graph links.
// Runtime session_id is an execution scope, not a native harness Session ID.
func auditOperationTools(ctx context.Context, db *sql.DB, run string, refs []string) (map[string][]string, error) {
	links := map[string][]string{}
	if len(refs) == 0 {
		return links, nil
	}
	ids := make([]string, 0, len(refs))
	for _, ref := range refs {
		ids = append(ids, strings.TrimPrefix(ref, "runtime_event/"))
	}
	encoded, err := json.Marshal(ids)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `SELECT e.id, g.from_id FROM events e JOIN graph_edges g
		ON g.run_id=e.run_id AND g.to_id='runtime_event/'||e.id AND g.edge_type IN ('agent_syscall','runtime_tool_call_event')
		WHERE e.run_id=? AND e.id IN (SELECT value FROM json_each(?))
		UNION SELECT id, tool_call_id FROM events WHERE run_id=? AND id IN (SELECT value FROM json_each(?))
		AND COALESCE(tool_call_id,'')!='' ORDER BY 1,2 LIMIT 10001`, run, string(encoded), run, string(encoded))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		if count > 10000 {
			return nil, fmt.Errorf("session audit tool-link limit exceeded")
		}
		var id, tool string
		if err := rows.Scan(&id, &tool); err != nil {
			return nil, err
		}
		links["runtime_event/"+id] = append(links["runtime_event/"+id], tool)
	}
	return links, rows.Err()
}
