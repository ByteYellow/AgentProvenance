package dashboard

import (
	"context"
	"fmt"
	"net/http"

	"github.com/byteyellow/agentprovenance/internal/staticdata"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func (s Server) auditAssociations(w http.ResponseWriter, r *http.Request) {
	if s.replayProjection != nil {
		// A projected DB has lost excluded competing candidates. Export uses the
		// original frozen source below; never re-infer from this smaller store.
		http.Error(w, "use the frozen replay audit reader", http.StatusServiceUnavailable)
		return
	}
	telemetry.AuditAssociationsHandler(s.DB).ServeHTTP(w, r)
}

type replayAuditIndex struct {
	SchemaVersion string            `json:"schema_version"`
	Pages         []replayAuditPage `json:"pages"`
}

type replayAuditPage struct {
	First string         `json:"first"`
	Last  string         `json:"last"`
	Data  staticdata.Ref `json:"data"`
}

func (s Server) exportReplayAudit(ctx context.Context, run string, w *staticdata.Writer) (*replayAuditIndex, error) {
	index := &replayAuditIndex{SchemaVersion: "agentprovenance.replay_audit/v1", Pages: []replayAuditPage{}}
	source := s.DB
	var admitted map[string]bool
	if p := s.replayProjection; p != nil {
		source = p.auditSource
		if source == nil {
			return nil, fmt.Errorf("original audit evidence snapshot unavailable")
		}
		admitted = map[string]bool{}
		for _, record := range p.plan.Records {
			if record.Included {
				admitted[record.ID] = true
			}
		}
	}
	cursor := ""
	for {
		report, err := telemetry.BuildAuditAssociations(ctx, source, telemetry.AuditAssociationOptions{RunID: run, Limit: 100, Cursor: cursor})
		if err != nil {
			return nil, err
		}
		next := report.NextCursor
		// Shards retain the original page's bounded-analysis diagnostics. Browser
		// pagination is over selected IDs only, so cursors cannot expose exclusions.
		report.AnalysisScope, report.NextCursor, report.HasMore = "export_pages", "", false
		selected := make([]telemetry.AuditAssociationItem, 0, len(report.Items))
		for _, item := range report.Items {
			if admitted != nil && !admitted["3/"+item.EventID] {
				continue
			}
			if admitted != nil {
				var withheld bool
				item, withheld = projectAuditItem(item, admitted)
				if withheld {
					report.Status = "incomplete"
					report.Issues = appendUniqueAuditIssue(report.Issues, "replay_evidence_excluded")
				}
			}
			selected = append(selected, item)
		}
		report.Items = selected
		if len(selected) > 0 {
			ref, err := w.JSON(report)
			if err != nil {
				return nil, err
			}
			index.Pages = append(index.Pages, replayAuditPage{First: selected[0].EventID, Last: selected[len(selected)-1].EventID, Data: ref})
		}
		if next == "" {
			return index, nil
		}
		cursor = next
	}
}

func appendUniqueAuditIssue(issues []string, issue string) []string {
	for _, existing := range issues {
		if existing == issue {
			return issues
		}
	}
	return append(issues, issue)
}

// Preserve the frozen ambiguity only when all cited support is shared. If a
// dependency is withheld, omit the inference as a whole, not individual rivals.
func projectAuditItem(item telemetry.AuditAssociationItem, admitted map[string]bool) (telemetry.AuditAssociationItem, bool) {
	refsIncluded := func(refs []string) bool {
		for _, ref := range refs {
			const prefix = "runtime_event/"
			if len(ref) <= len(prefix) || ref[:len(prefix)] != prefix || !admitted["3/"+ref[len(prefix):]] {
				return false
			}
		}
		return true
	}
	available := refsIncluded(item.ProcessExits)
	for _, association := range []telemetry.AuditAssociation{item.Process, item.Operation} {
		if association.CandidatesTruncated {
			available = false
		}
		for _, candidate := range association.Candidates {
			available = available && refsIncluded(candidate.EvidenceRefs)
		}
	}
	for _, op := range item.Operations {
		available = available && !op.RefsTruncated && refsIncluded(op.AttemptRefs) && refsIncluded(op.ResultRefs)
	}
	item.EvidenceScope = "selected_records_only"
	if !available {
		item.Process = telemetry.AuditAssociation{Status: "unassociated", Reason: "replay_evidence_excluded"}
		item.Operation = item.Process
		item.Operations, item.ProcessExits, item.TimeWindow = nil, nil, nil
		return item, true
	}
	for i := range item.Operations {
		op := &item.Operations[i]
		var kept []telemetry.AuditContextRef
		for _, ref := range op.Context {
			if admitted["3/"+ref.EventID] && (ref.ToolCallID == "" || admitted["2/"+ref.ToolCallID]) {
				kept = append(kept, ref)
			}
		}
		op.Context = kept
	}
	return item, false
}
