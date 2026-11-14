package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/handoff"
	"github.com/byteyellow/agentprovenance/internal/staticdata"
)

const replayExecutionSchema = "agentprovenance.replay_execution_links/v1"

type replayExecutionShard struct {
	Count int            `json:"count"`
	Data  staticdata.Ref `json:"data"`
}

type replayExecutionIndex struct {
	SchemaVersion string                            `json:"schema_version"`
	Directions    map[string][]replayExecutionShard `json:"directions"`
}

// Keep only exclusion metadata after each run is projected. Full context bodies
// and selection plans can be released before indexing the next run.
type replayExecutionSelection struct {
	Selection   ReplaySelection
	DeniedCalls map[string]bool
}

func nativeExecutionCallKey(harness, session, call string) string {
	raw, _ := json.Marshal([]string{harness, session, call})
	return string(raw)
}

func executionSelection(plan *replaySelectionPlan) replayExecutionSelection {
	result := replayExecutionSelection{Selection: plan.Selection, DeniedCalls: map[string]bool{}}
	for _, record := range plan.Records {
		if record.Included || record.Category != "tools" {
			continue
		}
		if entry, ok := plan.Entries[strings.TrimPrefix(record.ID, "entry/")]; ok && entry.ToolCallID != "" {
			result.DeniedCalls[nativeExecutionCallKey(entry.Source.Harness, entry.Source.SessionID, entry.ToolCallID)] = true
		}
	}
	return result
}

func (s replayExecutionSelection) includesSource(src handoff.Source) bool {
	return s.Selection.RunID == src.RunID && !slices.Contains(s.Selection.ExcludeCategories, "tools") &&
		(s.Selection.Scope == "whole_run" || (s.Selection.Harness == src.Harness && s.Selection.SessionID == src.SessionID)) &&
		!s.DeniedCalls[nativeExecutionCallKey(src.Harness, src.SessionID, src.ToolCallID)]
}

func projectReplayExecution(link handoff.ExecutionLink, direction string, selections map[string]replayExecutionSelection) (handoff.ExecutionLink, bool) {
	link.Issues = slices.Clone(link.Issues)
	source, sourceSelected := selections[link.Identity.Source.RunID]
	sourceIncluded := sourceSelected && source.includesSource(link.Identity.Source)
	execution, executionSelected := selections[link.Identity.LocalRunID]
	if direction == "outgoing" && !sourceIncluded {
		return handoff.ExecutionLink{}, false
	}
	if !executionSelected {
		link.DeliveryRef, link.Manifest, link.Receipt, link.Checkpoint = "", nil, nil, nil
		link.Basis, link.Issues = "authenticated_admission", []string{"execution_run_not_selected"}
		return link, true
	}
	if !sourceIncluded {
		link.Admission = nil
		link.Basis = "unanchored_delivery"
		reason := "source_run_not_selected"
		if sourceSelected {
			reason = "source_call_excluded_by_selection"
		}
		if !slices.Contains(link.Issues, reason) {
			link.Issues = append(link.Issues, reason)
		}
	}
	if link.Checkpoint != nil && (&replaySelectionPlan{Selection: execution.Selection}).partial() {
		// A checkpoint embeds command/output/artifact metadata. Keep the original
		// hash as a boundary; never rewrite or copy it around record exclusions.
		link.Checkpoint = nil
		link.Issues = append(link.Issues, "checkpoint_excluded_by_selection")
	}
	return link, true
}

func (s Server) exportExecutionLinks(ctx context.Context, run string, w *staticdata.Writer, selections map[string]replayExecutionSelection) (*replayExecutionIndex, error) {
	index := &replayExecutionIndex{SchemaVersion: replayExecutionSchema, Directions: map[string][]replayExecutionShard{}}
	for _, direction := range []string{"outgoing", "incoming"} {
		index.Directions[direction] = []replayExecutionShard{}
		cursor, count := "", 0
		for {
			page, err := (handoff.EvidenceService{DB: s.DB}).Links(ctx, handoff.ExecutionLinksOptions{RunID: run, Direction: direction, Limit: 50, Cursor: cursor})
			if err != nil {
				return nil, err
			}
			count += page.Scanned
			if count > replaySelectionLimit {
				return nil, fmt.Errorf("replay execution links exceed %d records; reduce the selected scope", replaySelectionLimit)
			}
			links := make([]handoff.ExecutionLink, 0, len(page.Links))
			for _, link := range page.Links {
				if selected, included := projectReplayExecution(link, direction, selections); included {
					links = append(links, selected)
				}
			}
			if len(links) > 0 {
				ref, err := w.JSON(links)
				if err != nil {
					return nil, err
				}
				index.Directions[direction] = append(index.Directions[direction], replayExecutionShard{Count: len(links), Data: ref})
			}
			if !page.HasMore {
				break
			}
			if page.NextCursor == "" || page.NextCursor == cursor {
				return nil, fmt.Errorf("invalid execution link continuation")
			}
			cursor = page.NextCursor
		}
	}
	return index, ctx.Err()
}
