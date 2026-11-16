package dashboard

import (
	"context"
	"fmt"

	"github.com/byteyellow/agentprovenance/internal/capturemanifest"
	"github.com/byteyellow/agentprovenance/internal/derivedview"
	"github.com/byteyellow/agentprovenance/internal/staticdata"
)

type replayCapturePage struct {
	Count int            `json:"count"`
	First string         `json:"first"`
	Last  string         `json:"last"`
	Data  staticdata.Ref `json:"data"`
}

type replayCaptureIndex struct {
	SchemaVersion string              `json:"schema_version"`
	Scope         string              `json:"scope"`
	Pages         []replayCapturePage `json:"pages"`
	coverage      derivedview.Coverage
}

// Use the same frozen, selected database as the other replay readers. Native
// checkpoints excluded by the projection must not be recovered from the source.
func (s Server) exportCaptureManifest(ctx context.Context, run string, w *staticdata.Writer) (*replayCaptureIndex, error) {
	index := &replayCaptureIndex{SchemaVersion: "agentprovenance.replay_capture_manifest/v1", Scope: "whole_run", Pages: []replayCapturePage{}}
	index.coverage.State = derivedview.CoverageUnknown
	if s.replayProjection != nil && s.replayProjection.plan.partial() {
		index.Scope = "selected_evidence"
	}
	cursor, count := "", 0
	for {
		page, err := (capturemanifest.Service{DB: s.DB}).List(ctx, capturemanifest.Options{RunID: run, Cursor: cursor, Limit: 50})
		if err != nil {
			return nil, err
		}
		count += len(page.Records)
		for _, record := range page.Records {
			switch record.Status {
			case "partial", "incomplete", "degraded", "failed", "error", "unavailable", "truncated":
				index.coverage.State = derivedview.CoverageGaps
				addCaptureDiagnostic(&index.coverage, record.Source, "observation_status_"+record.Status)
			}
			for _, counter := range record.Loss {
				// Collector cumulative counts are not allocated to this run.
				if counter.Scope == "run" && counter.Value != nil && *counter.Value != "0" {
					index.coverage.State = derivedview.CoverageGaps
					addCaptureDiagnostic(&index.coverage, record.Source, "recorded_run_loss")
				}
			}
		}
		if count > replaySelectionLimit {
			return nil, fmt.Errorf("replay capture manifest exceeds %d records; reduce the selected scope", replaySelectionLimit)
		}
		if len(page.Records) > 0 {
			ref, err := w.JSON(page.Records)
			if err != nil {
				return nil, err
			}
			index.Pages = append(index.Pages, replayCapturePage{Count: len(page.Records), First: page.Records[0].ID, Last: page.Records[len(page.Records)-1].ID, Data: ref})
		}
		if !page.HasMore {
			return index, ctx.Err()
		}
		if page.NextCursor == "" || page.NextCursor == cursor {
			return nil, fmt.Errorf("invalid capture manifest continuation")
		}
		cursor = page.NextCursor
	}
}

// Counts here are saved observations, not the number of lost events. Detailed
// counters keep their original scopes in the capture-manifest reader.
func addCaptureDiagnostic(coverage *derivedview.Coverage, category, reason string) {
	for i := range coverage.Gaps {
		if coverage.Gaps[i].Category == category && coverage.Gaps[i].Reason == reason {
			coverage.Gaps[i].Count++
			return
		}
	}
	coverage.Gaps = append(coverage.Gaps, derivedview.Gap{Category: category, Reason: reason, Count: 1})
}
