package dashboard

import (
	"context"
	"fmt"

	"github.com/byteyellow/agentprovenance/internal/capturemanifest"
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
}

// Use the same frozen, selected database as the other replay readers. Native
// checkpoints excluded by the projection must not be recovered from the source.
func (s Server) exportCaptureManifest(ctx context.Context, run string, w *staticdata.Writer) (*replayCaptureIndex, error) {
	index := &replayCaptureIndex{SchemaVersion: "agentprovenance.replay_capture_manifest/v1", Scope: "whole_run", Pages: []replayCapturePage{}}
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
