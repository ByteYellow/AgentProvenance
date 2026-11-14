package dashboard

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/observability"
	"github.com/byteyellow/agentprovenance/internal/staticdata"
)

const maxReplayRuns = 64

// ReplayRunInventory retains each run's independent coverage and selection.
// Top-level content counts sum these values; they are not unique across runs.
type ReplayRunInventory struct {
	RunID             string                         `json:"run_id"`
	Scope             string                         `json:"scope"`
	Events            int                            `json:"events"`
	Contents          ReplayContents                 `json:"contents"`
	Selection         ReplayFile                     `json:"record_selection"`
	SelectionSummary  ReplaySelectionSummary         `json:"selection_summary"`
	AnalysisOmissions map[string]int                 `json:"analysis_omissions,omitempty"`
	CapturePolicy     *agentcontext.CapturePolicy    `json:"capture_policy,omitempty"`
	CaptureSettings   *observability.CaptureSettings `json:"capture_settings,omitempty"`
}

func normalizeReplaySelections(inputs []ReplaySelection) ([]ReplaySelection, error) {
	if len(inputs) == 0 || len(inputs) > maxReplayRuns {
		return nil, fmt.Errorf("%w: select between 1 and %d runs", agentcontext.ErrInvalidArgument, maxReplayRuns)
	}
	seen := make(map[string]bool, len(inputs))
	result := make([]ReplaySelection, 0, len(inputs))
	for _, input := range inputs {
		selection, err := input.normalized()
		if err != nil {
			return nil, err
		}
		if seen[selection.RunID] {
			return nil, fmt.Errorf("%w: each run must have exactly one selection", agentcontext.ErrInvalidArgument)
		}
		seen[selection.RunID] = true
		result = append(result, selection)
	}
	return result, nil
}

func (c *ReplayContents) add(other ReplayContents) {
	c.Sessions += other.Sessions
	c.ContextEntries += other.ContextEntries
	c.LatestEntries += other.LatestEntries
	c.BodyRefs += other.BodyRefs
	c.RawRefs += other.RawRefs
	for category, count := range other.Sources {
		c.Sources[category] += count
	}
}

func (s Server) prepareReplayRun(ctx context.Context, snapshot *replaySnapshot, input ReplaySelection, visibleRuns []string, w *staticdata.Writer) (ReplayRunInventory, ReplayRun, error) {
	item := ReplayRunInventory{RunID: input.RunID, Scope: input.Scope}
	selection, err := s.resolveReplaySelection(ctx, input)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return item, ReplayRun{}, fmt.Errorf("%w: run or session selection was not found", err)
		}
		return item, ReplayRun{}, err
	}
	data, err := json.Marshal(struct {
		SchemaVersion string                   `json:"schema_version"`
		Selection     ReplaySelection          `json:"selection"`
		Records       []replayRecordDecision   `json:"records"`
		Warnings      []replaySelectionWarning `json:"warnings,omitempty"`
		WarningCount  int                      `json:"warning_count"`
	}{"agentprovenance.replay_selection/v1", selection.Selection, selection.Records, selection.Warnings, selection.WarningCount})
	if err != nil {
		return item, ReplayRun{}, err
	}
	w.Bytes += int64(len(data))
	if w.Bytes > 900<<20 {
		return item, ReplayRun{}, fmt.Errorf("offline replay data and selections exceed 900 MiB; reduce the selected scope")
	}
	name := "record-selection.json"
	if len(visibleRuns) > 1 {
		name = "selections/" + replayDigest([]byte(input.RunID)) + ".json"
	}
	path := filepath.Join(w.Root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return item, ReplayRun{}, err
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return item, ReplayRun{}, err
	}
	item.Selection = ReplayFile{Path: name, SHA256: replayDigest(data), Bytes: int64(len(data))}
	item.SelectionSummary = selection.summary()
	if selection.partial() {
		projection, err := snapshot.projectSelection(ctx, selection)
		if err != nil {
			return item, ReplayRun{}, err
		}
		defer projection.Close()
		s.DB, s.replayProjection = projection.DB, projection
		item.AnalysisOmissions = projection.omitted
	}
	selection = nil
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE run_id=?`, input.RunID).Scan(&item.Events); err != nil {
		return item, ReplayRun{}, err
	}
	replay, err := s.ExportReplaySet(ctx, input.RunID, w, visibleRuns)
	if err != nil {
		return item, replay, err
	}
	item.Contents, err = describeReplay(w.Root, replay)
	if err != nil {
		return item, replay, err
	}
	coverage, err := (agentcontext.Service{DB: s.DB}).Overview(ctx, input.RunID)
	if err != nil {
		return item, replay, err
	}
	item.CapturePolicy, item.CaptureSettings = coverage.CapturePolicy, coverage.CaptureSettings
	return item, replay, ctx.Err()
}
