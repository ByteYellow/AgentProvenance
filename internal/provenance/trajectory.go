package provenance

import (
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/byteyellow/agentprovenance/internal/i18n"
)

type TrajectoryManifest struct {
	SchemaVersion string               `json:"schema_version"`
	RunID         string               `json:"run_id"`
	DecisionOwner string               `json:"decision_owner"`
	Rollouts      []TrajectoryRollout  `json:"rollouts"`
	Trajectories  []TrajectoryEvidence `json:"trajectories"`
}

type TrajectoryRollout struct {
	ID             string          `json:"id"`
	BaseSnapshotID string          `json:"base_snapshot_id"`
	Status         string          `json:"status"`
	LocalCandidate string          `json:"local_candidate,omitempty"`
	PromotionID    string          `json:"promotion_id,omitempty"`
	RiskStatus     string          `json:"risk_status"`
	BaseSnapshot   *ReplaySnapshot `json:"base_snapshot,omitempty"`
}

type TrajectoryEvidence struct {
	RunID                  string                 `json:"run_id"`
	RolloutID              string                 `json:"rollout_id"`
	AttemptID              string                 `json:"attempt_id"`
	SnapshotID             string                 `json:"snapshot_id"`
	ToolCallID             string                 `json:"tool_call_id,omitempty"`
	Workspace              string                 `json:"workspace"`
	Strategy               string                 `json:"strategy"`
	Command                string                 `json:"command"`
	Status                 string                 `json:"status"`
	RiskStatus             string                 `json:"risk_status"`
	LocalCandidateEligible bool                   `json:"local_candidate_eligible"`
	ReplayBlocked          bool                   `json:"replay_blocked"`
	BlockReasons           []string               `json:"block_reasons,omitempty"`
	Score                  float64                `json:"score"`
	CostEstimate           float64                `json:"cost_estimate"`
	ArtifactResult         string                 `json:"artifact_result,omitempty"`
	ArtifactDigest         *ReplayArtifactDigest  `json:"artifact_digest,omitempty"`
	ToolCall               *ReplayToolCall        `json:"tool_call,omitempty"`
	Processes              []ReplayProcess        `json:"processes,omitempty"`
	RuntimeEvents          []ReplayEvent          `json:"runtime_events,omitempty"`
	ExternalEffects        []ReplayExternalEffect `json:"external_effects,omitempty"`
	FileChanges            []TrajectoryFileChange `json:"file_changes,omitempty"`
	FileChangeSummary      FileChangeSummary      `json:"file_change_summary"`
	FileChangeSource       string                 `json:"file_change_source,omitempty"`
	FileCaptureState       string                 `json:"file_capture_state,omitempty"`
}

type TrajectoryFileChange struct {
	Path         string   `json:"path"`
	ChangeType   string   `json:"change_type"`
	BaseExists   bool     `json:"base_exists"`
	NextExists   bool     `json:"next_exists"`
	BaseSHA256   string   `json:"base_sha256"`
	NextSHA256   string   `json:"next_sha256"`
	BaseBytes    int64    `json:"base_bytes"`
	NextBytes    int64    `json:"next_bytes"`
	UnifiedDiff  []string `json:"unified_diff,omitempty"`
	ContentState string   `json:"content_state,omitempty"`
	PatchState   string   `json:"patch_state,omitempty"`
	EvidenceRef  string   `json:"evidence_ref,omitempty"`
	ContentRef   string   `json:"content_ref,omitempty"`
}

type FileChangeSummary struct {
	Created      int `json:"created"`
	Modified     int `json:"modified"`
	Deleted      int `json:"deleted"`
	Unchanged    int `json:"unchanged"`
	OtherChanges int `json:"other_changes,omitempty"`
}

type fileSnapshotState struct {
	Exists  bool
	SHA256  string
	Bytes   int64
	Content []byte
}

func TrajectoriesRun(db *sql.DB, runID string, out io.Writer, languages ...i18n.Locale) error {
	manifest, err := BuildTrajectoriesRun(db, runID)
	if err != nil {
		return err
	}
	PrintTrajectoryManifest(out, manifest, languages...)
	return nil
}

func TrajectoriesRunJSON(db *sql.DB, runID string, out io.Writer) error {
	manifest, err := BuildTrajectoriesRun(db, runID)
	if err != nil {
		return err
	}
	return printJSON(out, manifest)
}

func BuildTrajectoriesRun(db *sql.DB, runID string) (TrajectoryManifest, error) {
	return buildTrajectories(db, runID, false)
}

func buildTrajectories(db *sql.DB, runID string, captureForks bool) (TrajectoryManifest, error) {
	replay, err := BuildReplayRun(db, runID)
	if err != nil {
		return TrajectoryManifest{}, err
	}
	manifest := TrajectoryManifest{
		SchemaVersion: "agentprovenance.trajectories/v1",
		RunID:         runID,
		DecisionOwner: "external_evaluator",
	}
	var saved map[string]TrajectoryEvidence
	for _, rollout := range replay.Rollouts {
		manifest.Rollouts = append(manifest.Rollouts, TrajectoryRollout{
			ID:             rollout.ID,
			BaseSnapshotID: rollout.BaseSnapshotID,
			Status:         rollout.Status,
			LocalCandidate: rollout.WinnerAttemptID,
			PromotionID:    rollout.PromotionID,
			RiskStatus:     rollout.RiskStatus,
			BaseSnapshot:   rollout.BaseSnapshot,
		})
		for _, attempt := range rollout.Attempts {
			var changes []TrajectoryFileChange
			var summary FileChangeSummary
			source, state := "retained_fork_snapshot", "not_recorded"
			if attempt.Strategy == "zero-sdk-record" {
				source = "recorded_snapshot"
				report, err := recordedFilesFor(db, runID, rollout.ID, rollout.BaseSnapshotID)
				if err != nil {
					return TrajectoryManifest{}, err
				}
				state = report.Status
				for i := range report.Files {
					path, err := cleanRelativeFile(report.Files[i].Path)
					if err != nil {
						return TrajectoryManifest{}, err
					}
					change, err := report.comparison(db, runID, path, &report.Files[i])
					if err != nil {
						return TrajectoryManifest{}, err
					}
					changes = append(changes, change)
					switch change.ChangeType {
					case "created":
						summary.Created++
					case "modified":
						summary.Modified++
					case "deleted":
						summary.Deleted++
					default:
						summary.OtherChanges++
					}
				}
			} else {
				if saved == nil {
					saved, err = savedForkFiles(db, runID)
					if err != nil {
						return TrajectoryManifest{}, err
					}
				}
				if old, ok := saved[attempt.ID]; ok && old.RolloutID == rollout.ID {
					changes, summary, state = old.FileChanges, old.FileChangeSummary, old.FileCaptureState
					if state == "" {
						state = "ok"
					}
				} else if captureForks && attempt.Workspace != "" && rollout.BaseSnapshot != nil && rollout.BaseSnapshot.Path != "" {
					baseFiles := map[string]fileSnapshotState{}
					if rollout.BaseSnapshot != nil {
						baseFiles, err = collectFileStates(rollout.BaseSnapshot.Path)
						if err != nil {
							return TrajectoryManifest{}, err
						}
					}
					nextFiles, err := collectFileStates(attempt.Workspace)
					if err != nil {
						return TrajectoryManifest{}, err
					}
					changes, summary = compareFileStates(baseFiles, nextFiles)
					state = "ok"
				}
			}
			manifest.Trajectories = append(manifest.Trajectories, TrajectoryEvidence{
				RunID:                  rollout.RunID,
				RolloutID:              rollout.ID,
				AttemptID:              attempt.ID,
				SnapshotID:             attempt.SnapshotID,
				ToolCallID:             attempt.ToolCallID,
				Workspace:              attempt.Workspace,
				Strategy:               attempt.Strategy,
				Command:                attempt.Command,
				Status:                 attempt.Status,
				RiskStatus:             attempt.RiskStatus,
				LocalCandidateEligible: attempt.IsWinner && !attempt.ReplayBlocked,
				ReplayBlocked:          attempt.ReplayBlocked,
				BlockReasons:           attempt.BlockReasons,
				Score:                  attempt.Score,
				CostEstimate:           attempt.CostEstimate,
				ArtifactResult:         attempt.ArtifactResult,
				ArtifactDigest:         attempt.ArtifactDigest,
				ToolCall:               attempt.ToolCall,
				Processes:              attempt.Processes,
				RuntimeEvents:          attempt.Events,
				ExternalEffects:        attempt.ExternalEffects,
				FileChanges:            changes,
				FileChangeSummary:      summary,
				FileChangeSource:       source,
				FileCaptureState:       state,
			})
		}
	}
	return manifest, nil
}

func PrintTrajectoryManifest(out io.Writer, manifest TrajectoryManifest, languages ...i18n.Locale) {
	lang := presentationLocale(languages)
	fmt.Fprintf(out, i18n.T(lang, "trajectories_run=%s schema=%s decision_owner=%s trajectories=%d\n"), manifest.RunID, manifest.SchemaVersion, manifest.DecisionOwner, len(manifest.Trajectories))
	for _, trajectory := range manifest.Trajectories {
		fmt.Fprintf(out, i18n.T(lang, "trajectory attempt=%s rollout=%s tool_call=%s status=%s risk=%s local_candidate_eligible=%t replay_blocked=%t score=%.3f cost=%.6f files_created=%d files_modified=%d files_deleted=%d files_unchanged=%d artifact=%s\n"),
			trajectory.AttemptID, trajectory.RolloutID, trajectory.ToolCallID, trajectory.Status, trajectory.RiskStatus, trajectory.LocalCandidateEligible, trajectory.ReplayBlocked, trajectory.Score, trajectory.CostEstimate, trajectory.FileChangeSummary.Created, trajectory.FileChangeSummary.Modified, trajectory.FileChangeSummary.Deleted, trajectory.FileChangeSummary.Unchanged, trajectory.ArtifactResult)
		for _, change := range trajectory.FileChanges {
			fmt.Fprintf(out, i18n.T(lang, "  file=%s change=%s base_sha256=%s next_sha256=%s base_bytes=%d next_bytes=%d\n"),
				change.Path, change.ChangeType, change.BaseSHA256, change.NextSHA256, change.BaseBytes, change.NextBytes)
		}
	}
}

func collectFileStates(root string) (map[string]fileSnapshotState, error) {
	files := map[string]fileSnapshotState{}
	if root == "" {
		return files, nil
	}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = fileSnapshotState{
			Exists:  true,
			SHA256:  sha256Hex(content),
			Bytes:   int64(len(content)),
			Content: content,
		}
		return nil
	})
	return files, err
}

func compareFileStates(base, next map[string]fileSnapshotState) ([]TrajectoryFileChange, FileChangeSummary) {
	paths := make(map[string]bool, len(base)+len(next))
	for path := range base {
		paths[path] = true
	}
	for path := range next {
		paths[path] = true
	}
	ordered := make([]string, 0, len(paths))
	for path := range paths {
		ordered = append(ordered, path)
	}
	sort.Strings(ordered)

	var changes []TrajectoryFileChange
	var summary FileChangeSummary
	for _, path := range ordered {
		baseState, baseOK := base[path]
		nextState, nextOK := next[path]
		changeType := "unchanged"
		switch {
		case !baseOK && nextOK:
			changeType = "created"
			summary.Created++
		case baseOK && !nextOK:
			changeType = "deleted"
			summary.Deleted++
		case baseOK && nextOK && baseState.SHA256 != nextState.SHA256:
			changeType = "modified"
			summary.Modified++
		default:
			summary.Unchanged++
		}
		if changeType == "unchanged" {
			continue
		}
		change := TrajectoryFileChange{
			Path:        path,
			ChangeType:  changeType,
			BaseExists:  baseOK,
			NextExists:  nextOK,
			BaseSHA256:  hashOrMissing(baseState.Content, baseOK),
			NextSHA256:  hashOrMissing(nextState.Content, nextOK),
			BaseBytes:   baseState.Bytes,
			NextBytes:   nextState.Bytes,
			UnifiedDiff: unifiedLines(baseState.Content, baseOK, nextState.Content, nextOK),
		}
		changes = append(changes, change)
	}
	return changes, summary
}
