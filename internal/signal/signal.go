package signal

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/security"
)

type Kind string

const (
	KindRewardFeature Kind = "reward_feature"
	KindPenalty       Kind = "penalty"
	KindDatasetLabel  Kind = "dataset_label"
	KindQualitySignal Kind = "quality_signal"
)

type EvalSignal struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Kind       Kind           `json:"kind"`
	RunID      string         `json:"run_id"`
	AttemptID  string         `json:"attempt_id,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
	Score      float64        `json:"score"`
	Label      string         `json:"label,omitempty"`
	Reason     string         `json:"reason"`
	Evidence   map[string]any `json:"evidence,omitempty"`
}

type EvalReport struct {
	SchemaVersion string       `json:"schema_version"`
	RunID         string       `json:"run_id"`
	Engine        string       `json:"engine"`
	DecisionOwner string       `json:"decision_owner"`
	SignalCount   int          `json:"signal_count"`
	ResultSetID   string       `json:"result_set_id"`
	PageHash      string       `json:"page_hash"`
	Signals       []EvalSignal `json:"signals"`
}

type EvalContext struct {
	SchemaVersion string                            `json:"schema_version"`
	RunID         string                            `json:"run_id"`
	Trajectories  provenance.TrajectoryManifest     `json:"trajectories"`
	Risks         []security.RiskSignalRecord       `json:"risks"`
	Responses     []security.ResponseActionRecord   `json:"responses"`
	RuntimeEvents []provenance.ReplayEvent          `json:"runtime_events"`
	FileChanges   []provenance.TrajectoryFileChange `json:"file_changes"`
}

type ExternalEvalOutput struct {
	Signals []EvalSignal `json:"signals"`
}

type Context struct {
	DB           *sql.DB
	RunID        string
	Trajectories provenance.TrajectoryManifest
	Risks        []security.RiskSignalRecord
	Responses    []security.ResponseActionRecord
}

type Evaluator func(Context) ([]EvalSignal, error)

type Registry struct {
	evaluators map[string]Evaluator
}

func NewRegistry() Registry {
	r := Registry{evaluators: map[string]Evaluator{}}
	r.Register("risk_penalty", riskPenalty)
	r.Register("replay_block_penalty", replayBlockPenalty)
	r.Register("file_change_volume", fileChangeVolume)
	r.Register("artifact_presence", artifactPresence)
	r.Register("dataset_label", datasetLabel)
	return r
}

func (r Registry) Register(name string, evaluator Evaluator) {
	if strings.TrimSpace(name) == "" || evaluator == nil {
		return
	}
	r.evaluators[name] = evaluator
}

func BuildRunReport(db *sql.DB, runID string) (EvalReport, error) {
	ctx, err := BuildEvalContext(db, runID)
	if err != nil {
		return EvalReport{}, err
	}
	return BuildBuiltinReportFromContext(ctx)
}

func BuildEvalContext(db *sql.DB, runID string) (EvalContext, error) {
	if strings.TrimSpace(runID) == "" {
		return EvalContext{}, fmt.Errorf("run_id is required")
	}
	trajectories, err := provenance.BuildTrajectoriesRun(db, runID)
	if err != nil {
		return EvalContext{}, err
	}
	risks, err := security.ListRiskSignals(db, runID)
	if err != nil {
		return EvalContext{}, err
	}
	responses, err := security.ListResponseActions(db, runID)
	if err != nil {
		return EvalContext{}, err
	}
	var runtimeEvents []provenance.ReplayEvent
	var fileChanges []provenance.TrajectoryFileChange
	for _, trajectory := range trajectories.Trajectories {
		runtimeEvents = append(runtimeEvents, trajectory.RuntimeEvents...)
		fileChanges = append(fileChanges, trajectory.FileChanges...)
	}
	if risks == nil {
		risks = []security.RiskSignalRecord{}
	}
	if responses == nil {
		responses = []security.ResponseActionRecord{}
	}
	if runtimeEvents == nil {
		runtimeEvents = []provenance.ReplayEvent{}
	}
	if fileChanges == nil {
		fileChanges = []provenance.TrajectoryFileChange{}
	}
	return EvalContext{
		SchemaVersion: "agentprovenance.eval_context/v1",
		RunID:         runID,
		Trajectories:  trajectories,
		Risks:         risks,
		Responses:     responses,
		RuntimeEvents: runtimeEvents,
		FileChanges:   fileChanges,
	}, nil
}

func BuildBuiltinReportFromContext(evalCtx EvalContext) (EvalReport, error) {
	ctx := Context{RunID: evalCtx.RunID, Trajectories: evalCtx.Trajectories, Risks: evalCtx.Risks, Responses: evalCtx.Responses}
	registry := NewRegistry()
	names := make([]string, 0, len(registry.evaluators))
	for name := range registry.evaluators {
		names = append(names, name)
	}
	sort.Strings(names)
	var signals []EvalSignal
	for _, name := range names {
		items, err := registry.evaluators[name](ctx)
		if err != nil {
			return EvalReport{}, fmt.Errorf("signal %s: %w", name, err)
		}
		signals = append(signals, items...)
	}
	sort.Slice(signals, func(i, j int) bool {
		if signals[i].AttemptID == signals[j].AttemptID {
			return signals[i].Name < signals[j].Name
		}
		return signals[i].AttemptID < signals[j].AttemptID
	})
	for i := range signals {
		signals[i].ID = fmt.Sprintf("signal-%03d", i+1)
	}
	resultSetID, pageHash, err := integrity(evalCtx.RunID, signals)
	if err != nil {
		return EvalReport{}, err
	}
	return EvalReport{
		SchemaVersion: "agentprovenance.eval_signals/v1",
		RunID:         evalCtx.RunID,
		Engine:        "builtin-code-signal-engine",
		DecisionOwner: "external_evaluator",
		SignalCount:   len(signals),
		ResultSetID:   resultSetID,
		PageHash:      pageHash,
		Signals:       signals,
	}, nil
}

func ImportSignals(runID, engine string, signals []EvalSignal) (EvalReport, error) {
	if strings.TrimSpace(runID) == "" {
		return EvalReport{}, fmt.Errorf("run_id is required")
	}
	if strings.TrimSpace(engine) == "" {
		engine = "external-evaluator"
	}
	for i := range signals {
		if err := validateSignal(&signals[i]); err != nil {
			return EvalReport{}, fmt.Errorf("signal %d: %w", i+1, err)
		}
		if signals[i].RunID == "" {
			signals[i].RunID = runID
		}
		if signals[i].RunID != runID {
			return EvalReport{}, fmt.Errorf("signal %d run_id %q does not match %q", i+1, signals[i].RunID, runID)
		}
		signals[i].ID = fmt.Sprintf("signal-%03d", i+1)
	}
	resultSetID, pageHash, err := integrity(runID, signals)
	if err != nil {
		return EvalReport{}, err
	}
	return EvalReport{
		SchemaVersion: "agentprovenance.eval_signals/v1",
		RunID:         runID,
		Engine:        engine,
		DecisionOwner: "external_evaluator",
		SignalCount:   len(signals),
		ResultSetID:   resultSetID,
		PageHash:      pageHash,
		Signals:       signals,
	}, nil
}

func RunExternal(command string, evalCtx EvalContext) (EvalReport, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return EvalReport{}, fmt.Errorf("external evaluator command is required")
	}
	input, err := json.Marshal(evalCtx)
	if err != nil {
		return EvalReport{}, err
	}
	cmd := exec.Command("sh", "-c", command)
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return EvalReport{}, fmt.Errorf("external evaluator failed: %w stderr=%s", err, strings.TrimSpace(stderr.String()))
	}
	var output ExternalEvalOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		return EvalReport{}, fmt.Errorf("external evaluator output must be JSON object with signals: %w", err)
	}
	return ImportSignals(evalCtx.RunID, command, output.Signals)
}

func validateSignal(signal *EvalSignal) error {
	if strings.TrimSpace(signal.Name) == "" {
		return fmt.Errorf("name is required")
	}
	switch signal.Kind {
	case KindRewardFeature, KindPenalty, KindDatasetLabel, KindQualitySignal:
	default:
		return fmt.Errorf("invalid kind %q", signal.Kind)
	}
	if strings.TrimSpace(signal.Reason) == "" {
		return fmt.Errorf("reason is required")
	}
	return nil
}

func riskPenalty(ctx Context) ([]EvalSignal, error) {
	var out []EvalSignal
	for _, t := range ctx.Trajectories.Trajectories {
		count := 0
		severity := map[string]int{}
		for _, event := range t.RuntimeEvents {
			for _, risk := range ctx.Risks {
				if risk.EventID == event.ID {
					count++
					severity[risk.Severity]++
				}
			}
		}
		if count == 0 && t.RiskStatus != "" && t.RiskStatus != "clean" && t.RiskStatus != "unknown" {
			count = 1
		}
		if count > 0 {
			out = append(out, EvalSignal{
				Name:       "runtime.risk_penalty",
				Kind:       KindPenalty,
				RunID:      ctx.RunID,
				AttemptID:  t.AttemptID,
				ToolCallID: t.ToolCallID,
				Score:      -1 * float64(count),
				Reason:     "trajectory has runtime risk evidence",
				Evidence:   map[string]any{"risk_count": count, "severity": severity, "risk_status": t.RiskStatus},
			})
		}
	}
	return out, nil
}

func replayBlockPenalty(ctx Context) ([]EvalSignal, error) {
	var out []EvalSignal
	for _, t := range ctx.Trajectories.Trajectories {
		if t.ReplayBlocked || len(t.BlockReasons) > 0 {
			out = append(out, EvalSignal{
				Name:       "replay.blocked_penalty",
				Kind:       KindPenalty,
				RunID:      ctx.RunID,
				AttemptID:  t.AttemptID,
				ToolCallID: t.ToolCallID,
				Score:      -1,
				Reason:     "trajectory replay is blocked by provenance/risk gate",
				Evidence:   map[string]any{"block_reasons": t.BlockReasons},
			})
		}
	}
	return out, nil
}

func fileChangeVolume(ctx Context) ([]EvalSignal, error) {
	var out []EvalSignal
	for _, t := range ctx.Trajectories.Trajectories {
		changed := t.FileChangeSummary.Created + t.FileChangeSummary.Modified + t.FileChangeSummary.Deleted
		out = append(out, EvalSignal{
			Name:       "state.file_change_volume",
			Kind:       KindRewardFeature,
			RunID:      ctx.RunID,
			AttemptID:  t.AttemptID,
			ToolCallID: t.ToolCallID,
			Score:      float64(changed),
			Reason:     "file-level state delta size for external scoring",
			Evidence: map[string]any{
				"created": t.FileChangeSummary.Created, "modified": t.FileChangeSummary.Modified,
				"deleted": t.FileChangeSummary.Deleted, "unchanged": t.FileChangeSummary.Unchanged,
			},
		})
	}
	return out, nil
}

func artifactPresence(ctx Context) ([]EvalSignal, error) {
	var out []EvalSignal
	for _, t := range ctx.Trajectories.Trajectories {
		score := 0.0
		label := "missing_artifact"
		if t.ArtifactResult != "" || t.ArtifactDigest != nil {
			score = 1
			label = "artifact_present"
		}
		out = append(out, EvalSignal{
			Name:       "artifact.presence",
			Kind:       KindQualitySignal,
			RunID:      ctx.RunID,
			AttemptID:  t.AttemptID,
			ToolCallID: t.ToolCallID,
			Score:      score,
			Label:      label,
			Reason:     "artifact availability signal for evaluator filtering",
			Evidence:   map[string]any{"artifact_result": t.ArtifactResult, "artifact_digest": t.ArtifactDigest},
		})
	}
	return out, nil
}

func datasetLabel(ctx Context) ([]EvalSignal, error) {
	var out []EvalSignal
	for _, t := range ctx.Trajectories.Trajectories {
		label := "candidate"
		score := 1.0
		reasons := []string{}
		if t.ReplayBlocked {
			label = "reject_replay_blocked"
			score = 0
			reasons = append(reasons, "replay_blocked")
		}
		if t.RiskStatus != "" && t.RiskStatus != "clean" && t.RiskStatus != "unknown" {
			label = "reject_risky"
			score = 0
			reasons = append(reasons, "risk_status="+t.RiskStatus)
		}
		out = append(out, EvalSignal{
			Name:       "dataset.filter_label",
			Kind:       KindDatasetLabel,
			RunID:      ctx.RunID,
			AttemptID:  t.AttemptID,
			ToolCallID: t.ToolCallID,
			Score:      score,
			Label:      label,
			Reason:     "dataset inclusion label derived from provenance gates",
			Evidence:   map[string]any{"reasons": reasons, "local_candidate_eligible": t.LocalCandidateEligible},
		})
	}
	return out, nil
}

func integrity(runID string, signals []EvalSignal) (string, string, error) {
	resultRaw, err := json.Marshal(map[string]any{"kind": "eval_signal_result_set", "run_id": runID, "count": len(signals)})
	if err != nil {
		return "", "", err
	}
	resultSum := sha256.Sum256(resultRaw)
	pageRaw, err := json.Marshal(map[string]any{"kind": "eval_signal_page", "result_set_id": fmt.Sprintf("sha256:%x", resultSum[:]), "signals": signals})
	if err != nil {
		return "", "", err
	}
	pageSum := sha256.Sum256(pageRaw)
	return fmt.Sprintf("sha256:%x", resultSum[:]), fmt.Sprintf("sha256:%x", pageSum[:]), nil
}
