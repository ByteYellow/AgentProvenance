package attempt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/byteyellow/agentprovenance/internal/control"
	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/ids"
	runtimeplane "github.com/byteyellow/agentprovenance/internal/runtime"
	"github.com/byteyellow/agentprovenance/internal/scheduler"
	"github.com/byteyellow/agentprovenance/internal/state"
	"github.com/byteyellow/agentprovenance/internal/store"
)

type Service struct {
	DB    *sql.DB
	State state.Service
}

type Result struct {
	AttemptID      string
	ToolCallID     string
	SessionID      string
	ProcessID      string
	WorkspacePath  string
	Strategy       string
	Command        string
	Status         string
	ExitCode       int
	WallMS         int64
	OutputSummary  string
	Score          float64
	BudgetSeconds  int
	ArtifactResult string
	CostEstimate   float64
	SavedCost      float64
	RiskStatus     string
	BudgetExceeded bool
	IsWinner       bool
	BurstID        string
	BurstStatus    string
	BurstReason    string
}

func (s Service) BestOf(snapshotNameOrID string, strategies []string) ([]Result, Result, error) {
	return s.BestOfWithOptions(snapshotNameOrID, strategies, Options{MaxFanout: len(strategies)})
}

type Options struct {
	MaxFanout       int
	MaxCost         float64
	EarlyStop       bool
	TopK            int
	RunID           string
	BurstCPURequest float64
	BurstTTL        time.Duration
	Runtime         string
	TaskPath        string
	BaseSnapshotID  string
	Paths           store.Paths
	Driver          runtimeplane.Driver
}

type Strategy struct {
	Name           string
	Command        string
	ProbeCommand   string
	BudgetSeconds  int
	ScoreParser    string
	ArtifactResult string
}

func (s Service) BestOfWithOptions(snapshotNameOrID string, strategies []string, opts Options) ([]Result, Result, error) {
	if len(strategies) == 0 {
		return nil, Result{}, fmt.Errorf("at least one --strategy is required")
	}
	parsed := parseStrategies(strategies)
	if opts.MaxFanout <= 0 || opts.MaxFanout > len(parsed) {
		opts.MaxFanout = len(parsed)
	}
	if opts.MaxCost > 0 {
		maxByCost := int(opts.MaxCost / 0.001)
		if maxByCost < 1 {
			maxByCost = 1
		}
		if maxByCost < opts.MaxFanout {
			opts.MaxFanout = maxByCost
		}
	}
	parsed = parsed[:opts.MaxFanout]
	forks, err := s.State.Fork(snapshotNameOrID, len(parsed))
	if err != nil {
		return nil, Result{}, err
	}
	toolCallIDs := make([]string, len(parsed))
	createdAt := time.Now().UTC().Format(time.RFC3339Nano)
	for i, strategy := range parsed {
		toolCallID := ids.New("tool")
		toolCallIDs[i] = toolCallID
		if _, err := s.DB.Exec(`INSERT INTO tool_calls
			(id, run_id, attempt_id, command, args_hash, status, created_at)
			VALUES (?, ?, ?, ?, ?, 'prepared', ?)`,
			toolCallID, opts.RunID, forks[i].AttemptID, strategy.Command, argsHash(strategy.Command), createdAt); err != nil {
			return nil, Result{}, err
		}
	}
	results := make([]Result, len(parsed))
	prunedCount := 0
	if shouldRunProbeStage(parsed, opts) {
		prunedCount = s.runProbeThenTopK(forks, parsed, toolCallIDs, opts, results)
	} else {
		var wg sync.WaitGroup
		for i, fork := range forks {
			wg.Add(1)
			go func(i int, fork state.ForkResult, strategy Strategy, toolCallID string) {
				defer wg.Done()
				results[i] = s.runAttemptWithBurst(fork.AttemptID, toolCallID, fork.WorkspacePath, strategy, opts)
			}(i, fork, parsed[i], toolCallIDs[i])
		}
		wg.Wait()
	}

	winnerIndex := -1
	var totalCost float64
	for i, result := range results {
		totalCost += result.CostEstimate
		if _, err := s.DB.Exec(`UPDATE fork_attempts
			SET tool_call_id = ?, strategy = ?, command = ?, status = ?, exit_code = ?, wall_ms = ?, output_summary = ?, score = ?, budget_seconds = ?, artifact_result = ?, cost_estimate = ?, saved_cost = ?, risk_status = ?, budget_exceeded = ?
			WHERE id = ?`, result.ToolCallID, result.Strategy, result.Command, result.Status, result.ExitCode, result.WallMS, result.OutputSummary, result.Score, result.BudgetSeconds, result.ArtifactResult, result.CostEstimate, result.SavedCost, result.RiskStatus, boolInt(result.BudgetExceeded), result.AttemptID); err != nil {
			return results, Result{}, err
		}
		endedAt := time.Now().UTC().Format(time.RFC3339Nano)
		if _, err := s.DB.Exec(`UPDATE tool_calls
			SET session_id = ?, status = ?, exit_code = ?, wall_ms = ?, cost_estimate = ?, result_ref = ?, policy_decision = 'allow', started_at = COALESCE(NULLIF(started_at, ''), created_at), ended_at = ?
			WHERE id = ?`, result.SessionID, result.Status, result.ExitCode, result.WallMS, result.CostEstimate, result.ArtifactResult, endedAt, result.ToolCallID); err != nil {
			return results, Result{}, err
		}
		if winnerIndex == -1 || better(result, results[winnerIndex]) {
			winnerIndex = i
		}
	}
	if winnerIndex == -1 {
		return results, Result{}, fmt.Errorf("no attempts executed")
	}
	winner := results[winnerIndex]
	winner.IsWinner = true
	results[winnerIndex].IsWinner = true
	if _, err := s.DB.Exec(`UPDATE fork_attempts SET is_winner = CASE WHEN id = ? THEN 1 ELSE 0 END`, winner.AttemptID); err != nil {
		return results, Result{}, err
	}
	saved := float64(len(strategies)-len(results)+prunedCount) * 0.001
	for i := range results {
		results[i].SavedCost = saved
		_, _ = s.DB.Exec(`UPDATE fork_attempts SET saved_cost = ? WHERE id = ?`, saved, results[i].AttemptID)
	}
	_, _ = s.DB.Exec(`INSERT INTO cost_samples (id, run_id, fanout_cost, saved_cost, created_at)
		SELECT 'cost-' || lower(hex(randomblob(6))), COALESCE(s.run_id, 'unknown'), ?, ?, ?
		FROM snapshots sn LEFT JOIN sessions s ON sn.session_id = s.id WHERE sn.id = (SELECT snapshot_id FROM fork_attempts WHERE id = ?)
		LIMIT 1`, totalCost, saved, time.Now().UTC().Format(time.RFC3339Nano), winner.AttemptID)
	return results, winner, nil
}

func shouldRunProbeStage(strategies []Strategy, opts Options) bool {
	for _, strategy := range strategies {
		if strings.TrimSpace(strategy.ProbeCommand) != "" {
			return opts.TopK > 0 || opts.EarlyStop
		}
	}
	return false
}

func (s Service) runProbeThenTopK(forks []state.ForkResult, strategies []Strategy, toolCallIDs []string, opts Options, results []Result) int {
	probes := make([]Result, len(strategies))
	var wg sync.WaitGroup
	for i, fork := range forks {
		wg.Add(1)
		go func(i int, fork state.ForkResult, strategy Strategy, toolCallID string) {
			defer wg.Done()
			probeStrategy := strategy
			if strings.TrimSpace(strategy.ProbeCommand) != "" {
				probeStrategy.Command = strategy.ProbeCommand
			}
			probeStrategy.ArtifactResult = "probe:" + strategy.ArtifactResult
			probes[i] = s.runAttemptWithBurst(fork.AttemptID, toolCallID, fork.WorkspacePath, probeStrategy, opts)
			probes[i].Strategy = strategy.Name
			probes[i].Command = strategy.Command
			probes[i].ArtifactResult = strategy.ArtifactResult
			if probes[i].OutputSummary != "" {
				probes[i].OutputSummary = "probe: " + probes[i].OutputSummary
			} else {
				probes[i].OutputSummary = "probe completed"
			}
		}(i, fork, strategies[i], toolCallIDs[i])
	}
	wg.Wait()

	topK := opts.TopK
	if topK <= 0 && opts.EarlyStop {
		topK = 1
	}
	if topK <= 0 || topK > len(strategies) {
		topK = len(strategies)
	}
	order := make([]int, len(strategies))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool {
		return better(probes[order[i]], probes[order[j]])
	})
	selected := map[int]bool{}
	for _, index := range order[:topK] {
		selected[index] = true
	}

	pruned := 0
	for i := range forks {
		if !selected[i] {
			result := probes[i]
			result.Status = "pruned"
			result.OutputSummary = strings.TrimSpace(result.OutputSummary + " | pruned_before_full_command")
			results[i] = result
			pruned++
		}
	}
	for _, i := range order {
		if !selected[i] || results[i].AttemptID != "" {
			continue
		}
		fork := forks[i]
		full := s.runAttemptWithBurst(fork.AttemptID, toolCallIDs[i], fork.WorkspacePath, strategies[i], opts)
		full.WallMS += probes[i].WallMS
		full.CostEstimate += probes[i].CostEstimate
		if probes[i].BudgetExceeded {
			full.BudgetExceeded = true
		}
		if probes[i].OutputSummary != "" {
			full.OutputSummary = strings.TrimSpace(probes[i].OutputSummary + " | full: " + full.OutputSummary)
		}
		results[i] = full
		if opts.EarlyStop && full.ExitCode == 0 && !full.BudgetExceeded && full.Score >= 999 {
			for _, index := range order {
				if index == i || !selected[index] || results[index].AttemptID != "" {
					continue
				}
				result := probes[index]
				result.Status = "pruned"
				result.OutputSummary = strings.TrimSpace(result.OutputSummary + " | early_stop_after_winner")
				results[index] = result
				pruned++
			}
			break
		}
	}
	for i := range results {
		if results[i].AttemptID == "" {
			result := probes[i]
			result.Status = "pruned"
			result.OutputSummary = strings.TrimSpace(result.OutputSummary + " | pruned_before_full_command")
			results[i] = result
			pruned++
		}
	}
	return pruned
}

func (s Service) runAttemptWithBurst(attemptID, toolCallID, workspacePath string, strategy Strategy, opts Options) Result {
	if strings.EqualFold(opts.Runtime, "docker") {
		return s.runDockerAttempt(attemptID, toolCallID, workspacePath, strategy, opts)
	}
	cpuRequest := opts.BurstCPURequest
	if cpuRequest <= 0 {
		cpuRequest = 1
	}
	ttl := opts.BurstTTL
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	runID := opts.RunID
	if runID == "" {
		runID = "unknown"
	}
	sessionID, err := s.ensureLocalAttemptSession(runID, attemptID, workspacePath, opts)
	if err != nil {
		return rejectedResult(attemptID, toolCallID, workspacePath, strategy, err.Error())
	}
	processID := ids.New("proc")
	startedAt := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.execWithBusyRetry(`INSERT INTO processes
		(id, session_id, tool_call_id, command, status, started_at)
		VALUES (?, ?, ?, ?, 'burst_pending', ?)`, processID, sessionID, toolCallID, strategy.Command, startedAt); err != nil {
		return rejectedResult(attemptID, toolCallID, workspacePath, strategy, err.Error())
	}
	_, _ = correlation.RecordBinding(s.DB, correlation.Binding{
		RunID:         runID,
		SessionID:     sessionID,
		AttemptID:     attemptID,
		ToolCallID:    toolCallID,
		ProcessID:     processID,
		StartedAt:     startedAt,
		BindingSource: "rollout_local",
	})
	_, _ = s.DB.Exec(`UPDATE tool_calls SET status = 'burst_pending', started_at = ? WHERE id = ?`, startedAt, toolCallID)
	reservation, err := (scheduler.Scheduler{DB: s.DB}).ReserveBurst(runID, sessionID, processID, cpuRequest, ttl)
	if err != nil {
		reason := reservation.Reason
		if reason == "" {
			reason = err.Error()
		}
		endedAt := time.Now().UTC().Format(time.RFC3339Nano)
		_, _ = s.DB.Exec(`UPDATE processes SET status = 'rejected', exit_code = 125, ended_at = ? WHERE id = ?`, endedAt, processID)
		_, _ = s.DB.Exec(`UPDATE sessions SET status = 'stopped', updated_at = ? WHERE id = ?`, endedAt, sessionID)
		_, _ = s.DB.Exec(`UPDATE tool_calls
			SET status = 'rejected', exit_code = 125, result_ref = ?, policy_decision = 'allow', ended_at = ?
			WHERE id = ?`, reason, endedAt, toolCallID)
		_, _ = s.DB.Exec(`INSERT INTO events (id, run_id, session_id, tool_call_id, process_id, source, event_type, payload, created_at)
			VALUES (?, ?, ?, ?, ?, 'rollout', 'burst_reject', ?, ?)`,
			ids.New("evt"), runID, sessionID, toolCallID, processID, fmt.Sprintf(`{"reservation_id":%q,"reason":%q}`, reservation.ID, reason), endedAt)
		return Result{
			AttemptID:      attemptID,
			ToolCallID:     toolCallID,
			SessionID:      sessionID,
			ProcessID:      processID,
			WorkspacePath:  workspacePath,
			Strategy:       strategy.Name,
			Command:        strategy.Command,
			Status:         "rejected",
			ExitCode:       125,
			OutputSummary:  reason,
			Score:          -2000,
			BudgetSeconds:  strategy.BudgetSeconds,
			ArtifactResult: strategy.ArtifactResult,
			RiskStatus:     "unknown",
			BurstID:        reservation.ID,
			BurstStatus:    "rejected",
			BurstReason:    reason,
		}
	}
	_, _ = s.DB.Exec(`INSERT INTO events (id, run_id, session_id, tool_call_id, process_id, source, event_type, payload, created_at)
		VALUES (?, ?, ?, ?, ?, 'rollout', 'burst_reserve', ?, ?)`,
		ids.New("evt"), runID, sessionID, toolCallID, processID, fmt.Sprintf(`{"reservation_id":%q,"inflight_before":%d,"max_inflight":%d,"reserved_cpu_before":%.3f}`, reservation.ID, reservation.Inflight, reservation.MaxInflight, reservation.ReservedCPU), time.Now().UTC().Format(time.RFC3339Nano))
	_, _ = s.DB.Exec(`UPDATE tool_calls SET status = 'running' WHERE id = ?`, toolCallID)
	_, _ = s.DB.Exec(`UPDATE processes SET status = 'running' WHERE id = ?`, processID)
	_, _ = s.DB.Exec(`INSERT INTO events (id, run_id, session_id, tool_call_id, process_id, source, event_type, payload, created_at)
		VALUES (?, ?, ?, ?, ?, 'rollout', 'exec_start', ?, ?)`,
		ids.New("evt"), runID, sessionID, toolCallID, processID, fmt.Sprintf(`{"attempt_id":%q,"command":%q}`, attemptID, strategy.Command), time.Now().UTC().Format(time.RFC3339Nano))
	result := runAttempt(attemptID, workspacePath, strategy)
	result.RiskStatus = "clean"
	result.BudgetExceeded = budgetExceeded(result.WallMS, strategy.BudgetSeconds)
	if result.BudgetExceeded && result.Status == "passed" {
		result.Status = "budget_exceeded"
		result.Score -= 500
	}
	result = s.captureArtifact(result, strategy)
	result.ToolCallID = toolCallID
	result.SessionID = sessionID
	result.ProcessID = processID
	result.BurstID = reservation.ID
	result.BurstStatus = "released"
	result.BurstReason = reservation.Reason
	processStatus := "exited"
	if result.Status == "failed" || result.Status == "rejected" {
		processStatus = result.Status
	}
	endedAt := time.Now().UTC().Format(time.RFC3339Nano)
	_, _ = s.DB.Exec(`UPDATE processes SET status = ?, exit_code = ?, ended_at = ? WHERE id = ?`, processStatus, result.ExitCode, endedAt, processID)
	_ = correlation.CloseBinding(s.DB, processID, endedAt)
	_, _ = s.DB.Exec(`UPDATE sessions SET status = 'stopped', updated_at = ? WHERE id = ?`, endedAt, sessionID)
	_, _ = s.DB.Exec(`INSERT INTO events (id, run_id, session_id, tool_call_id, process_id, source, event_type, payload, created_at)
		VALUES (?, ?, ?, ?, ?, 'rollout', 'exec_end', ?, ?)`,
		ids.New("evt"), runID, sessionID, toolCallID, processID, fmt.Sprintf(`{"attempt_id":%q,"exit_code":%d,"status":%q,"wall_ms":%d}`, attemptID, result.ExitCode, result.Status, result.WallMS), endedAt)
	_ = (scheduler.Scheduler{DB: s.DB}).ReleaseBurst(reservation.ID)
	_, _ = s.DB.Exec(`INSERT INTO events (id, run_id, session_id, tool_call_id, process_id, source, event_type, payload, created_at)
		VALUES (?, ?, ?, ?, ?, 'rollout', 'burst_release', ?, ?)`,
		ids.New("evt"), runID, sessionID, toolCallID, processID, fmt.Sprintf(`{"reservation_id":%q}`, reservation.ID), time.Now().UTC().Format(time.RFC3339Nano))
	return result
}

func (s Service) ensureLocalAttemptSession(runID, attemptID, workspacePath string, opts Options) (string, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	leaseID := "lease-" + attemptID
	sessionID := "local-" + attemptID
	taskPath := opts.TaskPath
	taskYAML := "{}"
	if taskPath != "" {
		if raw, err := os.ReadFile(taskPath); err == nil {
			taskYAML = string(raw)
		}
	}
	if _, err := s.execWithBusyRetry(`INSERT OR IGNORE INTO leases
		(id, run_id, task_path, task_yaml, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'allocated', ?, ?)`, leaseID, runID, taskPath, taskYAML, now, now); err != nil {
		return "", err
	}
	if _, err := s.execWithBusyRetry(`INSERT OR IGNORE INTO sessions
		(id, lease_id, run_id, workspace_host_path, runtime, parent_snapshot_id, status, startup_cold_ms, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'local', ?, 'running', 0, ?, ?)`,
		sessionID, leaseID, runID, workspacePath, opts.BaseSnapshotID, now, now); err != nil {
		return "", err
	}
	if _, err := s.execWithBusyRetry(`UPDATE sessions SET status = 'running', updated_at = ? WHERE id = ?`, now, sessionID); err != nil {
		return "", err
	}
	return sessionID, nil
}

func (s Service) execWithBusyRetry(query string, args ...any) (sql.Result, error) {
	deadline := time.Now().Add(2 * time.Second)
	var lastErr error
	for {
		result, err := s.DB.Exec(query, args...)
		if err == nil {
			return result, nil
		}
		lastErr = err
		if !isSQLiteBusy(err) || time.Now().After(deadline) {
			return nil, lastErr
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func isSQLiteBusy(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "database is locked") || strings.Contains(msg, "sqlite_busy")
}

func (s Service) runDockerAttempt(attemptID, toolCallID, workspacePath string, strategy Strategy, opts Options) Result {
	if opts.TaskPath == "" {
		return rejectedResult(attemptID, toolCallID, workspacePath, strategy, "docker rollout requires task path")
	}
	if opts.Driver == nil {
		return rejectedResult(attemptID, toolCallID, workspacePath, strategy, "docker rollout requires runtime driver")
	}
	ctrl := control.Service{DB: s.DB, Paths: opts.Paths, Driver: opts.Driver}
	sessionID, err := ctrl.CreateSessionFromWorkspace(control.WorkspaceSessionRequest{
		RunID:            opts.RunID,
		TaskPath:         opts.TaskPath,
		WorkspacePath:    workspacePath,
		ParentSnapshotID: opts.BaseSnapshotID,
		AttemptID:        attemptID,
	})
	if err != nil {
		return rejectedResult(attemptID, toolCallID, workspacePath, strategy, err.Error())
	}
	defer func() { _ = ctrl.RemoveSession(sessionID) }()
	var output bytes.Buffer
	start := time.Now()
	processID, execErr := ctrl.ExecStream(sessionID, []string{"sh", "-lc", strategy.Command}, &output, &output)
	wallMS := time.Since(start).Milliseconds()
	exitCode := 0
	status := "passed"
	if execErr != nil {
		status = "failed"
		exitCode = 1
		if processID != "" {
			_ = s.DB.QueryRow(`SELECT COALESCE(exit_code, 1) FROM processes WHERE id = ?`, processID).Scan(&exitCode)
		}
		if exitCode == 125 {
			status = "rejected"
		}
	}
	if processID != "" {
		var dbExit int
		if err := s.DB.QueryRow(`SELECT COALESCE(exit_code, ?) FROM processes WHERE id = ?`, exitCode, processID).Scan(&dbExit); err == nil {
			exitCode = dbExit
		}
		_, _ = s.DB.Exec(`UPDATE processes SET tool_call_id = ? WHERE id = ?`, toolCallID, processID)
		_, _ = s.DB.Exec(`UPDATE events SET tool_call_id = ? WHERE process_id = ?`, toolCallID, processID)
		var containerID, startedAt, endedAt string
		_ = s.DB.QueryRow(`SELECT COALESCE(s.container_id, ''), p.started_at, COALESCE(p.ended_at, '')
			FROM processes p JOIN sessions s ON p.session_id = s.id WHERE p.id = ?`, processID).Scan(&containerID, &startedAt, &endedAt)
		_, _ = correlation.RecordBinding(s.DB, correlation.Binding{
			RunID:         opts.RunID,
			SessionID:     sessionID,
			AttemptID:     attemptID,
			ToolCallID:    toolCallID,
			ProcessID:     processID,
			ContainerID:   containerID,
			StartedAt:     startedAt,
			EndedAt:       endedAt,
			BindingSource: "rollout_docker",
		})
	}
	score := scoreOutput(output.String(), strategy.ScoreParser, wallMS, exitCode)
	if exitCode != 0 {
		score = -1000.0 - float64(exitCode)
	}
	cost := float64(wallMS) / 1000.0 * 0.001
	result := Result{
		AttemptID:      attemptID,
		ToolCallID:     toolCallID,
		SessionID:      sessionID,
		ProcessID:      processID,
		WorkspacePath:  workspacePath,
		Strategy:       strategy.Name,
		Command:        strategy.Command,
		Status:         status,
		ExitCode:       exitCode,
		WallMS:         wallMS,
		OutputSummary:  summarize(output.String()),
		Score:          score,
		BudgetSeconds:  strategy.BudgetSeconds,
		ArtifactResult: strategy.ArtifactResult,
		CostEstimate:   cost,
		BurstStatus:    "runtime",
	}
	if execErr != nil && result.OutputSummary == "" {
		result.OutputSummary = execErr.Error()
	}
	result.RiskStatus = "clean"
	result.BudgetExceeded = budgetExceeded(result.WallMS, strategy.BudgetSeconds)
	if result.BudgetExceeded && result.Status == "passed" {
		result.Status = "budget_exceeded"
		result.Score -= 500
	}
	return s.captureArtifact(result, strategy)
}

func rejectedResult(attemptID, toolCallID, workspacePath string, strategy Strategy, reason string) Result {
	return Result{
		AttemptID:      attemptID,
		ToolCallID:     toolCallID,
		WorkspacePath:  workspacePath,
		Strategy:       strategy.Name,
		Command:        strategy.Command,
		Status:         "rejected",
		ExitCode:       125,
		OutputSummary:  reason,
		Score:          -2000,
		BudgetSeconds:  strategy.BudgetSeconds,
		ArtifactResult: strategy.ArtifactResult,
		RiskStatus:     "unknown",
		BurstStatus:    "rejected",
		BurstReason:    reason,
	}
}

func argsHash(command string) string {
	sum := sha256.Sum256([]byte(command))
	return hex.EncodeToString(sum[:])
}

func parseStrategies(raws []string) []Strategy {
	strategies := make([]Strategy, 0, len(raws))
	for i, raw := range raws {
		strategies = append(strategies, parseStrategy(raw, i))
	}
	return strategies
}

func parseStrategy(raw string, index int) Strategy {
	parts := strings.SplitN(raw, "::", 2)
	name := fmt.Sprintf("strategy-%d", index+1)
	command := strings.TrimSpace(raw)
	if len(parts) == 2 {
		name = strings.TrimSpace(parts[0])
		command = strings.TrimSpace(parts[1])
	}
	strategy := Strategy{Name: name, Command: command, BudgetSeconds: 0}
	fields := strings.Split(command, "::")
	if len(fields) > 1 {
		strategy.Command = strings.TrimSpace(fields[0])
		for _, field := range fields[1:] {
			key, value, ok := strings.Cut(field, "=")
			if !ok {
				continue
			}
			switch strings.TrimSpace(key) {
			case "budget":
				strategy.BudgetSeconds, _ = strconv.Atoi(strings.TrimSpace(value))
			case "score":
				strategy.ScoreParser = strings.TrimSpace(value)
			case "artifact":
				strategy.ArtifactResult = strings.TrimSpace(value)
			case "probe":
				strategy.ProbeCommand = strings.TrimSpace(value)
			}
		}
	}
	return strategy
}

func runAttempt(attemptID, workspacePath string, strategy Strategy) Result {
	start := time.Now()
	ctx := context.Background()
	cancel := func() {}
	if strategy.BudgetSeconds > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(strategy.BudgetSeconds)*time.Second)
	}
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-lc", strategy.Command)
	cmd.Dir = workspacePath
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	wallMS := time.Since(start).Milliseconds()
	exitCode := 0
	status := "passed"
	if err != nil {
		status = "failed"
		exitCode = 1
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
	}
	score := scoreOutput(output.String(), strategy.ScoreParser, wallMS, exitCode)
	if exitCode != 0 {
		score = -1000.0 - float64(exitCode)
	}
	cost := float64(wallMS) / 1000.0 * 0.001
	return Result{
		AttemptID:      attemptID,
		WorkspacePath:  workspacePath,
		Strategy:       strategy.Name,
		Command:        strategy.Command,
		Status:         status,
		ExitCode:       exitCode,
		WallMS:         wallMS,
		OutputSummary:  summarize(output.String()),
		Score:          score,
		BudgetSeconds:  strategy.BudgetSeconds,
		ArtifactResult: strategy.ArtifactResult,
		CostEstimate:   cost,
		RiskStatus:     "clean",
		BudgetExceeded: budgetExceeded(wallMS, strategy.BudgetSeconds),
	}
}

func (s Service) captureArtifact(result Result, strategy Strategy) Result {
	declared := strings.TrimSpace(strategy.ArtifactResult)
	if declared == "" || result.WorkspacePath == "" || result.Status == "pruned" {
		return result
	}
	artifactRoot := s.State.Paths.Artifacts
	if artifactRoot == "" {
		return result
	}
	source, err := safeWorkspacePath(result.WorkspacePath, declared)
	if err != nil {
		result.OutputSummary = appendSummary(result.OutputSummary, "artifact_error="+err.Error())
		return result
	}
	info, err := os.Stat(source)
	if err != nil {
		result.OutputSummary = appendSummary(result.OutputSummary, "artifact_missing="+declared)
		return result
	}
	if info.IsDir() {
		result.OutputSummary = appendSummary(result.OutputSummary, "artifact_error=directory_not_supported")
		return result
	}
	if err := os.MkdirAll(artifactRoot, 0o755); err != nil {
		result.OutputSummary = appendSummary(result.OutputSummary, "artifact_error="+err.Error())
		return result
	}
	name := filepath.Base(declared)
	target := filepath.Join(artifactRoot, result.AttemptID+"-"+name)
	if err := copyFile(source, target, info.Mode()); err != nil {
		result.OutputSummary = appendSummary(result.OutputSummary, "artifact_error="+err.Error())
		return result
	}
	result.ArtifactResult = target
	result.OutputSummary = appendSummary(result.OutputSummary, "artifact_exported="+target)
	return result
}

func safeWorkspacePath(workspace, rel string) (string, error) {
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("artifact path must be workspace-relative")
	}
	clean := filepath.Clean(rel)
	if clean == "." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean == ".." {
		return "", fmt.Errorf("artifact path escapes workspace")
	}
	return filepath.Join(workspace, clean), nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func scoreOutput(output, parser string, wallMS int64, exitCode int) float64 {
	if strings.HasPrefix(parser, "contains:") {
		needle := strings.TrimPrefix(parser, "contains:")
		if strings.Contains(output, needle) {
			return 1000.0 - float64(wallMS)/1000
		}
		return -100.0
	}
	if parser == "number" || strings.HasPrefix(parser, "number:") {
		value := strings.TrimSpace(output)
		score, err := strconv.ParseFloat(value, 64)
		if err == nil {
			return score
		}
	}
	return 1000.0 - float64(wallMS)/1000
}

func better(a, b Result) bool {
	if riskRank(a.RiskStatus) != riskRank(b.RiskStatus) {
		return riskRank(a.RiskStatus) > riskRank(b.RiskStatus)
	}
	if statusRank(a.Status) != statusRank(b.Status) {
		return statusRank(a.Status) > statusRank(b.Status)
	}
	if a.ExitCode == 0 && b.ExitCode != 0 {
		return true
	}
	if a.ExitCode != 0 && b.ExitCode == 0 {
		return false
	}
	if a.BudgetExceeded != b.BudgetExceeded {
		return !a.BudgetExceeded
	}
	if a.Score != b.Score {
		return a.Score > b.Score
	}
	if a.CostEstimate != b.CostEstimate {
		return a.CostEstimate < b.CostEstimate
	}
	return a.WallMS < b.WallMS
}

func statusRank(status string) int {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "passed":
		return 4
	case "budget_exceeded":
		return 3
	case "failed":
		return 2
	case "rejected":
		return 1
	default:
		return 0
	}
}

func riskRank(status string) int {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "clean", "allow":
		return 3
	case "unknown", "":
		return 2
	case "audit":
		return 1
	default:
		return 0
	}
}

func budgetExceeded(wallMS int64, budgetSeconds int) bool {
	return budgetSeconds > 0 && wallMS > int64(budgetSeconds)*1000
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func summarize(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.ReplaceAll(raw, "\n", " | ")
	if len(raw) > 240 {
		return raw[:240]
	}
	return raw
}

func appendSummary(current, addition string) string {
	addition = strings.TrimSpace(addition)
	if addition == "" {
		return summarize(current)
	}
	if strings.TrimSpace(current) == "" {
		return summarize(addition)
	}
	return summarize(current + " | " + addition)
}
