package record

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/ids"
	"github.com/byteyellow/agentprovenance/internal/security"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/substrate/state"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

type Service struct {
	DB    *sql.DB
	Paths store.Paths
	// Options carries the execution hardening policy; the zero value is the
	// strict (fail-closed) default: DefaultExecTimeout with scope cancellation,
	// shell interpreters refused, cwd confined to the workspace
	// root, minimal child environment. See the Options doc comment.
	Options   Options
	Lifecycle *Lifecycle
}

type Request struct {
	RunID            string   `json:"run_id"`
	Name             string   `json:"name"`
	Workdir          string   `json:"workdir"`
	Command          []string `json:"command"`
	SampleIntervalMS int64    `json:"sample_interval_ms"`
	PostRootGraceMS  int64    `json:"post_root_grace_ms"`
	// DisableSnapshot skips the pre-exec base-directory copy and the post-exec
	// file diff. `record` keeps it off (file diff is core zero-SDK evidence), but
	// `launch` turns it on: wrapping an interactive agent in a real repo would
	// otherwise copy the entire working tree (node_modules, build output, ...) on
	// every run, dominating startup and disk. On Linux the kernel sensor's
	// file_write events already capture what changed at higher fidelity.
	DisableSnapshot bool      `json:"disable_snapshot"`
	Stdin           io.Reader `json:"-"`
	Stdout          io.Writer `json:"-"`
	Stderr          io.Writer `json:"-"`
}

type Result struct {
	RunID            string                `json:"run_id"`
	RolloutID        string                `json:"rollout_id"`
	BaseSnapshotID   string                `json:"base_snapshot_id"`
	AttemptID        string                `json:"attempt_id"`
	SessionID        string                `json:"session_id"`
	ToolCallID       string                `json:"tool_call_id"`
	ProcessID        string                `json:"process_id"`
	Workdir          string                `json:"workdir"`
	Command          string                `json:"command"`
	ExitCode         int                   `json:"exit_code"`
	Status           string                `json:"status"`
	WallMS           int64                 `json:"wall_ms"`
	ChangedFiles     []string              `json:"changed_files"`
	RootPID          int64                 `json:"root_pid"`
	Observed         []ObservedProcess     `json:"observed"`
	OrphanPolicy     string                `json:"orphan_policy"`
	SampleIntervalMS int64                 `json:"sample_interval_ms"`
	PostRootGraceMS  int64                 `json:"post_root_grace_ms"`
	CWD              string                `json:"cwd"`
	StartedAt        string                `json:"started_at"`
	EndedAt          string                `json:"ended_at"`
	FailureReason    string                `json:"failure_reason"`
	ArtifactCapture  ArtifactCaptureReport `json:"artifact_capture"`
	Scope            *ExecutionScope       `json:"execution_scope,omitempty"`
	EndEventID       string                `json:"end_event_id,omitempty"`
	Stop             *StopReport           `json:"stop_report,omitempty"`
	ScopeObservation *ScopeObservation     `json:"scope_observation,omitempty"`
}

type ObservedProcess struct {
	PID          int64  `json:"pid"`
	PPID         int64  `json:"ppid"`
	Command      string `json:"command"`
	FirstSeen    string `json:"first_seen"`
	LastSeen     string `json:"last_seen"`
	OutlivedRoot bool   `json:"outlived_root"`
}

func (s Service) Run(req Request) (Result, error) {
	return s.RunContext(context.Background(), req)
}

// RunContext accepts an execution lifetime owned by the caller. HTTP request
// contexts must not be used for durable remote jobs; their executor owns it.
func (s Service) RunContext(ctx context.Context, req Request) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if len(req.Command) == 0 {
		return Result{}, fmt.Errorf("command is required after --")
	}
	opts := s.Options
	if opts.Foreground && opts.Timeout >= 0 {
		return Result{}, fmt.Errorf("record policy: foreground execution requires an unbounded timeout")
	}
	// Policy preflight (C2 hardening): refuse shell interpreters and confine
	// the working directory BEFORE any snapshot, graph row, or workspace
	// directory is created, so a refused request leaves zero side effects.
	if err := checkShellPolicy(req.Command, opts.AllowShell); err != nil {
		return Result{}, err
	}
	if req.RunID == "" {
		req.RunID = ids.New("run")
	}
	if req.Name == "" {
		req.Name = "record"
	}
	absWorkdir, err := s.resolveWorkdir(req.Workdir, req.RunID, opts)
	if err != nil {
		return Result{}, err
	}
	sampleInterval := time.Duration(req.SampleIntervalMS) * time.Millisecond
	if sampleInterval <= 0 {
		sampleInterval = 25 * time.Millisecond
	}
	postRootGrace := time.Duration(req.PostRootGraceMS) * time.Millisecond
	if postRootGrace <= 0 {
		postRootGrace = 250 * time.Millisecond
	}
	commandText := strings.Join(req.Command, " ")
	now := time.Now().UTC().Format(time.RFC3339Nano)

	baseSnapshotID := ids.New("snap")
	baseDir := filepath.Join(s.Paths.Snapshots, baseSnapshotID)
	// Exclude .git/.agentprov from the base snapshot, matching the diff path's
	// ignoredPath. This keeps the snapshot clean and (with the dst-subtree guard
	// in CopyDirFiltered) prevents self-recursion when the .agentprov data dir
	// lives inside the workdir being recorded.
	//
	// DisableSnapshot skips the copy+manifest entirely (an empty base dir stands
	// in so the snapshot row and its FKs stay valid); the post-exec diff is
	// skipped in lockstep below. See Request.DisableSnapshot.
	var baseManifest state.Manifest
	if req.DisableSnapshot {
		if err := os.MkdirAll(baseDir, 0o755); err != nil {
			return Result{}, err
		}
		baseManifest, err = state.BuildManifest(baseDir)
		if err != nil {
			return Result{}, err
		}
	} else {
		if err := state.CopyDirFiltered(absWorkdir, baseDir, ignoredPath); err != nil {
			return Result{}, err
		}
		baseManifest, err = state.BuildManifest(baseDir)
		if err != nil {
			return Result{}, err
		}
	}
	_, err = s.DB.Exec(`INSERT INTO snapshots
		(id, name, kind, source, path, manifest_hash, file_count, bytes, snapshot_semantic_type, snapshot_physical_type, logical_bytes, physical_bytes, dirty_bytes_estimate, inode_estimate, storage_amplification_ratio, status, created_at)
		VALUES (?, ?, 'ready', 'record', ?, ?, ?, ?, 'directory', 'copy', ?, ?, ?, ?, 1, 'ready', ?)`,
		baseSnapshotID, req.Name+"-base", baseDir, baseManifest.Hash, baseManifest.Files, baseManifest.Bytes, baseManifest.Bytes, baseManifest.Bytes, baseManifest.Bytes, baseManifest.Files, now)
	if err != nil {
		return Result{}, err
	}

	rolloutID := ids.New("rollout")
	attemptID := ids.New("attempt")
	sessionID := "record-" + attemptID
	leaseID := "lease-" + attemptID
	toolCallID := ids.New("tool")
	processID := ids.New("proc")
	_, err = s.DB.Exec(`INSERT INTO leases (id, run_id, task_path, task_yaml, status, created_at, updated_at)
		VALUES (?, ?, ?, '{}', 'allocated', ?, ?)`, leaseID, req.RunID, "record:"+absWorkdir, now, now)
	if err != nil {
		return Result{}, err
	}
	_, err = s.DB.Exec(`INSERT INTO sessions
		(id, lease_id, run_id, container_id, workspace_host_path, runtime, parent_snapshot_id, status, startup_cold_ms, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, 'record', ?, 'running', 0, ?, ?)`,
		sessionID, leaseID, req.RunID, "agentprov-record-"+attemptID, absWorkdir, baseSnapshotID, now, now)
	if err != nil {
		return Result{}, err
	}
	_, err = s.DB.Exec(`INSERT INTO rollouts
		(id, run_id, task_path, base_snapshot_id, status, fanout, risk_status, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'running', 1, 'pending', ?, ?)`,
		rolloutID, req.RunID, "record:"+absWorkdir, baseSnapshotID, now, now)
	if err != nil {
		return Result{}, err
	}
	_, err = s.DB.Exec(`INSERT INTO fork_attempts
		(id, rollout_id, tool_call_id, snapshot_id, workspace_path, fork_ms, strategy, command, status, risk_status, created_at)
		VALUES (?, ?, ?, ?, ?, 0, 'zero-sdk-record', ?, 'running', 'clean', ?)`,
		attemptID, rolloutID, toolCallID, baseSnapshotID, absWorkdir, commandText, now)
	if err != nil {
		return Result{}, err
	}
	_, err = s.DB.Exec(`INSERT INTO tool_calls
		(id, run_id, rollout_id, attempt_id, session_id, command, args_hash, status, policy_decision, created_at, started_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'running', 'allow', ?, ?)`,
		toolCallID, req.RunID, rolloutID, attemptID, sessionID, commandText, argsHash(commandText), now, now)
	if err != nil {
		return Result{}, err
	}
	_, err = s.DB.Exec(`INSERT INTO processes
		(id, session_id, tool_call_id, command, status, started_at)
		VALUES (?, ?, ?, ?, 'running', ?)`, processID, sessionID, toolCallID, commandText, now)
	if err != nil {
		return Result{}, err
	}
	if err := s.insertGraphEdges(req.RunID, rolloutID, baseSnapshotID, attemptID, sessionID, toolCallID, processID, now); err != nil {
		return Result{}, errors.Join(err, s.markFailed(req.RunID, rolloutID, attemptID, sessionID, toolCallID, processID, err.Error()))
	}

	// The execution owner supplies cancellation; timeout uses the same stop path.
	execTimeout := opts.Timeout
	if execTimeout == 0 {
		execTimeout = DefaultExecTimeout
	}
	execCtx := ctx
	if execTimeout > 0 {
		var cancelTimeout func()
		execCtx, cancelTimeout = context.WithTimeout(execCtx, execTimeout)
		defer cancelTimeout()
	}
	cmd := exec.CommandContext(execCtx, req.Command[0], req.Command[1:]...)
	cmd.Dir = absWorkdir
	// Minimal environment: never hand the daemon's full environment (API keys,
	// auth tokens, service credentials) to a recorded child unless the caller
	// explicitly opted in.
	cmd.Env = childEnv(opts.InheritFullEnv)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if req.Stdout != nil {
		cmd.Stdout = req.Stdout
	}
	if req.Stderr != nil {
		cmd.Stderr = req.Stderr
	}
	cmd.Stdin = req.Stdin
	group := applyExecutionAttrs(cmd, opts.Foreground)
	// Bound the post-exit I/O drain so grandchildren holding the inherited
	// pipes cannot keep Wait blocked long after the recorded root is gone.
	cmd.WaitDelay = 2 * time.Second
	// The child is born in its own scope, which is also the stop boundary.
	cgroup := prepareScopeCgroup(cmd, attemptID)
	defer cgroup.cleanup()
	scopeCgroupID := cgroup.id
	stop := executionStop{cmd: cmd, cgroup: cgroup, group: group}
	cmd.Cancel = stop.signal
	start := time.Now()
	startedAt := start.UTC().Format(time.RFC3339Nano)
	// Publish the scope before the child can emit its first syscall. A live
	// collector may otherwise drain exec/open/connect before cmd.Start returns
	// and permanently drop them as uncorrelated (especially on a quiet node).
	bindingID, err := correlation.RecordBinding(s.DB, correlation.Binding{
		RunID: req.RunID, SessionID: sessionID, AttemptID: attemptID,
		ToolCallID: toolCallID, ProcessID: processID,
		ContainerID: "agentprov-record-" + attemptID, CgroupID: scopeCgroupID,
		StartedAt: startedAt, BindingSource: "zero_sdk_record",
	})
	if err != nil {
		return Result{}, errors.Join(fmt.Errorf("publish execution scope before launch: %w", err),
			s.markFailed(req.RunID, rolloutID, attemptID, sessionID, toolCallID, processID, err.Error()))
	}
	scopeKind := "cgroup"
	if strings.HasPrefix(scopeCgroupID, "agentprov-record-") {
		scopeKind = "logical_process_scope"
	}
	scope := ExecutionScope{RunID: req.RunID, RolloutID: rolloutID, AttemptID: attemptID, SessionID: sessionID,
		ToolCallID: toolCallID, ProcessID: processID, BaseSnapshotID: baseSnapshotID, BindingID: bindingID,
		CgroupID: scopeCgroupID, ScopeKind: scopeKind, Workdir: absWorkdir, StartedAt: startedAt}
	if s.Lifecycle != nil && s.Lifecycle.Prepared != nil {
		if err := s.Lifecycle.Prepared(scope); err != nil {
			return Result{RunID: req.RunID, Scope: &scope}, errors.Join(err,
				s.markFailed(req.RunID, rolloutID, attemptID, sessionID, toolCallID, processID, err.Error()),
				correlation.CloseBindingByID(s.DB, bindingID, time.Now().UTC().Format(time.RFC3339Nano)))
		}
	}
	if err := cmd.Start(); err != nil {
		endedAt := time.Now().UTC().Format(time.RFC3339Nano)
		status, exitCode := "failed", 125
		if errors.Is(execCtx.Err(), context.Canceled) {
			status, exitCode = "cancelled", 130
		} else if errors.Is(execCtx.Err(), context.DeadlineExceeded) {
			exitCode = 124
		}
		persistErr := errors.Join(s.markStopped(req.RunID, rolloutID, attemptID, sessionID, toolCallID, processID, status, exitCode, err.Error()),
			correlation.CloseBindingByID(s.DB, bindingID, endedAt))
		artifactCapture := newArtifactCaptureReport()
		if !req.DisableSnapshot {
			artifactCapture.Status, artifactCapture.Reason = "failed", "File snapshot capture was not performed because the command could not start."
			artifactCapture.Issues = append(artifactCapture.Issues, "command_start_failed")
		}
		if saveErr := s.persistArtifactReport(req.RunID, rolloutID, &artifactCapture); saveErr != nil {
			artifactCapture.Status = "failed"
			artifactCapture.Issues = append(artifactCapture.Issues, "report_storage_failed")
			persistErr = errors.Join(persistErr, saveErr)
		}
		return Result{
			RunID:           req.RunID,
			RolloutID:       rolloutID,
			BaseSnapshotID:  baseSnapshotID,
			AttemptID:       attemptID,
			SessionID:       sessionID,
			ToolCallID:      toolCallID,
			ProcessID:       processID,
			Workdir:         absWorkdir,
			Command:         commandText,
			ExitCode:        exitCode,
			Status:          status,
			WallMS:          time.Since(start).Milliseconds(),
			CWD:             absWorkdir,
			StartedAt:       startedAt,
			EndedAt:         endedAt,
			FailureReason:   err.Error(),
			ArtifactCapture: artifactCapture,
			Scope:           &scope,
		}, persistErr
	}
	pid := int64(cmd.Process.Pid)
	scope.RootPID = pid
	// Start observing immediately; post-spawn database writes can outlast a
	// short-lived child, especially while another collector holds the writer.
	stopSampler := make(chan struct{})
	samplerDone := make(chan []ObservedProcess, 1)
	go sampleProcessTree(pid, sampleInterval, stopSampler, samplerDone)
	abortStarted := func(cause error) (Result, error) {
		_ = stop.signal()
		_ = cmd.Wait()
		stopReport := stop.finish()
		close(stopSampler)
		<-samplerDone
		endedAt := time.Now().UTC().Format(time.RFC3339Nano)
		return Result{RunID: req.RunID, RootPID: pid, Scope: &scope, EndedAt: endedAt, Stop: stopReport,
				ScopeObservation: cgroup.observe(scope)}, errors.Join(cause,
				s.markFailed(req.RunID, rolloutID, attemptID, sessionID, toolCallID, processID, cause.Error()),
				correlation.CloseBindingByID(s.DB, bindingID, endedAt))
	}
	scope.StartEventID, err = s.persistStart(scope, commandText)
	if err != nil {
		return abortStarted(fmt.Errorf("persist execution start: %w", err))
	}
	if s.Lifecycle != nil && s.Lifecycle.Started != nil {
		if err := s.Lifecycle.Started(scope); err != nil {
			return abortStarted(err)
		}
	}

	err = cmd.Wait()
	timedOut := errors.Is(execCtx.Err(), context.DeadlineExceeded)
	cancelled := errors.Is(execCtx.Err(), context.Canceled)
	// Wait may win the race with context cancellation after the root exits.
	// The open cgroup is still an owned target; a reaped PID is not.
	if (timedOut || cancelled) && cgroup.kill != nil {
		_ = stop.signal()
	}
	stopReport := stop.finish()
	postRootGraceStarted := time.Now()
	time.Sleep(postRootGrace)
	close(stopSampler)
	observed := markOutlivedRoot(<-samplerDone, postRootGraceStarted.UTC().Format(time.RFC3339Nano))
	wallMS := time.Since(start).Milliseconds()
	exitCode := 0
	status := "passed"
	failureReason := ""
	switch {
	case cancelled:
		status = "cancelled"
		exitCode = 130
		failureReason = "execution cancelled; the recorded command was terminated"
	case timedOut:
		status = "failed"
		exitCode = 124
		failureReason = fmt.Sprintf("execution timed out after %s; the recorded command was terminated", execTimeout)
	case err != nil && !errors.Is(err, exec.ErrWaitDelay):
		// ErrWaitDelay only means grandchildren held the pipes past WaitDelay;
		// the root process itself already exited and its status is authoritative.
		status = "failed"
		exitCode = 1
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = commandExitCode(exitErr)
		}
	}
	endedAt := time.Now().UTC().Format(time.RFC3339Nano)
	for _, proc := range observed {
		_, _ = correlation.RecordBinding(s.DB, correlation.Binding{
			RunID:      req.RunID,
			SessionID:  sessionID,
			AttemptID:  attemptID,
			ToolCallID: toolCallID,
			ProcessID:  processID,
			// Polling establishes a PID window, not ownership of every process
			// in its cgroup. Native lifetime bindings survive actual migration.
			RootPID:       pid,
			PID:           proc.PID,
			StartedAt:     proc.FirstSeen,
			EndedAt:       proc.LastSeen,
			BindingSource: "zero_sdk_record_descendant",
			Confidence:    0.9,
		})
		payload, _ := json.Marshal(observedProcessPayload(proc, pid, absWorkdir, "root_pid_descendants+cwd+time_window"))
		_, _ = telemetry.IngestFiltered(s.DB, telemetry.IngestEvent{
			RunID:       req.RunID,
			RolloutID:   rolloutID,
			AttemptID:   attemptID,
			SessionID:   sessionID,
			ToolCallID:  toolCallID,
			ProcessID:   processID,
			SnapshotID:  baseSnapshotID,
			RawEventID:  fmt.Sprintf("record-process-%d", proc.PID),
			ContainerID: "agentprov-record-" + attemptID,
			CgroupID:    scopeCgroupID,
			PID:         proc.PID,
			TGID:        proc.PID,
			PPID:        proc.PPID,
			Timestamp:   proc.FirstSeen,
			Source:      "record_process_sample",
			EventType:   "process_observed",
			Payload:     string(payload),
		})
		if proc.OutlivedRoot {
			_ = s.persistOrphanDecision(req.RunID, rolloutID, attemptID, sessionID, toolCallID, processID, proc, string(payload))
		}
	}
	var changed []string
	artifactCapture := newArtifactCaptureReport()
	if !req.DisableSnapshot {
		var diffErr error
		changed, diffErr = changedFiles(baseDir, absWorkdir)
		if diffErr != nil {
			changed = append(changed, "diff_error:"+diffErr.Error())
			artifactCapture.Status, artifactCapture.Reason = "failed", "Changed files could not be enumerated."
		} else {
			artifactCapture = s.captureArtifacts(req.RunID, rolloutID, absWorkdir, changed)
		}
	}
	artifactByPath := make(map[string]CapturedArtifact, len(artifactCapture.Files))
	for _, item := range artifactCapture.Files {
		artifactByPath[item.Path] = item
	}
	for _, path := range changed {
		if strings.HasPrefix(path, "diff_error:") {
			continue
		}
		payload := map[string]any{"path": path, "op": "record_diff", "mode": "zero_sdk"}
		if item, ok := artifactByPath[path]; ok {
			payload["artifact_ref"], payload["content_state"] = item.Ref, item.ContentState
		} else {
			payload["content_state"] = "collection_limit"
		}
		raw, _ := json.Marshal(payload)
		_, ingestErr := telemetry.IngestFiltered(s.DB, telemetry.IngestEvent{
			RunID:       req.RunID,
			RolloutID:   rolloutID,
			AttemptID:   attemptID,
			SessionID:   sessionID,
			ToolCallID:  toolCallID,
			ProcessID:   processID,
			SnapshotID:  baseSnapshotID,
			RawEventID:  "record-file-" + path,
			ContainerID: "agentprov-record-" + attemptID,
			CgroupID:    scopeCgroupID,
			PID:         pid,
			TGID:        pid,
			PPID:        int64(os.Getpid()),
			Timestamp:   endedAt,
			Source:      "record_file_diff",
			EventType:   "file_write",
			Payload:     string(raw),
		})
		if ingestErr != nil && len(artifactCapture.Issues) == 0 {
			artifactCapture.Issues = append(artifactCapture.Issues, "file_event_write_failed")
			artifactCapture.Status = "partial"
		}
	}
	if err := s.persistArtifactReport(req.RunID, rolloutID, &artifactCapture); err != nil {
		artifactCapture.Status = "failed"
		artifactCapture.Issues = append(artifactCapture.Issues, "report_storage_failed")
	}
	if (artifactCapture.Status == "partial" || artifactCapture.Status == "failed") && req.Stderr != nil {
		fmt.Fprintf(req.Stderr, "record: artifact capture %s (stored=%d, omitted=%d, failed=%d)\n", artifactCapture.Status, artifactCapture.Stored, artifactCapture.Omitted, artifactCapture.Failed)
	}
	result := Result{
		RunID:            req.RunID,
		RolloutID:        rolloutID,
		BaseSnapshotID:   baseSnapshotID,
		AttemptID:        attemptID,
		SessionID:        sessionID,
		ToolCallID:       toolCallID,
		ProcessID:        processID,
		Workdir:          absWorkdir,
		Command:          commandText,
		ExitCode:         exitCode,
		Status:           status,
		WallMS:           wallMS,
		ChangedFiles:     changed,
		RootPID:          pid,
		Observed:         observed,
		OrphanPolicy:     "observe_only",
		SampleIntervalMS: sampleInterval.Milliseconds(),
		PostRootGraceMS:  postRootGrace.Milliseconds(),
		CWD:              absWorkdir,
		StartedAt:        startedAt,
		EndedAt:          endedAt,
		FailureReason:    failureReason,
		ArtifactCapture:  artifactCapture,
		Scope:            &scope,
		Stop:             stopReport,
		ScopeObservation: cgroup.observe(scope),
	}
	result.EndEventID, err = s.persistCompletion(result, timedOut, cancelled)
	if err != nil {
		return result, fmt.Errorf("persist execution completion: %w", err)
	}
	if s.Lifecycle != nil && s.Lifecycle.Completed != nil {
		if err := s.Lifecycle.Completed(result); err != nil {
			return result, fmt.Errorf("execution completion hook: %w", err)
		}
	}
	return result, nil
}

func observedProcessPayload(proc ObservedProcess, rootPID int64, cwd, boundary string) map[string]any {
	return map[string]any{
		"pid":             proc.PID,
		"ppid":            proc.PPID,
		"root_pid":        rootPID,
		"command":         proc.Command,
		"first_seen":      proc.FirstSeen,
		"last_seen":       proc.LastSeen,
		"outlived_root":   proc.OutlivedRoot,
		"cwd":             cwd,
		"scope_boundary":  boundary,
		"correlation_key": "pid+root_pid+cwd+time_window",
		"mode":            "zero_sdk",
	}
}

func (s Service) persistOrphanDecision(runID, rolloutID, attemptID, sessionID, toolCallID, processID string, proc ObservedProcess, payload string) error {
	record, err := security.PersistDecision(s.DB, security.Event{
		Source:     "zero_sdk_record",
		EventType:  "abnormal_process_tree",
		RunID:      runID,
		SessionID:  sessionID,
		ToolCallID: toolCallID,
		ProcessID:  processID,
		Args:       []string{proc.Command},
	}, payload, security.Decision{
		RuleID:   "zero_sdk_orphan_observe_only",
		Decision: "audit",
		Reason:   fmt.Sprintf("observed descendant pid %d outlived root; policy=observe_only", proc.PID),
	})
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, _ = s.DB.Exec(`INSERT INTO evidence_events
		(id, run_id, rollout_id, attempt_id, session_id, tool_call_id, event_type, priority, payload, status, created_at, processed_at)
		VALUES (?, ?, ?, ?, ?, ?, 'orphan_lifecycle_decision', 'normal', ?, 'processed', ?, ?)`,
		ids.New("evidence"), runID, rolloutID, attemptID, sessionID, toolCallID,
		fmt.Sprintf(`{"policy_decision_id":%q,"rule_id":"zero_sdk_orphan_observe_only","decision":"audit","action":"observe_only","pid":%d,"payload":%s}`, record.ID, proc.PID, payload),
		now, now)
	return nil
}

func markOutlivedRoot(procs []ObservedProcess, rootEndedAt string) []ObservedProcess {
	table, _ := processTable()
	alive := map[int64]bool{}
	for _, proc := range table {
		alive[proc.PID] = true
	}
	for i := range procs {
		if procs[i].LastSeen >= rootEndedAt || alive[procs[i].PID] {
			procs[i].OutlivedRoot = true
		}
	}
	return procs
}

func sampleProcessTree(rootPID int64, interval time.Duration, stop <-chan struct{}, done chan<- []ObservedProcess) {
	seen := map[int64]ObservedProcess{}
	var mu sync.Mutex
	record := func() {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		procs, err := processTable()
		if err != nil {
			return
		}
		descendants := descendantsOf(rootPID, procs)
		mu.Lock()
		defer mu.Unlock()
		for _, proc := range descendants {
			if proc.PID == rootPID {
				continue
			}
			prev, ok := seen[proc.PID]
			if !ok {
				proc.FirstSeen = now
				proc.LastSeen = now
				seen[proc.PID] = proc
				continue
			}
			prev.PPID = proc.PPID
			prev.Command = proc.Command
			prev.LastSeen = now
			seen[proc.PID] = prev
		}
	}
	record()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			record()
		case <-stop:
			record()
			out := make([]ObservedProcess, 0, len(seen))
			for _, proc := range seen {
				out = append(out, proc)
			}
			sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
			done <- out
			return
		}
	}
}

func processTable() ([]ObservedProcess, error) {
	out, err := exec.Command("ps", "-Ao", "pid=,ppid=,command=").Output()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(out), "\n")
	var procs []ObservedProcess
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		var pid, ppid int64
		if _, err := fmt.Sscanf(fields[0], "%d", &pid); err != nil {
			continue
		}
		if _, err := fmt.Sscanf(fields[1], "%d", &ppid); err != nil {
			continue
		}
		command := ""
		if len(fields) > 2 {
			command = strings.Join(fields[2:], " ")
		}
		procs = append(procs, ObservedProcess{PID: pid, PPID: ppid, Command: command})
	}
	return procs, nil
}

func descendantsOf(rootPID int64, procs []ObservedProcess) []ObservedProcess {
	children := map[int64][]ObservedProcess{}
	for _, proc := range procs {
		children[proc.PPID] = append(children[proc.PPID], proc)
	}
	var out []ObservedProcess
	queue := []int64{rootPID}
	seen := map[int64]bool{rootPID: true}
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		for _, child := range children[parent] {
			if seen[child.PID] {
				continue
			}
			seen[child.PID] = true
			out = append(out, child)
			queue = append(queue, child.PID)
		}
	}
	return out
}

func (s Service) insertGraphEdges(runID, rolloutID, snapshotID, attemptID, sessionID, toolCallID, processID, createdAt string) error {
	edges := [][3]string{
		{rolloutID, attemptID, "rollout_attempt"},
		{snapshotID, attemptID, "snapshot_attempt"},
		{attemptID, toolCallID, "attempt_tool_call"},
		{attemptID, sessionID, "attempt_session"},
		{toolCallID, sessionID, "tool_call_session"},
		{toolCallID, processID, "tool_call_process"},
	}
	return store.WithWriteTx(context.Background(), s.DB, func(tx *sql.Tx) error {
		for _, edge := range edges {
			if _, err := tx.Exec(`INSERT INTO graph_edges (id, run_id, rollout_id, from_id, to_id, edge_type, source_event_id, created_at)
			VALUES (?, ?, ?, ?, ?, ?, 'record', ?)`,
				ids.New("edge"), runID, rolloutID, edge[0], edge[1], edge[2], createdAt); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s Service) markFailed(runID, rolloutID, attemptID, sessionID, toolCallID, processID, reason string) error {
	return s.markStopped(runID, rolloutID, attemptID, sessionID, toolCallID, processID, "failed", 125, reason)
}

func (s Service) markStopped(runID, rolloutID, attemptID, sessionID, toolCallID, processID, status string, exitCode int, reason string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	return store.WithWriteTx(context.Background(), s.DB, func(tx *sql.Tx) error {
		for _, update := range []struct {
			sql  string
			args []any
		}{
			{`UPDATE processes SET status=?,exit_code=?,ended_at=? WHERE id=?`, []any{status, exitCode, now, processID}},
			{`UPDATE sessions SET status='stopped',updated_at=? WHERE id=?`, []any{now, sessionID}},
			{`UPDATE tool_calls SET status=?,exit_code=?,result_ref=?,ended_at=? WHERE id=?`, []any{status, exitCode, reason, now, toolCallID}},
			{`UPDATE fork_attempts SET status=?,exit_code=?,output_summary=? WHERE id=?`, []any{status, exitCode, reason, attemptID}},
			{`UPDATE rollouts SET status=?,updated_at=? WHERE id=?`, []any{status, now, rolloutID}},
		} {
			if err := updateOne(tx, update.sql, update.args...); err != nil {
				return err
			}
		}
		_, err := tx.Exec(`INSERT INTO events (id, run_id, session_id, tool_call_id, process_id, source, event_type, payload, created_at)
		VALUES (?, ?, ?, ?, ?, 'record', 'exec_error', ?, ?)`,
			ids.New("evt"), runID, sessionID, toolCallID, processID, fmt.Sprintf(`{"reason":%q}`, reason), now)
		return err
	})
}

func changedFiles(baseDir, workdir string) ([]string, error) {
	base, err := state.BuildFileManifest(baseDir)
	if err != nil {
		return nil, err
	}
	current, err := state.BuildFileManifest(workdir)
	if err != nil {
		return nil, err
	}
	changedSet := map[string]bool{}
	baseByPath := map[string]state.FileEntry{}
	for _, entry := range base {
		baseByPath[entry.Path] = entry
	}
	currentByPath := map[string]state.FileEntry{}
	for _, entry := range current {
		currentByPath[entry.Path] = entry
	}
	for path, entry := range currentByPath {
		if ignoredPath(path) {
			continue
		}
		if before, ok := baseByPath[path]; !ok || before.Hash != entry.Hash {
			changedSet[path] = true
		}
	}
	for path := range baseByPath {
		if ignoredPath(path) {
			continue
		}
		if _, ok := currentByPath[path]; !ok {
			changedSet[path] = true
		}
	}
	changed := make([]string, 0, len(changedSet))
	for path := range changedSet {
		changed = append(changed, path)
	}
	sort.Strings(changed)
	return changed, nil
}

func ignoredPath(path string) bool {
	return path == ".git" || strings.HasPrefix(path, ".git/") ||
		path == ".agentprov" || strings.HasPrefix(path, ".agentprov") ||
		strings.HasPrefix(path, "agentprov.db")
}

func argsHash(command string) string {
	sum := sha256.Sum256([]byte(command))
	return hex.EncodeToString(sum[:])
}

func processStatus(status string) string {
	if status == "passed" {
		return "exited"
	}
	return status
}

func score(exitCode int, wallMS int64) float64 {
	if exitCode != 0 {
		return -1000 - float64(exitCode)
	}
	return 1000 - float64(wallMS)/1000
}
