package provenance

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/store"
)

type ObjectStore struct {
	DB    *sql.DB
	Paths store.Paths
}

type MaterializeResult struct {
	RunID       string
	ObjectRoot  string
	ObjectCount int
	RootHashes  []string
}

type provenanceObject struct {
	Schema    string         `json:"schema"`
	Type      string         `json:"type"`
	SourceID  string         `json:"source_id"`
	RunID     string         `json:"run_id,omitempty"`
	RolloutID string         `json:"rollout_id,omitempty"`
	Parents   []string       `json:"parents,omitempty"`
	Refs      map[string]any `json:"refs,omitempty"`
	Payload   map[string]any `json:"payload,omitempty"`
}

func (s ObjectStore) MaterializeRun(runID string) (MaterializeResult, error) {
	if runID == "" {
		return MaterializeResult{}, fmt.Errorf("run_id is required")
	}
	if s.DB == nil {
		return MaterializeResult{}, fmt.Errorf("database is required")
	}
	if s.Paths.Provenance == "" {
		s.Paths.Provenance = filepath.Join(s.Paths.Root, "provenance")
	}
	if err := os.MkdirAll(objectRoot(s.Paths), 0o755); err != nil {
		return MaterializeResult{}, err
	}
	ctx := materializeContext{store: s, runID: runID, refHash: map[string]string{}}
	if err := ctx.materializeSnapshots(); err != nil {
		return MaterializeResult{}, err
	}
	if err := ctx.materializeRollouts(); err != nil {
		return MaterializeResult{}, err
	}
	if err := ctx.materializeAttempts(); err != nil {
		return MaterializeResult{}, err
	}
	if err := ctx.materializeToolCalls(); err != nil {
		return MaterializeResult{}, err
	}
	if err := ctx.materializeProcesses(); err != nil {
		return MaterializeResult{}, err
	}
	if err := ctx.materializeArtifacts(); err != nil {
		return MaterializeResult{}, err
	}
	if err := ctx.materializePromotions(); err != nil {
		return MaterializeResult{}, err
	}
	if err := ctx.materializeEvidence(); err != nil {
		return MaterializeResult{}, err
	}
	if err := ctx.materializeEvents(); err != nil {
		return MaterializeResult{}, err
	}
	if err := ctx.materializePolicyDecisions(); err != nil {
		return MaterializeResult{}, err
	}
	if err := ctx.materializeCosts(); err != nil {
		return MaterializeResult{}, err
	}
	sort.Strings(ctx.rootHashes)
	return MaterializeResult{
		RunID:       runID,
		ObjectRoot:  objectRoot(s.Paths),
		ObjectCount: ctx.objectCount,
		RootHashes:  ctx.rootHashes,
	}, nil
}

func PrintMaterializeResult(out io.Writer, result MaterializeResult) {
	fmt.Fprintf(out, "run=%s objects=%d object_root=%s\n", result.RunID, result.ObjectCount, result.ObjectRoot)
	for _, hash := range result.RootHashes {
		fmt.Fprintf(out, "root=%s\n", hash)
	}
}

type materializeContext struct {
	store       ObjectStore
	runID       string
	refHash     map[string]string
	objectCount int
	rootHashes  []string
}

func objectRoot(paths store.Paths) string {
	return filepath.Join(paths.Provenance, "objects", "sha256")
}

func (c *materializeContext) put(obj provenanceObject) (string, error) {
	obj.Schema = "agentprov.provenance.object.v1"
	if obj.RunID == "" {
		obj.RunID = c.runID
	}
	if obj.Refs == nil {
		obj.Refs = map[string]any{}
	}
	if obj.Payload == nil {
		obj.Payload = map[string]any{}
	}
	sort.Strings(obj.Parents)
	raw, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	hash := "sha256:" + hex.EncodeToString(sum[:])
	path := c.objectPath(hash)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return "", err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = c.store.DB.Exec(`INSERT OR REPLACE INTO provenance_objects
		(hash, object_type, source_id, run_id, rollout_id, parent_hashes, path, size_bytes, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		hash, obj.Type, obj.SourceID, obj.RunID, obj.RolloutID, strings.Join(obj.Parents, ","), path, len(raw), now)
	if err != nil {
		return "", err
	}
	c.refHash[obj.Type+"/"+obj.SourceID] = hash
	c.objectCount++
	return hash, nil
}

func (c *materializeContext) objectPath(hash string) string {
	clean := strings.TrimPrefix(hash, "sha256:")
	prefix := clean
	if len(prefix) > 2 {
		prefix = prefix[:2]
	}
	return filepath.Join(objectRoot(c.store.Paths), prefix, clean+".json")
}

func (c *materializeContext) parent(keys ...string) []string {
	parents := []string{}
	seen := map[string]bool{}
	for _, key := range keys {
		if key == "" {
			continue
		}
		hash := c.refHash[key]
		if hash == "" || seen[hash] {
			continue
		}
		seen[hash] = true
		parents = append(parents, hash)
	}
	sort.Strings(parents)
	return parents
}

func (c *materializeContext) materializeSnapshots() error {
	rows, err := c.store.DB.Query(`SELECT DISTINCT sn.id, COALESCE(sn.name, ''), COALESCE(sn.parent_id, ''), sn.kind, sn.source, sn.path,
			sn.manifest_hash, sn.file_count, sn.bytes, sn.status, COALESCE(sn.tainted, 0), sn.created_at
		FROM snapshots sn
		WHERE sn.id IN (SELECT base_snapshot_id FROM rollouts WHERE run_id = ?)
		   OR sn.id IN (SELECT a.snapshot_id FROM fork_attempts a JOIN rollouts r ON a.rollout_id = r.id WHERE r.run_id = ?)
		   OR sn.session_id IN (SELECT id FROM sessions WHERE run_id = ?)
		ORDER BY sn.created_at ASC`, c.runID, c.runID, c.runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, name, parentID, kind, source, path, manifestHash, status, createdAt string
		var files, bytes int64
		var tainted int
		if err := rows.Scan(&id, &name, &parentID, &kind, &source, &path, &manifestHash, &files, &bytes, &status, &tainted, &createdAt); err != nil {
			return err
		}
		_, err := c.put(provenanceObject{
			Type:     "snapshot",
			SourceID: id,
			Parents:  c.parent("snapshot/" + parentID),
			Refs:     map[string]any{"parent_id": parentID},
			Payload: map[string]any{
				"name": name, "kind": kind, "source": source, "path": path, "manifest_hash": manifestHash,
				"file_count": files, "bytes": bytes, "status": status, "tainted": tainted != 0, "created_at": createdAt,
			},
		})
		if err != nil {
			return err
		}
	}
	return rows.Err()
}

func (c *materializeContext) materializeRollouts() error {
	rows, err := c.store.DB.Query(`SELECT id, base_snapshot_id, status, fanout, winner_attempt_id, promotion_id, cost_estimate, risk_status, created_at, updated_at
		FROM rollouts WHERE run_id = ? ORDER BY created_at ASC`, c.runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, baseSnapshotID, status, winnerAttemptID, promotionID, riskStatus, createdAt, updatedAt string
		var fanout int
		var cost float64
		if err := rows.Scan(&id, &baseSnapshotID, &status, &fanout, &winnerAttemptID, &promotionID, &cost, &riskStatus, &createdAt, &updatedAt); err != nil {
			return err
		}
		hash, err := c.put(provenanceObject{
			Type:      "rollout",
			SourceID:  id,
			RolloutID: id,
			Parents:   c.parent("snapshot/" + baseSnapshotID),
			Refs:      map[string]any{"base_snapshot_id": baseSnapshotID, "winner_attempt_id": winnerAttemptID, "promotion_id": promotionID},
			Payload:   map[string]any{"status": status, "fanout": fanout, "cost_estimate": cost, "risk_status": riskStatus, "created_at": createdAt, "updated_at": updatedAt},
		})
		if err != nil {
			return err
		}
		c.rootHashes = append(c.rootHashes, hash)
	}
	return rows.Err()
}

func (c *materializeContext) materializeAttempts() error {
	rows, err := c.store.DB.Query(`SELECT a.id, a.rollout_id, a.tool_call_id, a.snapshot_id, a.strategy, a.command, a.status,
			COALESCE(a.exit_code, 0), a.wall_ms, a.output_summary, a.score, a.cost_estimate, a.saved_cost,
			a.risk_status, a.budget_exceeded, a.is_winner, COALESCE(a.artifact_result, ''), a.created_at
		FROM fork_attempts a JOIN rollouts r ON a.rollout_id = r.id WHERE r.run_id = ? ORDER BY a.created_at ASC`, c.runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, rolloutID, toolCallID, snapshotID, strategy, command, status, output, risk, artifact, createdAt string
		var exitCode, wallMS int64
		var score, cost, saved float64
		var budgetExceeded, isWinner int
		if err := rows.Scan(&id, &rolloutID, &toolCallID, &snapshotID, &strategy, &command, &status, &exitCode, &wallMS, &output, &score, &cost, &saved, &risk, &budgetExceeded, &isWinner, &artifact, &createdAt); err != nil {
			return err
		}
		if _, err := c.put(provenanceObject{
			Type:      "attempt",
			SourceID:  id,
			RolloutID: rolloutID,
			Parents:   c.parent("rollout/"+rolloutID, "snapshot/"+snapshotID),
			Refs:      map[string]any{"rollout_id": rolloutID, "tool_call_id": toolCallID, "snapshot_id": snapshotID, "artifact_result": artifact},
			Payload: map[string]any{
				"strategy": strategy, "command": command, "status": status, "exit_code": exitCode, "wall_ms": wallMS,
				"output_summary": output, "score": score, "cost_estimate": cost, "saved_cost": saved,
				"risk_status": risk, "budget_exceeded": budgetExceeded != 0, "winner": isWinner != 0, "created_at": createdAt,
			},
		}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (c *materializeContext) materializeToolCalls() error {
	rows, err := c.store.DB.Query(`SELECT id, rollout_id, attempt_id, session_id, command, args_hash, status, COALESCE(exit_code, 0),
			wall_ms, cost_estimate, COALESCE(result_ref, ''), policy_decision, created_at, started_at, ended_at
		FROM tool_calls WHERE run_id = ? ORDER BY created_at ASC`, c.runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, rolloutID, attemptID, sessionID, command, argsHash, status, resultRef, policy, createdAt, startedAt, endedAt string
		var exitCode, wallMS int64
		var cost float64
		if err := rows.Scan(&id, &rolloutID, &attemptID, &sessionID, &command, &argsHash, &status, &exitCode, &wallMS, &cost, &resultRef, &policy, &createdAt, &startedAt, &endedAt); err != nil {
			return err
		}
		if _, err := c.put(provenanceObject{
			Type:      "tool_call",
			SourceID:  id,
			RolloutID: rolloutID,
			Parents:   c.parent("attempt/"+attemptID, "rollout/"+rolloutID),
			Refs:      map[string]any{"attempt_id": attemptID, "session_id": sessionID, "result_ref": resultRef},
			Payload: map[string]any{
				"command": command, "args_hash": argsHash, "status": status, "exit_code": exitCode, "wall_ms": wallMS,
				"cost_estimate": cost, "policy_decision": policy, "created_at": createdAt, "started_at": startedAt, "ended_at": endedAt,
			},
		}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (c *materializeContext) materializeProcesses() error {
	rows, err := c.store.DB.Query(`SELECT p.id, p.session_id, COALESCE(p.tool_call_id, ''), p.command, p.status, COALESCE(p.exit_code, 0), p.started_at, COALESCE(p.ended_at, '')
		FROM processes p JOIN sessions s ON p.session_id = s.id WHERE s.run_id = ? ORDER BY p.started_at ASC`, c.runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, sessionID, toolCallID, command, status, startedAt, endedAt string
		var exitCode int64
		if err := rows.Scan(&id, &sessionID, &toolCallID, &command, &status, &exitCode, &startedAt, &endedAt); err != nil {
			return err
		}
		if _, err := c.put(provenanceObject{
			Type:     "process",
			SourceID: id,
			Parents:  c.parent("tool_call/" + toolCallID),
			Refs:     map[string]any{"session_id": sessionID, "tool_call_id": toolCallID},
			Payload:  map[string]any{"command": command, "status": status, "exit_code": exitCode, "started_at": startedAt, "ended_at": endedAt},
		}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (c *materializeContext) materializeArtifacts() error {
	rows, err := c.store.DB.Query(`SELECT a.id, a.rollout_id, a.tool_call_id, COALESCE(a.artifact_result, '')
		FROM fork_attempts a JOIN rollouts r ON a.rollout_id = r.id
		WHERE r.run_id = ? AND COALESCE(a.artifact_result, '') != '' ORDER BY a.created_at ASC`, c.runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var attemptID, rolloutID, toolCallID, artifactRef string
		if err := rows.Scan(&attemptID, &rolloutID, &toolCallID, &artifactRef); err != nil {
			return err
		}
		fileHash, size, exists := fileDigest(artifactRef)
		if _, err := c.put(provenanceObject{
			Type:      "artifact",
			SourceID:  artifactRef,
			RolloutID: rolloutID,
			Parents:   c.parent("attempt/"+attemptID, "tool_call/"+toolCallID),
			Refs:      map[string]any{"attempt_id": attemptID, "tool_call_id": toolCallID, "path": artifactRef},
			Payload:   map[string]any{"file_sha256": fileHash, "size_bytes": size, "exists": exists},
		}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (c *materializeContext) materializePromotions() error {
	rows, err := c.store.DB.Query(`SELECT p.id, p.rollout_id, p.attempt_id, p.base_snapshot_id, p.status, p.risk_status, p.reason,
		COALESCE(p.telemetry_watermark, ''), COALESCE(p.drain_started_at, ''), COALESCE(p.drain_completed_at, ''),
		COALESCE(p.drain_queued_before, 0), COALESCE(p.drain_processed, 0), COALESCE(p.drain_pending_after, 0),
		p.created_at, p.updated_at
		FROM promotions p JOIN rollouts r ON p.rollout_id = r.id WHERE r.run_id = ? ORDER BY p.created_at ASC`, c.runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, rolloutID, attemptID, baseSnapshotID, status, riskStatus, reason, watermark, drainStartedAt, drainCompletedAt, createdAt, updatedAt string
		var drainQueuedBefore, drainProcessed, drainPendingAfter int
		if err := rows.Scan(&id, &rolloutID, &attemptID, &baseSnapshotID, &status, &riskStatus, &reason, &watermark, &drainStartedAt, &drainCompletedAt, &drainQueuedBefore, &drainProcessed, &drainPendingAfter, &createdAt, &updatedAt); err != nil {
			return err
		}
		hash, err := c.put(provenanceObject{
			Type:      "promotion",
			SourceID:  id,
			RolloutID: rolloutID,
			Parents:   c.parent("rollout/"+rolloutID, "attempt/"+attemptID, "snapshot/"+baseSnapshotID),
			Refs:      map[string]any{"attempt_id": attemptID, "base_snapshot_id": baseSnapshotID},
			Payload: map[string]any{
				"status": status, "risk_status": riskStatus, "reason": reason,
				"telemetry_watermark": watermark, "drain_started_at": drainStartedAt, "drain_completed_at": drainCompletedAt,
				"drain_queued_before": drainQueuedBefore, "drain_processed": drainProcessed, "drain_pending_after": drainPendingAfter,
				"created_at": createdAt, "updated_at": updatedAt,
			},
		})
		if err != nil {
			return err
		}
		c.rootHashes = append(c.rootHashes, hash)
	}
	return rows.Err()
}

func (c *materializeContext) materializeEvidence() error {
	rows, err := c.store.DB.Query(`SELECT id, rollout_id, attempt_id, session_id, tool_call_id, snapshot_id, event_type, priority, payload, status, created_at, processed_at
		FROM evidence_events WHERE run_id = ? ORDER BY created_at ASC`, c.runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, rolloutID, attemptID, sessionID, toolCallID, snapshotID, eventType, priority, payload, status, createdAt, processedAt string
		if err := rows.Scan(&id, &rolloutID, &attemptID, &sessionID, &toolCallID, &snapshotID, &eventType, &priority, &payload, &status, &createdAt, &processedAt); err != nil {
			return err
		}
		if _, err := c.put(provenanceObject{
			Type:      "evidence",
			SourceID:  id,
			RolloutID: rolloutID,
			Parents:   c.parent("attempt/"+attemptID, "tool_call/"+toolCallID, "snapshot/"+snapshotID),
			Refs:      map[string]any{"attempt_id": attemptID, "session_id": sessionID, "tool_call_id": toolCallID, "snapshot_id": snapshotID},
			Payload:   map[string]any{"event_type": eventType, "priority": priority, "payload": payload, "status": status, "created_at": createdAt, "processed_at": processedAt},
		}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (c *materializeContext) materializeEvents() error {
	rows, err := c.store.DB.Query(`SELECT id, COALESCE(session_id, ''), COALESCE(tool_call_id, ''), COALESCE(process_id, ''), COALESCE(snapshot_id, ''), source, event_type, payload, created_at
		FROM events WHERE run_id = ? ORDER BY created_at ASC`, c.runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, sessionID, toolCallID, processID, snapshotID, source, eventType, payload, createdAt string
		if err := rows.Scan(&id, &sessionID, &toolCallID, &processID, &snapshotID, &source, &eventType, &payload, &createdAt); err != nil {
			return err
		}
		if _, err := c.put(provenanceObject{
			Type:     "event",
			SourceID: id,
			Parents:  c.parent("tool_call/"+toolCallID, "process/"+processID, "snapshot/"+snapshotID),
			Refs:     map[string]any{"session_id": sessionID, "tool_call_id": toolCallID, "process_id": processID, "snapshot_id": snapshotID},
			Payload:  map[string]any{"source": source, "event_type": eventType, "payload": payload, "created_at": createdAt},
		}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (c *materializeContext) materializePolicyDecisions() error {
	rows, err := c.store.DB.Query(`SELECT id, COALESCE(event_id, ''), COALESCE(session_id, ''), rule_id, decision, reason, created_at
		FROM policy_decisions WHERE run_id = ? ORDER BY created_at ASC`, c.runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, eventID, sessionID, ruleID, decision, reason, createdAt string
		if err := rows.Scan(&id, &eventID, &sessionID, &ruleID, &decision, &reason, &createdAt); err != nil {
			return err
		}
		if _, err := c.put(provenanceObject{
			Type:     "policy_decision",
			SourceID: id,
			Parents:  c.parent("event/" + eventID),
			Refs:     map[string]any{"event_id": eventID, "session_id": sessionID},
			Payload:  map[string]any{"rule_id": ruleID, "decision": decision, "reason": reason, "created_at": createdAt},
		}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (c *materializeContext) materializeCosts() error {
	rows, err := c.store.DB.Query(`SELECT id, COALESCE(session_id, ''), active_cpu_seconds, idle_seconds, wall_seconds, snapshot_bytes, policy_block_count, quarantine_count, fanout_cost, saved_cost, created_at
		FROM cost_samples WHERE run_id = ? ORDER BY created_at ASC`, c.runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, sessionID, createdAt string
		var activeCPU, idle, wall, fanoutCost, savedCost float64
		var snapshotBytes, policyBlocks, quarantine int64
		if err := rows.Scan(&id, &sessionID, &activeCPU, &idle, &wall, &snapshotBytes, &policyBlocks, &quarantine, &fanoutCost, &savedCost, &createdAt); err != nil {
			return err
		}
		if _, err := c.put(provenanceObject{
			Type:     "cost",
			SourceID: id,
			Refs:     map[string]any{"session_id": sessionID},
			Payload: map[string]any{
				"active_cpu_seconds": activeCPU, "idle_seconds": idle, "wall_seconds": wall, "snapshot_bytes": snapshotBytes,
				"policy_block_count": policyBlocks, "quarantine_count": quarantine, "fanout_cost": fanoutCost, "saved_cost": savedCost, "created_at": createdAt,
			},
		}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func fileDigest(path string) (string, int64, bool) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, false
	}
	defer file.Close()
	h := sha256.New()
	n, err := io.Copy(h, file)
	if err != nil {
		return "", 0, false
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), n, true
}
