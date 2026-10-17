package provenance

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/byteyellow/agentprovenance/internal/ids"
	storepkg "github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/tlsintent"
)

// Graph edges wiring the model's actual traffic into the signed graph.
const (
	edgeLLMBody     = "llm_body"     // runtime_event(tls) -> the objectified body
	edgeLLMRequest  = "llm_request"  // llm_call -> request body object
	edgeLLMResponse = "llm_response" // llm_call -> response body object
	edgeLLMCaused   = "llm_caused"   // llm_call -> inferred command execution
)

// MaterializeLLMCalls turns the captured LLM traffic into verifiable evidence:
// each tls_write/tls_read gets a content-addressed message with its pairing
// assessment and optional saved body. Connection/stream identities determine
// pairs; old ingestion-time edges are not matching inputs. Derived TLS results
// are atomically replaced, leaving transcript and endpoint captures intact.
func MaterializeLLMCalls(store ObjectStore, db *sql.DB, runID string) (int, error) {
	if runID == "" {
		return 0, fmt.Errorf("materialize llm calls: run id is required")
	}
	var n int
	err := storepkg.WithTx(context.Background(), db, func(tx *sql.Tx) error {
		var err error
		n, err = materializeLLMCallsTx(store, tx, runID)
		return err
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

func materializeLLMCallsTx(store ObjectStore, tx *sql.Tx, runID string) (int, error) {
	store.Tx = tx
	now := time.Now().UTC().Format(time.RFC3339Nano)

	// Read the complete matching input before replacing any derived objects.
	rows, err := tx.Query(`SELECT id,event_type,COALESCE(payload,''),created_at,source,COALESCE(session_id,''),cgroup_id,container_id,pid
		FROM events WHERE run_id = ? AND event_type IN ('tls_write','tls_read') ORDER BY id LIMIT ?`, runID, maxLLMActions+1)
	if err != nil {
		return 0, err
	}
	objByEvent := map[string]string{}
	var evs []tlsEvent
	bytes := 0
	for rows.Next() {
		var r tlsEvent
		if err := rows.Scan(&r.id, &r.etype, &r.payload, &r.timestamp, &r.scope.source, &r.scope.session, &r.scope.cgroup, &r.scope.container, &r.pid); err != nil {
			rows.Close()
			return 0, err
		}
		bytes += len(r.payload)
		if len(evs) >= maxLLMActions || bytes > maxLLMMatchBytes {
			rows.Close()
			return 0, fmt.Errorf("materialize llm calls: TLS input limit exceeded")
		}
		r.at, _ = time.Parse(time.RFC3339Nano, r.timestamp)
		r.scope.origin = llmOrigin(r.payload, r.pid)
		readTLSIdentity(&r)
		evs = append(evs, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	captureGap := false
	if len(evs) > 0 {
		captureGap, err = tlsCaptureGap(tx, runID)
		if err != nil {
			return 0, fmt.Errorf("materialize llm calls: capture report: %w", err)
		}
	}
	ps, reports := pairTLSMessages(evs, captureGap)
	var decisions []llmDecision
	for _, p := range ps {
		req, resp := evs[p.request], evs[p.response]
		content, _ := tlsBodyContent(resp.payload)
		for _, command := range tlsintent.ParseSemantics(tlsintent.Response, []byte(content)).ToolCommands {
			decisions = append(decisions, llmDecision{node: "llm_call/" + req.id, sourceEvent: resp.id, command: command, at: resp.at, scope: resp.scope})
		}
	}
	actions, err := readLLMActions(tx, runID, false)
	if err != nil {
		return 0, err
	}
	matches, err := matchLLMDecisions(decisions, actions)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`DELETE FROM graph_edges WHERE run_id=? AND (
		edge_type IN ('llm_call','llm_intent_caused','llm_body') OR
		(edge_type IN ('llm_request','llm_response','llm_caused') AND from_id IN (
			SELECT 'llm_call/' || id FROM events WHERE run_id=? AND event_type='tls_write')))`, runID, runID); err != nil {
		return 0, fmt.Errorf("materialize llm calls: clear edges: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM provenance_objects WHERE run_id=? AND object_type='llm_message'
		AND (source_id LIKE 'llm_request/%' OR source_id LIKE 'llm_response/%')`, runID); err != nil {
		return 0, fmt.Errorf("materialize llm calls: clear objects: %w", err)
	}
	// Objectify each TLS body, including decisions with no attributable execution.
	for _, r := range evs {
		content, model := tlsBodyContent(r.payload)
		dir, prefix := tlsintent.Request, "llm_request"
		if r.etype == "tls_read" {
			dir, prefix = tlsintent.Response, "llm_response"
		}
		sem := tlsintent.ParseSemantics(dir, []byte(content))
		if model == "" {
			model = sem.Model
		}
		res, err := store.PutExternalObject(ExternalObjectInput{
			Type:     "llm_message",
			SourceID: prefix + "/" + r.id,
			RunID:    runID,
			Payload: map[string]any{"direction": dir, "model": model, "content": content, "semantics": sem,
				"content_saved": content != "", "http_identity": r.http, "truncated": r.truncated, "correlation": reports[r.id]},
		})
		if err != nil {
			return 0, fmt.Errorf("materialize llm calls: objectify %s: %w", r.id, err)
		}
		objByEvent[r.id] = res.Hash
		if err := insertLLMEdge(tx, runID, "runtime_event/"+r.id, res.Hash, edgeLLMBody, r.id, now); err != nil {
			return 0, err
		}
	}

	n := 0
	for _, p := range ps {
		reqID, respID := evs[p.request].id, evs[p.response].id
		reqObj, respObj := objByEvent[reqID], objByEvent[respID]
		if reqObj == "" && respObj == "" {
			continue
		}
		llmNode := "llm_call/" + reqID // deterministic: one llm_call per request
		report := reports[reqID]
		if _, err := tx.Exec(`INSERT INTO graph_edges (id,run_id,rollout_id,from_id,to_id,edge_type,source_event_id,created_at)
			VALUES (?,?,'',?,?,'llm_call',?,?)`, tlsPairEdgePrefix+report.Method+"-"+ids.New("edge"), runID,
			"runtime_event/"+reqID, "runtime_event/"+respID, respID, evs[p.response].at.UTC().Format(time.RFC3339Nano)); err != nil {
			return 0, fmt.Errorf("materialize llm calls: insert pair: %w", err)
		}
		if err := insertLLMEdge(tx, runID, llmNode, reqObj, edgeLLMRequest, reqID, now); err != nil {
			return 0, err
		}
		if err := insertLLMEdge(tx, runID, llmNode, respObj, edgeLLMResponse, respID, now); err != nil {
			return 0, err
		}
		n++
	}
	for i, d := range decisions {
		if action, ok := matches[i]; ok {
			if err := insertLLMEdge(tx, runID, d.node, action, edgeLLMCaused, d.sourceEvent, now); err != nil {
				return 0, err
			}
		}
	}
	return n, nil
}

// insertLLMEdge writes one graph edge. An empty endpoint is a legitimate skip
// (e.g. a request with no captured response body) and returns nil; a real write
// failure is returned so MaterializeLLMCalls fails loudly rather than reporting
// success over a graph that is silently missing edges.
type llmEdgeWriter interface {
	Exec(string, ...any) (sql.Result, error)
}

func insertLLMEdge(db llmEdgeWriter, runID, from, to, edgeType, sourceEvent, now string) error {
	if from == "" || to == "" {
		return nil
	}
	id := ids.New("edge")
	if edgeType == edgeLLMCaused {
		id = llmCommandEdgePrefix + id
	}
	if _, err := db.Exec(`INSERT INTO graph_edges (id, run_id, rollout_id, from_id, to_id, edge_type, source_event_id, created_at)
		VALUES (?, ?, '', ?, ?, ?, ?, ?)`, id, runID, from, to, edgeType, sourceEvent, now); err != nil {
		return fmt.Errorf("materialize llm calls: insert %s edge: %w", edgeType, err)
	}
	return nil
}

// tlsBodyContent extracts the full reassembled body + model from a tls event's
// payload. The body is present only when full TLS capture is enabled at ingest;
// otherwise the payload carries just a hash + preview and this returns "".
func tlsBodyContent(payload string) (content, model string) {
	var m map[string]any
	if json.Unmarshal([]byte(payload), &m) != nil {
		return "", ""
	}
	inner := m
	if p, ok := m["payload"].(map[string]any); ok { // envelope from the recorder
		inner = p
	}
	content, _ = inner["content"].(string)
	if content == "" {
		if raw, ok := inner["raw"].(map[string]any); ok {
			content, _ = raw["content"].(string)
		}
	}
	if s, ok := inner["model"].(string); ok {
		model = s
	}
	return content, model
}
