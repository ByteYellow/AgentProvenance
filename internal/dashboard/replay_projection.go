package dashboard

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/observability"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
)

// A partial replay is a private read projection, never a rewritten evidence
// store. Only explicitly admitted tables and object dependencies are copied.
// The temporary databases themselves are not included in the shared ZIP.
type replayProjection struct {
	*replaySnapshot
	auditSource *sql.DB
	plan        *replaySelectionPlan
	boundaries  map[string]string
	readers     map[string]string
	capture     observability.RuntimeCaptureReport
	omitted     map[string]int
}

func (p *replaySelectionPlan) partial() bool {
	return p.Selection.Scope != "whole_run" || len(p.Selection.ExcludeRecords) > 0 || len(p.Selection.ExcludeCategories) > 0
}

func (snapshot *replaySnapshot) projectSelection(ctx context.Context, plan *replaySelectionPlan) (_ *replayProjection, err error) {
	root, err := os.MkdirTemp("", "agentprov-replay-projection-")
	if err != nil {
		return nil, err
	}
	var db *sql.DB
	defer func() {
		if err != nil {
			if db != nil {
				_ = db.Close()
			}
			_ = os.RemoveAll(root)
		}
	}()
	db, err = store.Open(store.ResolvePaths(root))
	if err != nil {
		return nil, err
	}
	if err = store.EnsureSchema(db); err != nil {
		return nil, err
	}
	p := &replayProjection{replaySnapshot: &replaySnapshot{DB: db, root: root}, plan: plan,
		auditSource: snapshot.DB, boundaries: map[string]string{}, readers: map[string]string{}, omitted: map[string]int{}}
	run := plan.Selection.RunID
	coverage, err := observability.ReadRuntimeCoverage(ctx, snapshot.DB, run)
	if err != nil {
		return nil, err
	}
	p.capture = coverage.Capture
	// Retain the recorded run-level gap counters, not rejected raw examples or
	// host-specific probe inventories which may contain unselected content.
	p.capture.RejectionExamples = nil
	p.capture.CapabilitiesStart, p.capture.CapabilitiesEnd = nil, nil

	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	source := url.URL{Scheme: "file", Path: filepath.Join(snapshot.root, "snapshot.db"), RawQuery: "mode=ro"}
	if _, err = conn.ExecContext(ctx, "ATTACH DATABASE ? AS captured", source.String()); err != nil {
		return nil, err
	}
	attached := true
	defer func() {
		if attached {
			_, _ = conn.ExecContext(context.Background(), "DETACH DATABASE captured")
		}
	}()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	exec := func(query string, args ...any) error {
		_, err := tx.ExecContext(ctx, query, args...)
		return err
	}
	if err = exec(`CREATE TABLE replay_members (id TEXT PRIMARY KEY, node TEXT NOT NULL, included INTEGER NOT NULL); CREATE INDEX replay_member_node ON replay_members(node);`); err != nil {
		return nil, err
	}
	records, err := json.Marshal(plan.Records)
	if err != nil {
		return nil, err
	}
	if err = exec(`INSERT INTO replay_members SELECT json_extract(value,'$.id'), COALESCE(json_extract(value,'$.node'),''), json_extract(value,'$.included') FROM json_each(?)`, string(records)); err != nil {
		return nil, err
	}
	copyTable := func(table, predicate string, args ...any) error {
		return exec("INSERT INTO main."+table+" SELECT x.* FROM captured."+table+" x WHERE "+predicate, args...)
	}
	for _, table := range []struct{ name, prefix string }{{"events", "3/"}, {"tool_calls", "2/"}, {"agent_context_entries", "entry/"}} {
		if err = copyTable(table.name, "x.run_id=? AND ?||x.id IN (SELECT id FROM replay_members WHERE included=1)", run, table.prefix); err != nil {
			return nil, err
		}
	}
	if err = copyTable("agent_context_reports", `x.run_id=? AND (?='whole_run' OR x.source_id IN (SELECT source_id FROM main.agent_context_entries)
		OR (x.harness=? AND x.session_id=?))`, run, plan.Selection.Scope, plan.Selection.Harness, plan.Selection.SessionID); err != nil {
		return nil, err
	}
	// All selected object envelopes keep their original hashes and bytes. Parent
	// hashes are references, not permission to recursively pull in other records.
	if err = copyTable("provenance_objects", `x.run_id=? AND (
		x.hash IN (SELECT node FROM replay_members WHERE included=1 AND (id LIKE '1/%' OR id LIKE 'entry/%'))
		OR (x.object_type='event' AND x.source_id IN (SELECT id FROM main.events))
		OR (x.object_type='tool_call' AND x.source_id IN (SELECT id FROM main.tool_calls))
		OR (x.object_type='agent_context_coverage' AND x.hash IN (SELECT object_hash FROM main.agent_context_reports))
		OR x.object_type IN ('context_capture_policy','run_capture_settings')
		OR (x.object_type='egress_payload' AND EXISTS (SELECT 1 FROM captured.graph_edges g JOIN main.events e ON g.source_event_id=e.id AND g.run_id=e.run_id
			WHERE g.run_id=x.run_id AND g.to_id=x.hash AND g.edge_type='endpoint_egress_payload'))
	)`, run); err != nil {
		return nil, err
	}
	for _, item := range []struct{ table, where string }{
		{"agents", `x.run_id=? AND (x.id IN (SELECT agent_id FROM main.tool_calls) OR x.id IN (SELECT agent_id FROM main.agent_context_entries))`},
		{"policy_decisions", `x.run_id=? AND x.event_id IN (SELECT id FROM main.events)`},
		{"risk_signals", `x.run_id=? AND x.event_id IN (SELECT id FROM main.events)
		 AND (x.tool_call_id='' OR x.tool_call_id IN (SELECT id FROM main.tool_calls))
		 AND (x.policy_decision_id='' OR x.policy_decision_id IN (SELECT id FROM main.policy_decisions))`},
		{"response_actions", `x.run_id=? AND (x.risk_signal_id!='' OR x.policy_decision_id!='')
		 AND (x.risk_signal_id='' OR x.risk_signal_id IN (SELECT id FROM main.risk_signals))
		 AND (x.policy_decision_id='' OR x.policy_decision_id IN (SELECT id FROM main.policy_decisions))`},
	} {
		if err = copyTable(item.table, item.where, run); err != nil {
			return nil, err
		}
	}
	// Scope membership is not a traversal: neighbors become boundary references,
	// and cannot bring in their other events, tools, files or sessions.
	if err = exec(`CREATE TABLE replay_nodes (id TEXT PRIMARY KEY);
		INSERT OR IGNORE INTO replay_nodes SELECT node FROM replay_members WHERE included=1 AND node!='';
		INSERT OR IGNORE INTO replay_nodes SELECT hash FROM main.provenance_objects;
		INSERT OR IGNORE INTO replay_nodes SELECT source_id FROM main.provenance_objects WHERE object_type='artifact';
		INSERT OR IGNORE INTO replay_nodes SELECT 'agent/'||id FROM main.agents;
		INSERT OR IGNORE INTO replay_nodes SELECT id FROM main.policy_decisions;
		INSERT OR IGNORE INTO replay_nodes SELECT 'policy_decision/'||id FROM main.policy_decisions;
		INSERT OR IGNORE INTO replay_nodes SELECT id FROM main.risk_signals;
		INSERT OR IGNORE INTO replay_nodes SELECT 'risk_signal/'||id FROM main.risk_signals;
		INSERT OR IGNORE INTO replay_nodes SELECT id FROM main.response_actions;
		INSERT OR IGNORE INTO replay_nodes SELECT 'response_action/'||id FROM main.response_actions;`); err != nil {
		return nil, err
	}
	if err = copyTable("signals", `x.run_id=? AND (x.event_id IN (SELECT id FROM main.events)
		OR (x.source_table='risk_signals' AND x.source_id IN (SELECT id FROM main.risk_signals)))
		AND (x.tool_call_id='' OR x.tool_call_id IN (SELECT id FROM main.tool_calls))
		AND (x.object_ref='' OR x.object_ref IN (SELECT hash FROM main.provenance_objects))
		AND (x.graph_ref_id='' OR x.graph_ref_id IN (SELECT id FROM replay_nodes)
		 OR (x.graph_ref_kind='run' AND x.graph_ref_id=x.run_id)
		 OR (x.graph_ref_kind='event' AND x.graph_ref_id IN (SELECT id FROM main.events))
		 OR (x.graph_ref_kind='process' AND x.graph_ref_id IN (SELECT process_id FROM main.events))
		 OR (x.graph_ref_kind='session' AND x.graph_ref_id IN (SELECT session_id FROM main.events)))
		AND json_type(CASE WHEN json_valid(x.evidence_refs) THEN x.evidence_refs ELSE 'null' END)='array'
		AND NOT EXISTS (SELECT 1 FROM json_each(CASE WHEN json_valid(x.evidence_refs) THEN x.evidence_refs ELSE '[]' END) r
		 WHERE r.type!='text' OR (r.value NOT IN (SELECT id FROM replay_nodes) AND r.value NOT IN (SELECT id FROM main.events)))`, run); err != nil {
		return nil, err
	}
	if err = exec(`INSERT OR IGNORE INTO replay_nodes SELECT id FROM main.signals`); err != nil {
		return nil, err
	}
	if err = copyTable("intent_diffs", `x.run_id=? AND x.tool_call_id!='' AND x.tool_call_id IN (SELECT id FROM main.tool_calls)
		AND json_type(CASE WHEN json_valid(x.observed_effects) THEN x.observed_effects ELSE 'null' END)='array'
		AND NOT EXISTS (SELECT 1 FROM json_each(CASE WHEN json_valid(x.observed_effects) THEN x.observed_effects ELSE '[]' END) e
		 WHERE CASE WHEN e.type='object' THEN COALESCE(json_extract(e.value,'$.event_id'),'') ELSE '' END NOT IN (SELECT id FROM main.events))
		AND NOT EXISTS (SELECT 1 FROM captured.events e WHERE e.run_id=x.run_id AND e.tool_call_id=x.tool_call_id AND e.id NOT IN (SELECT id FROM main.events))`, run); err != nil {
		return nil, err
	}
	if err = exec(`INSERT OR IGNORE INTO replay_nodes SELECT id FROM main.intent_diffs`); err != nil {
		return nil, err
	}
	if err = copyTable("graph_edges", `x.run_id=? AND (NOT EXISTS (SELECT 1 FROM captured.events e WHERE e.run_id=x.run_id AND e.id=x.source_event_id)
		OR x.source_event_id IN (SELECT id FROM main.events))
		AND (x.from_id IN (SELECT id FROM replay_nodes) OR x.to_id IN (SELECT id FROM replay_nodes))`, run); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	for _, table := range []string{"intent_diffs", "signals", "risk_signals", "policy_decisions", "response_actions", "baseline_deviations", "cost_samples"} {
		var count int
		if err = conn.QueryRowContext(ctx, "SELECT (SELECT COUNT(*) FROM captured."+table+" WHERE run_id=?) - (SELECT COUNT(*) FROM main."+table+" WHERE run_id=?)", run, run).Scan(&count); err != nil {
			return nil, err
		}
		if count > 0 {
			p.omitted[table] = count
		}
	}
	// Load only content dependencies of admitted records. In particular, old
	// versions with a matching path/source ID are not added by this closure.
	refs := map[string]bool{}
	for _, r := range plan.Records {
		if !r.Included || !strings.HasPrefix(r.ID, "entry/") {
			continue
		}
		e := plan.Entries[strings.TrimPrefix(r.ID, "entry/")]
		if plan.WithheldContent[e.RawContent.Ref] != "" {
			p.readers[e.ObjectHash] = "raw_record_partially_excluded"
		}
		for _, content := range e.ContentReferences() {
			if content.State == "stored" && content.Ref != "" && plan.WithheldContent[content.Ref] == "" {
				refs[content.Ref] = true
			}
		}
	}
	rows, err := conn.QueryContext(ctx, `SELECT hash FROM provenance_objects WHERE object_type='artifact'`)
	if err != nil {
		return nil, err
	}
	var artifacts []string
	for rows.Next() {
		var hash string
		if err = rows.Scan(&hash); err != nil {
			rows.Close()
			return nil, err
		}
		artifacts = append(artifacts, hash)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, hash := range artifacts {
		var descriptor struct {
			ContentRef string `json:"content_ref"`
			Kind       string `json:"kind"`
		}
		if err := provenance.ReadObjectPayload(snapshot.DB, run, hash, &descriptor); err != nil {
			continue
		}
		if descriptor.Kind == "stored_text" {
			refs[hash] = true
		}
		if descriptor.ContentRef != "" {
			if reason := plan.WithheldContent[descriptor.ContentRef]; reason != "" {
				p.readers[hash] = reason
			} else {
				refs[descriptor.ContentRef] = true
			}
		}
	}
	contentTx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer contentTx.Rollback()
	for ref := range refs {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		var body struct {
			Manifest provenance.TextManifest `json:"text_manifest"`
		}
		// Missing or damaged stored bodies keep the ordinary reader's absence
		// diagnostics. They are not reconstructed from the current workspace.
		dependencies := []string{ref}
		if err := provenance.ReadObjectPayload(snapshot.DB, run, ref, &body); err == nil {
			for _, chunk := range body.Manifest.Chunks {
				if plan.WithheldContent[chunk.Ref] == "" {
					dependencies = append(dependencies, chunk.Ref)
				}
			}
		}
		encoded, marshalErr := json.Marshal(dependencies)
		if marshalErr != nil {
			return nil, marshalErr
		}
		if _, err = contentTx.ExecContext(ctx, `INSERT OR IGNORE INTO main.provenance_objects SELECT * FROM captured.provenance_objects
			WHERE run_id=? AND object_type IN ('text_content','text_chunk') AND hash IN (SELECT value FROM json_each(?))`, run, string(encoded)); err != nil {
			return nil, err
		}
	}
	if err = contentTx.Commit(); err != nil {
		return nil, err
	}
	rows, err = conn.QueryContext(ctx, `SELECT id FROM (
		SELECT from_id AS id FROM graph_edges UNION SELECT to_id FROM graph_edges
	) WHERE id NOT IN (SELECT id FROM replay_nodes)`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		p.boundaries[id] = "context_not_included"
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for id, reason := range plan.DeniedNodes {
		p.boundaries[id] = reason
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if _, err = conn.ExecContext(ctx, "DETACH DATABASE captured"); err != nil {
		return nil, err
	}
	attached = false
	if err = conn.Close(); err != nil {
		return nil, err
	}
	if err = db.Close(); err != nil {
		return nil, err
	}
	sealed := url.URL{Scheme: "file", Path: store.ResolvePaths(root).DB, RawQuery: "mode=ro&_pragma=query_only(1)"}
	db, err = sql.Open("sqlite", sealed.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	if err = db.PingContext(ctx); err != nil {
		return nil, err
	}
	p.DB = db
	return p, nil
}

func (p *replayProjection) entry(e agentcontext.Entry) agentcontext.Entry {
	refs := []*agentcontext.ContentRef{&e.Content, &e.RawContent}
	if e.IntentContent != nil {
		content := *e.IntentContent
		e.IntentContent = &content
		refs = append(refs, e.IntentContent)
	}
	for _, body := range refs {
		if reason := p.plan.WithheldContent[body.Ref]; reason != "" {
			body.State, body.Reason = "excluded", reason
		}
	}
	return e
}

func (p *replayProjection) lenses(lenses *provenance.ReplayLenses) {
	for id, n := range lenses.Nodes {
		if strings.HasPrefix(id, "runtime_process/") && n.Kind == "process" && n.TrustOrigin == "runtime_observed" {
			delete(p.boundaries, id)
		}
	}
	node := func(n provenance.GraphLensNode) provenance.GraphLensNode {
		if reason := p.boundaries[n.ID]; reason != "" {
			return provenance.GraphLensNode{ID: n.ID, Kind: "reference", Subtype: "replay_boundary", Label: "Context not included",
				Data: map[string]any{"content_state": "excluded", "reason": reason}}
		}
		return n
	}
	edges := func(edges []provenance.GraphLensEdge) {
		for i := range edges {
			if p.boundaries[edges[i].FromID] != "" || p.boundaries[edges[i].ToID] != "" {
				// Keep the original relation, rule and confidence. The marker is a
				// sharing boundary, not a new causal inference.
				edges[i].Data = map[string]any{"context_not_included": true}
			}
		}
	}
	for _, nodes := range []map[string]provenance.GraphLensNode{lenses.Nodes, lenses.FocusNodes} {
		for id, n := range nodes {
			nodes[id] = node(n)
		}
	}
	for key, view := range lenses.Views {
		for i, n := range view.Manifest.Nodes {
			view.Manifest.Nodes[i] = node(n)
		}
		for id, n := range view.ExtraNodes {
			view.ExtraNodes[id] = node(n)
		}
		edges(view.Manifest.Edges)
		edges(view.Manifest.DerivedEdges)
		edges(view.FocusEdges)
		overlays := view.Manifest.Overlays[:0]
		for _, overlay := range view.Manifest.Overlays {
			if p.boundaries[overlay.TargetID] == "" {
				overlays = append(overlays, overlay)
			}
		}
		view.Manifest.Overlays = overlays
		lenses.Views[key] = view
	}
}

func (p *replayProjection) excludedArtifact(node, mode string) (artifactResp, bool) {
	reason := p.boundaries[node]
	if reason == "" {
		reason = p.readers[node]
	}
	if reason == "" {
		return artifactResp{}, false
	}
	return artifactResp{SchemaVersion: "agentprovenance.artifact_page/v1", Kind: "unavailable", Ref: node,
		Mode: mode, ContentState: "excluded", Reason: fmt.Sprintf("Context not included in this replay (%s).", reason)}, true
}
