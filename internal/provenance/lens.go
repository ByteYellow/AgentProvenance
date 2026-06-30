package provenance

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

const graphLensSchemaVersion = "agentprovenance.graph_lens/v1"

var availableGraphLenses = []string{
	"default",
	"security",
	"process",
	"file-artifact",
	"network-egress",
	"data-flow-taint",
	"agent-intent",
	"trust-origin",
	"sandbox-boundary",
}

type GraphLensOptions struct {
	RunID    string
	Lens     string
	Focus    string
	Overlays []string
	Limit    int
	Detail   string
}

type GraphLensManifest struct {
	SchemaVersion   string             `json:"schema_version"`
	RunID           string             `json:"run_id"`
	Lens            string             `json:"lens"`
	AvailableLenses []string           `json:"available_lenses"`
	Query           GraphLensQuery     `json:"query"`
	Summary         []string           `json:"summary"`
	Nodes           []GraphLensNode    `json:"nodes"`
	Edges           []GraphLensEdge    `json:"edges"`
	DerivedEdges    []GraphLensEdge    `json:"derived_edges,omitempty"`
	Overlays        []GraphLensOverlay `json:"overlays,omitempty"`
}

type GraphLensQuery struct {
	Focus         string   `json:"focus,omitempty"`
	Overlays      []string `json:"overlays,omitempty"`
	Limit         int      `json:"limit"`
	Detail        string   `json:"detail"`
	Truncated     bool     `json:"truncated"`
	NodeCount     int      `json:"node_count"`
	EdgeCount     int      `json:"edge_count"`
	Derived       int      `json:"derived_edge_count"`
	RawEventCount int      `json:"raw_event_count"`
	OmittedNodes  int      `json:"omitted_nodes,omitempty"`
	OmittedEdges  int      `json:"omitted_edges,omitempty"`
	LensRules     []string `json:"lens_rules"`
	LayoutHint    string   `json:"layout_hint"`
}

type GraphLensNode struct {
	ID          string         `json:"id"`
	Kind        string         `json:"kind"`
	Subtype     string         `json:"subtype,omitempty"`
	Label       string         `json:"label"`
	TrustOrigin string         `json:"trust_origin,omitempty"`
	Risk        string         `json:"risk,omitempty"`
	Data        map[string]any `json:"data,omitempty"`
}

type GraphLensEdge struct {
	ID             string         `json:"id,omitempty"`
	FromID         string         `json:"from_id"`
	ToID           string         `json:"to_id"`
	EdgeType       string         `json:"edge_type"`
	SourceEventID  string         `json:"source_event_id,omitempty"`
	CreatedAt      string         `json:"created_at,omitempty"`
	Derived        bool           `json:"derived"`
	DerivationRule string         `json:"derivation_rule,omitempty"`
	Confidence     float64        `json:"confidence,omitempty"`
	EvidenceRefs   []string       `json:"evidence_refs,omitempty"`
	Data           map[string]any `json:"data,omitempty"`
}

type GraphLensOverlay struct {
	TargetID string         `json:"target_id"`
	Kind     string         `json:"kind"`
	Label    string         `json:"label"`
	Severity string         `json:"severity,omitempty"`
	Data     map[string]any `json:"data,omitempty"`
}

type lensEvent struct {
	ID          string
	NodeID      string
	Type        string
	ProcessID   string
	ToolCallID  string
	SessionID   string
	SnapshotID  string
	PID         int64
	PPID        int64
	Source      string
	Payload     string
	CreatedAt   string
	Path        string
	Destination string
}

func BuildGraphLens(db *sql.DB, opts GraphLensOptions) (GraphLensManifest, error) {
	opts.RunID = strings.TrimSpace(opts.RunID)
	if opts.RunID == "" {
		return GraphLensManifest{}, fmt.Errorf("--run is required")
	}
	lens := normalizeGraphLens(opts.Lens)
	detail := normalizeGraphLensDetail(opts.Detail)
	if opts.Limit <= 0 {
		opts.Limit = 500
	}
	nodes, events, err := graphLensNodes(db, opts.RunID)
	if err != nil {
		return GraphLensManifest{}, err
	}
	edges, err := graphLensEdges(db, opts.RunID)
	if err != nil {
		return GraphLensManifest{}, err
	}
	derived := deriveGraphLensEdges(lens, events, detail)
	allEdges := append(edges, derived...)
	filteredEdges := filterGraphLensEdges(lens, opts.Focus, detail, nodes, events, allEdges)
	manifest := GraphLensManifest{
		SchemaVersion:   graphLensSchemaVersion,
		RunID:           opts.RunID,
		Lens:            lens,
		AvailableLenses: append([]string{}, availableGraphLenses...),
		Query: GraphLensQuery{
			Focus:         opts.Focus,
			Overlays:      cleanOverlays(opts.Overlays),
			Limit:         opts.Limit,
			Detail:        detail,
			RawEventCount: len(events),
			LensRules:     graphLensRules(lens),
			LayoutHint:    graphLensLayout(lens),
		},
	}
	used := map[string]bool{}
	for _, edge := range filteredEdges {
		used[edge.FromID] = true
		used[edge.ToID] = true
		if edge.SourceEventID != "" {
			used["runtime_event/"+edge.SourceEventID] = true
		}
	}
	if opts.Focus != "" {
		used[opts.Focus] = true
	}
	manifest.Nodes = sortedLensNodes(nodes, used)
	manifest.Edges, manifest.DerivedEdges, manifest.Query.Truncated = splitAndLimitLensEdges(filteredEdges, opts.Limit)
	manifest.Query.NodeCount = len(manifest.Nodes)
	manifest.Query.EdgeCount = len(manifest.Edges) + len(manifest.DerivedEdges)
	manifest.Query.Derived = len(manifest.DerivedEdges)
	manifest.Query.OmittedNodes = maxInt(0, len(nodes)-manifest.Query.NodeCount)
	manifest.Query.OmittedEdges = maxInt(0, len(allEdges)-manifest.Query.EdgeCount)
	manifest.Overlays = buildGraphLensOverlays(nodes, manifest.Nodes, manifest.Query.Overlays)
	manifest.Summary = []string{
		fmt.Sprintf("lens=%s layout=%s", manifest.Lens, manifest.Query.LayoutHint),
		fmt.Sprintf("detail=%s raw_events=%d nodes=%d edges=%d derived_edges=%d omitted_nodes=%d omitted_edges=%d",
			manifest.Query.Detail, manifest.Query.RawEventCount, manifest.Query.NodeCount, len(manifest.Edges), len(manifest.DerivedEdges),
			manifest.Query.OmittedNodes, manifest.Query.OmittedEdges),
	}
	return manifest, nil
}

func GraphLensJSON(db *sql.DB, opts GraphLensOptions, out io.Writer) error {
	manifest, err := BuildGraphLens(db, opts)
	if err != nil {
		return err
	}
	return PrintGraphLensManifestJSON(out, manifest)
}

func PrintGraphLensManifestJSON(out io.Writer, manifest GraphLensManifest) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(manifest)
}

func GraphLens(db *sql.DB, opts GraphLensOptions, out io.Writer) error {
	manifest, err := BuildGraphLens(db, opts)
	if err != nil {
		return err
	}
	return PrintGraphLensManifest(out, manifest)
}

func PrintGraphLensManifest(out io.Writer, manifest GraphLensManifest) error {
	fmt.Fprintf(out, "graph_lens run=%s lens=%s schema=%s nodes=%d edges=%d derived=%d layout=%s truncated=%t\n",
		manifest.RunID, manifest.Lens, manifest.SchemaVersion, manifest.Query.NodeCount,
		len(manifest.Edges), len(manifest.DerivedEdges), manifest.Query.LayoutHint, manifest.Query.Truncated)
	for _, line := range manifest.Summary {
		fmt.Fprintf(out, "  summary=%s\n", line)
	}
	for _, edge := range manifest.DerivedEdges {
		fmt.Fprintf(out, "  derived_edge=%s %s -> %s confidence=%.2f rule=%s evidence=%s\n",
			edge.EdgeType, edge.FromID, edge.ToID, edge.Confidence, edge.DerivationRule, strings.Join(edge.EvidenceRefs, ","))
	}
	for _, edge := range manifest.Edges {
		fmt.Fprintf(out, "  edge=%s %s -> %s source_event=%s\n", edge.EdgeType, edge.FromID, edge.ToID, edge.SourceEventID)
	}
	return nil
}

func normalizeGraphLens(lens string) string {
	lens = strings.ToLower(strings.TrimSpace(lens))
	if lens == "" {
		return "default"
	}
	for _, allowed := range availableGraphLenses {
		if lens == allowed {
			return lens
		}
	}
	return "default"
}

func normalizeGraphLensDetail(detail string) string {
	switch strings.ToLower(strings.TrimSpace(detail)) {
	case "raw", "expanded":
		return strings.ToLower(strings.TrimSpace(detail))
	default:
		return "summary"
	}
}

func graphLensNodes(db *sql.DB, runID string) (map[string]GraphLensNode, map[string]lensEvent, error) {
	nodes := map[string]GraphLensNode{}
	events := map[string]lensEvent{}
	add := func(node GraphLensNode) {
		if node.ID != "" {
			nodes[node.ID] = node
		}
	}
	rows, err := db.Query(`SELECT id, COALESCE(session_id,''), COALESCE(tool_call_id,''), COALESCE(process_id,''), COALESCE(snapshot_id,''), COALESCE(pid,0), COALESCE(ppid,0), source, event_type, payload, created_at
		FROM events WHERE run_id = ? ORDER BY created_at ASC`, runID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ev lensEvent
		if err := rows.Scan(&ev.ID, &ev.SessionID, &ev.ToolCallID, &ev.ProcessID, &ev.SnapshotID, &ev.PID, &ev.PPID, &ev.Source, &ev.Type, &ev.Payload, &ev.CreatedAt); err != nil {
			return nil, nil, err
		}
		ev.NodeID = "runtime_event/" + ev.ID
		ev.Path = payloadString(ev.Payload, "path", "file")
		ev.Destination = payloadString(ev.Payload, "host", "dst_ip", "dst", "destination")
		events[ev.NodeID] = ev
		add(GraphLensNode{
			ID:      ev.NodeID,
			Kind:    "runtime_event",
			Subtype: ev.Type,
			Label:   ev.Type,
			Risk:    riskForEventType(ev.Type),
			Data: map[string]any{
				"event_id": ev.ID, "source": ev.Source, "pid": ev.PID, "ppid": ev.PPID,
				"process_id": ev.ProcessID, "tool_call_id": ev.ToolCallID, "path": ev.Path, "destination": ev.Destination,
				"created_at": ev.CreatedAt,
			},
		})
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	if err := addToolCallNodes(db, runID, add); err != nil {
		return nil, nil, err
	}
	if err := addProcessNodes(db, runID, add); err != nil {
		return nil, nil, err
	}
	if err := addPolicyNodes(db, runID, add); err != nil {
		return nil, nil, err
	}
	if err := addSnapshotAttemptNodes(db, runID, add); err != nil {
		return nil, nil, err
	}
	// runtime_process/pid/<pid> nodes are referenced by edges but otherwise carry
	// only the bare pid. Enrich them with the command from the matching execve
	// event so the graph shows the process NAME and the pid together (label =
	// command, subtitle = pid) instead of an opaque number.
	pidCommand := map[int64]string{}
	// execve is authoritative (the real exec). Then process_observed (the record
	// ps-sampler) fills in pids whose execve wasn't captured — e.g. processes that
	// were already running when the sensor attached — so the graph shows a name
	// instead of a bare pid.
	for _, ev := range events {
		if ev.Type == "execve" && ev.PID > 0 {
			if cmd := payloadString(ev.Payload, "command", "cmdline", "comm"); cmd != "" {
				pidCommand[ev.PID] = cmd
			}
		}
	}
	for _, ev := range events {
		if ev.Type == "process_observed" && ev.PID > 0 {
			if _, named := pidCommand[ev.PID]; named {
				continue
			}
			if cmd := payloadString(ev.Payload, "command", "cmdline", "comm"); cmd != "" {
				pidCommand[ev.PID] = cmd
			}
		}
	}
	for pid, cmd := range pidCommand {
		id := fmt.Sprintf("runtime_process/pid/%d", pid)
		add(GraphLensNode{
			ID:          id,
			Kind:        "runtime_process",
			Subtype:     fmt.Sprintf("pid %d", pid),
			Label:       cmd,
			TrustOrigin: "runtime_observed",
			Data:        map[string]any{"pid": pid, "command": cmd},
		})
	}
	return nodes, events, nil
}

func addToolCallNodes(db *sql.DB, runID string, add func(GraphLensNode)) error {
	rows, err := db.Query(`SELECT id, COALESCE(attempt_id,''), COALESCE(command,''), COALESCE(status,''), COALESCE(result_ref,''), COALESCE(policy_decision,'')
		FROM tool_calls WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, attempt, command, status, result, policy string
		if err := rows.Scan(&id, &attempt, &command, &status, &result, &policy); err != nil {
			return err
		}
		add(GraphLensNode{ID: id, Kind: "tool_call", Subtype: status, Label: shortLabel(command, id), TrustOrigin: "agent_asserted", Data: map[string]any{
			"attempt_id": attempt, "command": command, "status": status, "result_ref": result, "policy_decision": policy,
		}})
		if result != "" {
			add(GraphLensNode{ID: result, Kind: "artifact", Label: lensShortRef(result), TrustOrigin: "agent_generated", Data: map[string]any{"result_ref": result, "tool_call_id": id}})
		}
	}
	return rows.Err()
}

func addProcessNodes(db *sql.DB, runID string, add func(GraphLensNode)) error {
	rows, err := db.Query(`SELECT p.id, COALESCE(p.tool_call_id,''), COALESCE(p.command,''), COALESCE(p.status,''), COALESCE(p.exit_code,0)
		FROM processes p JOIN sessions s ON s.id = p.session_id WHERE s.run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, toolCall, command, status string
		var exitCode int
		if err := rows.Scan(&id, &toolCall, &command, &status, &exitCode); err != nil {
			return err
		}
		add(GraphLensNode{ID: id, Kind: "process", Subtype: status, Label: shortLabel(command, id), TrustOrigin: "runtime_observed", Data: map[string]any{
			"tool_call_id": toolCall, "command": command, "status": status, "exit_code": exitCode,
		}})
	}
	return rows.Err()
}

func addPolicyNodes(db *sql.DB, runID string, add func(GraphLensNode)) error {
	policies, err := db.Query(`SELECT id, COALESCE(rule_id,''), decision, COALESCE(reason,'') FROM policy_decisions WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer policies.Close()
	for policies.Next() {
		var id, rule, decision, reason string
		if err := policies.Scan(&id, &rule, &decision, &reason); err != nil {
			return err
		}
		add(GraphLensNode{ID: "policy_decision/" + id, Kind: "policy_decision", Subtype: decision, Label: "policy: " + decision, Risk: riskForDecision(decision), Data: map[string]any{
			"policy_decision_id": id, "rule_id": rule, "decision": decision, "reason": reason,
		}})
	}
	risks, err := db.Query(`SELECT id, signal_type, severity, COALESCE(reason,''), COALESCE(recommended_action,'') FROM risk_signals WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer risks.Close()
	for risks.Next() {
		var id, stype, severity, reason, action string
		if err := risks.Scan(&id, &stype, &severity, &reason, &action); err != nil {
			return err
		}
		add(GraphLensNode{ID: "risk_signal/" + id, Kind: "risk_signal", Subtype: severity, Label: stype, Risk: severity, Data: map[string]any{
			"risk_signal_id": id, "signal_type": stype, "severity": severity, "reason": reason, "recommended_action": action,
		}})
	}
	responses, err := db.Query(`SELECT id, action_type, COALESCE(status,''), COALESCE(target_type,''), COALESCE(target_id,'') FROM response_actions WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer responses.Close()
	for responses.Next() {
		var id, action, status, targetType, targetID string
		if err := responses.Scan(&id, &action, &status, &targetType, &targetID); err != nil {
			return err
		}
		add(GraphLensNode{ID: "response_action/" + id, Kind: "response_action", Subtype: status, Label: "response: " + action, Data: map[string]any{
			"response_action_id": id, "action_type": action, "status": status, "target_type": targetType, "target_id": targetID,
		}})
	}
	return nil
}

func addSnapshotAttemptNodes(db *sql.DB, runID string, add func(GraphLensNode)) error {
	rows, err := db.Query(`SELECT a.id, COALESCE(a.snapshot_id,''), COALESCE(a.status,''), COALESCE(a.strategy,''), COALESCE(a.artifact_result,''), COALESCE(a.risk_status,'')
		FROM fork_attempts a JOIN rollouts r ON r.id = a.rollout_id WHERE r.run_id = ?`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, snapshot, status, strategy, artifact, risk string
		if err := rows.Scan(&id, &snapshot, &status, &strategy, &artifact, &risk); err != nil {
			return err
		}
		add(GraphLensNode{ID: id, Kind: "attempt", Subtype: status, Label: id, Risk: risk, Data: map[string]any{
			"snapshot_id": snapshot, "strategy": strategy, "artifact_result": artifact, "risk_status": risk,
		}})
		if artifact != "" {
			add(GraphLensNode{ID: artifact, Kind: "artifact", Label: lensShortRef(artifact), TrustOrigin: "agent_generated", Data: map[string]any{"attempt_id": id, "result_ref": artifact}})
		}
	}
	snaps, err := db.Query(`SELECT id, COALESCE(name,''), COALESCE(kind,''), COALESCE(status,''), COALESCE(tainted,0) FROM snapshots`)
	if err != nil {
		return err
	}
	defer snaps.Close()
	for snaps.Next() {
		var id, name, kind, status string
		var tainted int
		if err := snaps.Scan(&id, &name, &kind, &status, &tainted); err != nil {
			return err
		}
		risk := ""
		if tainted != 0 {
			risk = "tainted"
		}
		add(GraphLensNode{ID: id, Kind: "snapshot", Subtype: kind, Label: fallback(name, id), Risk: risk, Data: map[string]any{"status": status, "tainted": tainted != 0}})
	}
	return nil
}

func graphLensEdges(db *sql.DB, runID string) ([]GraphLensEdge, error) {
	rows, err := db.Query(`SELECT id, from_id, to_id, edge_type, COALESCE(source_event_id,''), created_at FROM graph_edges WHERE run_id = ? ORDER BY created_at ASC, id ASC`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var edges []GraphLensEdge
	for rows.Next() {
		var edge GraphLensEdge
		if err := rows.Scan(&edge.ID, &edge.FromID, &edge.ToID, &edge.EdgeType, &edge.SourceEventID, &edge.CreatedAt); err != nil {
			return nil, err
		}
		edges = append(edges, edge)
	}
	return edges, rows.Err()
}

func filterGraphLensEdges(lens, focus, detail string, nodes map[string]GraphLensNode, events map[string]lensEvent, edges []GraphLensEdge) []GraphLensEdge {
	var out []GraphLensEdge
	focus = strings.TrimSpace(focus)
	for _, edge := range edges {
		if !edgeMatchesLens(lens, detail, edge, nodes, events) {
			continue
		}
		if focus != "" && edge.FromID != focus && edge.ToID != focus {
			if !strings.Contains(edge.FromID, focus) && !strings.Contains(edge.ToID, focus) {
				continue
			}
		}
		out = append(out, edge)
	}
	return out
}

func edgeMatchesLens(lens, detail string, edge GraphLensEdge, nodes map[string]GraphLensNode, events map[string]lensEvent) bool {
	from := nodes[edge.FromID]
	to := nodes[edge.ToID]
	fromEvent := events[edge.FromID]
	toEvent := events[edge.ToID]
	if detail != "raw" && !edgeIsMaterializedSignal(edge, from, to, fromEvent, toEvent) {
		return false
	}
	switch lens {
	case "security":
		return strings.Contains(edge.EdgeType, "policy") || strings.Contains(edge.EdgeType, "risk") || strings.Contains(edge.EdgeType, "response") ||
			isSecurityKind(from.Kind) || isSecurityKind(to.Kind) || riskForEventType(fromEvent.Type) != "" || riskForEventType(toEvent.Type) != ""
	case "process":
		return strings.Contains(edge.EdgeType, "process") || from.Kind == "process" || to.Kind == "process" || strings.HasPrefix(edge.FromID, "runtime_process/") || strings.HasPrefix(edge.ToID, "runtime_process/")
	case "file-artifact":
		return strings.Contains(edge.EdgeType, "file") || strings.Contains(edge.EdgeType, "artifact") || from.Kind == "file" || to.Kind == "file" || from.Kind == "artifact" || to.Kind == "artifact" ||
			strings.HasPrefix(edge.FromID, "workspace_file/") || strings.HasPrefix(edge.ToID, "workspace_file/")
	case "network-egress":
		return isNetworkEvent(fromEvent.Type) || isNetworkEvent(toEvent.Type) || strings.Contains(edge.EdgeType, "network") || strings.Contains(edge.EdgeType, "egress") || strings.Contains(edge.EdgeType, "llm_call")
	case "data-flow-taint":
		return edge.Derived || isSourceEvent(fromEvent.Type, fromEvent.Path) || isSourceEvent(toEvent.Type, toEvent.Path) || isSinkEvent(fromEvent.Type) || isSinkEvent(toEvent.Type)
	case "agent-intent":
		return strings.Contains(edge.EdgeType, "llm_") || from.Kind == "tool_call" || to.Kind == "tool_call" || strings.Contains(edge.EdgeType, "tool_call")
	case "trust-origin":
		return from.TrustOrigin != "" || to.TrustOrigin != "" || from.Kind == "artifact" || to.Kind == "artifact" || from.Kind == "tool_call" || to.Kind == "tool_call"
	case "sandbox-boundary":
		return isBoundaryEvent(fromEvent.Type) || isBoundaryEvent(toEvent.Type) || strings.Contains(edge.EdgeType, "snapshot") || strings.Contains(edge.EdgeType, "attempt")
	default:
		return true
	}
}

func edgeIsMaterializedSignal(edge GraphLensEdge, from, to GraphLensNode, fromEvent, toEvent lensEvent) bool {
	if edge.Derived {
		return true
	}
	if isStructuralEdge(edge.EdgeType) {
		return true
	}
	if fromEvent.ID != "" || toEvent.ID != "" {
		return eventIsGraphSignal(fromEvent) || eventIsGraphSignal(toEvent)
	}
	if isGraphValueNode(from) || isGraphValueNode(to) {
		return true
	}
	return eventIsGraphSignal(fromEvent) || eventIsGraphSignal(toEvent)
}

func isStructuralEdge(edgeType string) bool {
	switch edgeType {
	case "runtime_tool_call_process", "runtime_tool_call_file",
		"runtime_process_file", "runtime_attempt_file",
		"runtime_event_policy_decision", "policy_decision_risk_signal", "risk_signal_response_action",
		"llm_call", "llm_intent_caused", "attempt_snapshot", "snapshot_parent", "promotion_winner":
		return true
	default:
		return strings.Contains(edgeType, "policy") || strings.Contains(edgeType, "risk") ||
			strings.Contains(edgeType, "response") || strings.Contains(edgeType, "artifact")
	}
}

func isGraphValueNode(node GraphLensNode) bool {
	switch node.Kind {
	case "tool_call", "process", "artifact", "file", "policy_decision", "risk_signal", "response_action", "attempt", "snapshot":
		return true
	default:
		return false
	}
}

func eventIsGraphSignal(ev lensEvent) bool {
	if ev.ID == "" {
		return false
	}
	if riskForEventType(ev.Type) != "" || isNetworkEvent(ev.Type) || isSourceEvent(ev.Type, ev.Path) || isBoundaryEvent(ev.Type) {
		return true
	}
	switch ev.Type {
	case "execve", "file_write", "file_create", "file_modify", "artifact_export", "tool_call", "llm_call", "llm_intent", "process_start":
		return true
	default:
		return false
	}
}

func deriveGraphLensEdges(lens string, events map[string]lensEvent, detail string) []GraphLensEdge {
	if lens != "data-flow-taint" && lens != "security" && lens != "default" {
		return nil
	}
	sources := make([]lensEvent, 0)
	sinks := make([]lensEvent, 0)
	for _, ev := range events {
		if isSourceEvent(ev.Type, ev.Path) {
			sources = append(sources, ev)
		}
		if isSinkEvent(ev.Type) {
			sinks = append(sinks, ev)
		}
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].CreatedAt < sources[j].CreatedAt })
	sort.Slice(sinks, func(i, j int) bool { return sinks[i].CreatedAt < sinks[j].CreatedAt })
	if detail == "summary" {
		return deriveAggregatedDataFlowEdges(sources, sinks)
	}
	var derived []GraphLensEdge
	seen := map[string]bool{}
	for _, src := range sources {
		for _, sink := range sinks {
			// A data flow can only run forward in time: the secret must be read
			// before it can leave over the network. Skip sinks that happened at
			// or before the source so we never draw a temporally impossible edge
			// (e.g. an egress that preceded the secret read).
			if src.CreatedAt != "" && sink.CreatedAt != "" && sink.CreatedAt <= src.CreatedAt {
				continue
			}
			conf := 0.0
			rule := ""
			if src.ProcessID != "" && src.ProcessID == sink.ProcessID {
				conf = 0.82
				rule = "dataflow.same_process.secret_to_network.v1"
			} else if src.ToolCallID != "" && src.ToolCallID == sink.ToolCallID {
				conf = 0.62
				rule = "dataflow.same_tool_call.secret_to_network.v1"
			}
			if conf == 0 {
				continue
			}
			key := src.NodeID + "|" + sink.NodeID + "|" + rule
			if seen[key] {
				continue
			}
			seen[key] = true
			derived = append(derived, GraphLensEdge{
				ID:       "derived/" + key,
				FromID:   src.NodeID,
				ToID:     sink.NodeID,
				EdgeType: "possible_sensitive_data_flow",
				// Stamp the inferred flow with the sink's time so a time-scrubbed
				// replay surfaces it at the moment the data actually left.
				CreatedAt:      sink.CreatedAt,
				Derived:        true,
				DerivationRule: rule,
				Confidence:     conf,
				EvidenceRefs:   []string{src.NodeID, sink.NodeID},
			})
		}
	}
	return derived
}

func deriveAggregatedDataFlowEdges(sources, sinks []lensEvent) []GraphLensEdge {
	type flowGroup struct {
		fromID       string
		toID         string
		rule         string
		confidence   float64
		createdAt    string
		sourceRefs   map[string]bool
		sinkRefs     map[string]bool
		paths        map[string]bool
		destinations map[string]bool
	}
	groups := map[string]*flowGroup{}
	for _, src := range sources {
		for _, sink := range sinks {
			if src.CreatedAt != "" && sink.CreatedAt != "" && sink.CreatedAt <= src.CreatedAt {
				continue
			}
			scopeID := ""
			scopeKey := ""
			conf := 0.0
			rule := ""
			if src.ProcessID != "" && src.ProcessID == sink.ProcessID {
				scopeID = src.ProcessID
				scopeKey = "process:" + src.ProcessID
				conf = 0.82
				rule = "dataflow.same_process.secret_to_network.aggregate.v1"
			} else if src.ToolCallID != "" && src.ToolCallID == sink.ToolCallID {
				scopeID = src.ToolCallID
				scopeKey = "tool_call:" + src.ToolCallID
				conf = 0.62
				rule = "dataflow.same_tool_call.secret_to_network.aggregate.v1"
			}
			if scopeID == "" {
				continue
			}
			toID := "egress_group/" + safeGraphID(scopeKey)
			key := scopeKey + "|" + rule
			group := groups[key]
			if group == nil {
				group = &flowGroup{
					fromID:       scopeID,
					toID:         toID,
					rule:         rule,
					confidence:   conf,
					sourceRefs:   map[string]bool{},
					sinkRefs:     map[string]bool{},
					paths:        map[string]bool{},
					destinations: map[string]bool{},
				}
				groups[key] = group
			}
			if group.createdAt == "" || (sink.CreatedAt != "" && sink.CreatedAt > group.createdAt) {
				group.createdAt = sink.CreatedAt
			}
			group.sourceRefs[src.NodeID] = true
			group.sinkRefs[sink.NodeID] = true
			if src.Path != "" {
				group.paths[src.Path] = true
			}
			if sink.Destination != "" {
				group.destinations[sink.Destination] = true
			}
		}
	}
	out := make([]GraphLensEdge, 0, len(groups))
	for key, group := range groups {
		refs := append(sortedBoolKeys(group.sourceRefs), sortedBoolKeys(group.sinkRefs)...)
		out = append(out, GraphLensEdge{
			ID:             "derived/" + safeGraphID(key),
			FromID:         group.fromID,
			ToID:           group.toID,
			EdgeType:       "possible_sensitive_data_flow_summary",
			CreatedAt:      group.createdAt,
			Derived:        true,
			DerivationRule: group.rule,
			Confidence:     group.confidence,
			EvidenceRefs:   capStringSlice(refs, 80),
			Data: map[string]any{
				"source_count":       len(group.sourceRefs),
				"sink_count":         len(group.sinkRefs),
				"omitted_evidence":   maxInt(0, len(refs)-80),
				"sensitive_paths":    capStringSlice(sortedBoolKeys(group.paths), 12),
				"destinations":       capStringSlice(sortedBoolKeys(group.destinations), 12),
				"source_event_count": len(group.sourceRefs),
				"sink_event_count":   len(group.sinkRefs),
			},
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt < out[j].CreatedAt
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func sortedLensNodes(nodes map[string]GraphLensNode, used map[string]bool) []GraphLensNode {
	out := make([]GraphLensNode, 0, len(used))
	for id := range used {
		node, ok := nodes[id]
		if !ok {
			node = inferLensNode(id)
		}
		out = append(out, node)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func splitAndLimitLensEdges(edges []GraphLensEdge, limit int) ([]GraphLensEdge, []GraphLensEdge, bool) {
	truncated := false
	if limit > 0 && len(edges) > limit {
		edges = edges[:limit]
		truncated = true
	}
	canonical := []GraphLensEdge{}
	derived := []GraphLensEdge{}
	for _, edge := range edges {
		if edge.Derived {
			derived = append(derived, edge)
		} else {
			canonical = append(canonical, edge)
		}
	}
	return canonical, derived, truncated
}

func buildGraphLensOverlays(nodes map[string]GraphLensNode, selected []GraphLensNode, overlays []string) []GraphLensOverlay {
	if len(overlays) == 0 {
		return nil
	}
	want := map[string]bool{}
	for _, overlay := range overlays {
		want[overlay] = true
	}
	var out []GraphLensOverlay
	for _, node := range selected {
		full := nodes[node.ID]
		if want["risk"] || want["security"] {
			if full.Risk != "" {
				out = append(out, GraphLensOverlay{TargetID: node.ID, Kind: "risk", Label: full.Risk, Severity: full.Risk})
			}
		}
		if want["trust"] && full.TrustOrigin != "" {
			out = append(out, GraphLensOverlay{TargetID: node.ID, Kind: "trust_origin", Label: full.TrustOrigin})
		}
	}
	return out
}

func cleanOverlays(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, raw := range values {
		for _, part := range strings.Split(raw, ",") {
			part = strings.ToLower(strings.TrimSpace(part))
			if part == "" || seen[part] {
				continue
			}
			seen[part] = true
			out = append(out, part)
		}
	}
	return out
}

func graphLensRules(lens string) []string {
	switch lens {
	case "security":
		return []string{"policy/risk/response edges", "high-risk runtime events"}
	case "process":
		return []string{"process tree", "tool_call->process", "process->runtime_event"}
	case "file-artifact":
		return []string{"workspace file edges", "artifact lineage"}
	case "network-egress":
		return []string{"network_connect", "metadata_ip", "private_cidr", "dns_query", "tls_read/write"}
	case "data-flow-taint":
		return []string{"secret/file source events", "network sink events", "derived possible_sensitive_data_flow"}
	case "agent-intent":
		return []string{"llm_call", "llm_intent_caused", "tool_call edges"}
	case "trust-origin":
		return []string{"trust_origin annotations", "agent/tool/artifact nodes"}
	case "sandbox-boundary":
		return []string{"boundary/tamper/privilege events", "snapshot/attempt edges"}
	default:
		return []string{"canonical graph edges"}
	}
}

func graphLensLayout(lens string) string {
	switch lens {
	case "security":
		return "signature_chain"
	case "process":
		return "process_tree"
	case "file-artifact":
		return "lineage"
	case "network-egress":
		return "egress_map"
	case "data-flow-taint":
		return "source_to_sink"
	case "agent-intent":
		return "intent_to_action"
	case "trust-origin":
		return "origin_overlay"
	case "sandbox-boundary":
		return "boundary_map"
	default:
		return "graph_explorer"
	}
}

func inferLensNode(id string) GraphLensNode {
	switch {
	case strings.HasPrefix(id, "runtime_event/"):
		return GraphLensNode{ID: id, Kind: "runtime_event", Label: lensShortRef(id)}
	case strings.HasPrefix(id, "runtime_process/"):
		return GraphLensNode{ID: id, Kind: "runtime_process", Label: lensShortRef(id), TrustOrigin: "runtime_observed"}
	case strings.HasPrefix(id, "workspace_file/"):
		return GraphLensNode{ID: id, Kind: "file", Label: strings.TrimPrefix(id, "workspace_file/"), TrustOrigin: "workspace_state"}
	case strings.HasPrefix(id, "egress_group/"):
		return GraphLensNode{ID: id, Kind: "runtime_event", Subtype: "egress_group", Label: "egress group", Risk: "high", TrustOrigin: "derived_summary"}
	case strings.HasPrefix(id, "policy_decision/"):
		return GraphLensNode{ID: id, Kind: "policy_decision", Label: lensShortRef(id)}
	case strings.HasPrefix(id, "risk_signal/"):
		return GraphLensNode{ID: id, Kind: "risk_signal", Label: lensShortRef(id)}
	case strings.HasPrefix(id, "response_action/"):
		return GraphLensNode{ID: id, Kind: "response_action", Label: lensShortRef(id)}
	default:
		return GraphLensNode{ID: id, Kind: "unknown", Label: lensShortRef(id)}
	}
}

func isSecurityKind(kind string) bool {
	return kind == "policy_decision" || kind == "risk_signal" || kind == "response_action"
}

func isNetworkEvent(eventType string) bool {
	switch eventType {
	case "network_connect", "metadata_ip", "private_cidr", "dns_query", "tls_write", "tls_read":
		return true
	default:
		return false
	}
}

func isSourceEvent(eventType, path string) bool {
	if eventType == "secret_path" {
		return true
	}
	if eventType != "file_open" {
		return false
	}
	path = strings.ToLower(path)
	return strings.Contains(path, ".ssh") || strings.Contains(path, ".aws") || strings.Contains(path, "credential") || strings.Contains(path, "secret") || strings.Contains(path, "token")
}

func isSinkEvent(eventType string) bool {
	return eventType == "network_connect" || eventType == "metadata_ip" || eventType == "private_cidr" || eventType == "tls_write"
}

func isBoundaryEvent(eventType string) bool {
	switch eventType {
	case "setuid", "setgid", "ptrace", "abnormal_process_tree", "file_rename", "file_unlink", "metadata_ip", "private_cidr":
		return true
	default:
		return false
	}
}

func riskForEventType(eventType string) string {
	switch eventType {
	case "metadata_ip", "private_cidr", "secret_path", "abnormal_process_tree", "setuid", "setgid", "ptrace":
		return "high"
	case "file_rename", "file_unlink":
		return "medium"
	default:
		return ""
	}
}

func riskForDecision(decision string) string {
	switch strings.ToLower(decision) {
	case "deny", "kill", "quarantine", "taint_snapshot":
		return "high"
	case "audit":
		return "medium"
	default:
		return ""
	}
}

func payloadString(payload string, keys ...string) string {
	var top map[string]any
	if json.Unmarshal([]byte(payload), &top) != nil {
		return ""
	}
	if inner, ok := top["payload"].(map[string]any); ok {
		top = inner
	}
	if raw, ok := top["raw"].(map[string]any); ok {
		top = raw
	}
	for _, key := range keys {
		if v, ok := top[key]; ok {
			switch typed := v.(type) {
			case string:
				return typed
			case float64:
				return fmt.Sprintf("%.0f", typed)
			}
		}
	}
	return ""
}

func sortedBoolKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func capStringSlice(values []string, limit int) []string {
	if limit <= 0 || len(values) <= limit {
		return values
	}
	return append([]string{}, values[:limit]...)
}

func safeGraphID(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_', r == '.', r == ':':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		return "unknown"
	}
	if len(out) > 120 {
		return out[:120]
	}
	return out
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func shortLabel(value, fallbackValue string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallbackValue
	}
	if len(value) > 48 {
		return value[:45] + "..."
	}
	return value
}

func lensShortRef(ref string) string {
	if idx := strings.LastIndex(ref, "/"); idx >= 0 && idx+1 < len(ref) {
		return ref[idx+1:]
	}
	return ref
}

func fallback(value, fallbackValue string) string {
	if strings.TrimSpace(value) == "" {
		return fallbackValue
	}
	return value
}
