// Package dashboard serves a local, read-only web view over the verifiable
// provenance graph: the runs, their merged timeline, the unified signals/risks,
// the verify+signature status, and -- the signature view -- the causality DAG
// (LLM intent -> action -> policy -> risk), which a flat event stream cannot
// show. It is a thin presentation layer: every JSON endpoint reuses the SAME
// internal functions as the CLI/AI tools (provenance.Verify, signals.Export,
// etc.), so the UI never diverges from the contract. Read-only, local-first:
// the HTML/JS is embedded in the binary and loads no external assets.
package dashboard

import (
	"database/sql"
	_ "embed"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	securitymodel "github.com/byteyellow/agentprovenance/internal/security"
	"github.com/byteyellow/agentprovenance/internal/signals"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

//go:embed index.html
var indexHTML []byte

// Server serves the dashboard over a single read-only *sql.DB.
type Server struct{ DB *sql.DB }

// Handler returns the dashboard's HTTP routes (static UI + JSON API).
func (s Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.index)
	mux.HandleFunc("GET /api/runs", s.runs)
	mux.HandleFunc("GET /api/overview", s.overview)
	mux.HandleFunc("GET /api/timeline", s.timeline)
	mux.HandleFunc("GET /api/graph", s.graph)
	mux.HandleFunc("GET /api/lens", s.lens)
	mux.HandleFunc("GET /api/egress", s.egress)
	mux.HandleFunc("GET /api/processes", s.processes)
	return mux
}

// rawBody unwraps the stored telemetry payload ({"payload":{"raw":{...}}} or
// {"raw":{...}} or a bare body) down to the raw event fields.
func rawBody(payload string) map[string]any {
	var top map[string]any
	if json.Unmarshal([]byte(payload), &top) != nil {
		return map[string]any{}
	}
	if inner, ok := top["payload"].(map[string]any); ok {
		top = inner
	}
	if raw, ok := top["raw"].(map[string]any); ok {
		return raw
	}
	return top
}

func firstStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// egress lists the run's outbound network attempts (the destination is the
// security-relevant fact), flagging the risky ones (metadata IP, private CIDR).
func (s Server) egress(w http.ResponseWriter, r *http.Request) {
	run := r.URL.Query().Get("run")
	if run == "" {
		httpError(w, "run is required", 400)
		return
	}
	rows, err := s.DB.Query(`SELECT event_type, payload, created_at FROM events
		WHERE run_id = ? AND event_type IN ('network_connect','metadata_ip','private_cidr','dns_query') ORDER BY created_at`, run)
	if err != nil {
		httpError(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var et, payload, created string
		if err := rows.Scan(&et, &payload, &created); err != nil {
			httpError(w, err.Error(), 500)
			return
		}
		raw := rawBody(payload)
		out = append(out, map[string]any{
			"type": et,
			"dst":  firstStr(raw, "host", "dst_ip", "dst"),
			"port": firstStr(raw, "port", "dst_port"),
			"comm": firstStr(raw, "comm"),
			"risk": et == "metadata_ip" || et == "private_cidr",
			"time": created,
		})
	}
	writeJSON(w, out)
}

// processes returns the run's OS process events (pid/ppid/command) so the client
// can render the process tree by parent pid.
func (s Server) processes(w http.ResponseWriter, r *http.Request) {
	run := r.URL.Query().Get("run")
	if run == "" {
		httpError(w, "run is required", 400)
		return
	}
	rows, err := s.DB.Query(`SELECT pid, ppid, event_type, payload, created_at FROM events
		WHERE run_id = ? AND event_type IN ('execve','process_observed') ORDER BY created_at`, run)
	if err != nil {
		httpError(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var pid, ppid int64
		var et, payload, created string
		if err := rows.Scan(&pid, &ppid, &et, &payload, &created); err != nil {
			httpError(w, err.Error(), 500)
			return
		}
		raw := rawBody(payload)
		out = append(out, map[string]any{
			"pid": pid, "ppid": ppid, "type": et,
			"command": firstStr(raw, "command", "comm"), "comm": firstStr(raw, "comm"), "time": created,
		})
	}
	writeJSON(w, out)
}

func (s Server) index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store") // always serve the latest embedded UI
	_, _ = w.Write(indexHTML)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func httpError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

type runSummary struct {
	Run    string `json:"run"`
	Events int    `json:"events"`
}

func (s Server) runs(w http.ResponseWriter, r *http.Request) {
	rows, err := s.DB.Query(`SELECT run_id, COUNT(*) FROM events WHERE run_id != ''
		GROUP BY run_id ORDER BY MAX(created_at) DESC`)
	if err != nil {
		httpError(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	out := []runSummary{}
	for rows.Next() {
		var rs runSummary
		if err := rows.Scan(&rs.Run, &rs.Events); err != nil {
			httpError(w, err.Error(), 500)
			return
		}
		out = append(out, rs)
	}
	writeJSON(w, out)
}

// overview bundles verify + signals + risks for one run in a single call.
func (s Server) overview(w http.ResponseWriter, r *http.Request) {
	run := r.URL.Query().Get("run")
	if run == "" {
		httpError(w, "run is required", 400)
		return
	}
	out := map[string]any{}
	if v, err := provenance.Verify(s.DB, run); err == nil {
		out["verify"] = v
	} else {
		out["verify"] = map[string]any{"error": err.Error()}
	}
	if sig, err := signals.Export(s.DB, run); err == nil {
		out["signals"] = sig
	}
	if risks, err := securitymodel.BuildRiskSignalsReport(s.DB, run); err == nil {
		out["risks"] = risks
	}
	writeJSON(w, out)
}

func (s Server) timeline(w http.ResponseWriter, r *http.Request) {
	run := r.URL.Query().Get("run")
	if run == "" {
		httpError(w, "run is required", 400)
		return
	}
	events, err := telemetry.ListEventsFiltered(s.DB, telemetry.Filter{RunID: run})
	if err != nil {
		httpError(w, err.Error(), 500)
		return
	}
	total := len(events)
	limit := atoiClamp(r.URL.Query().Get("limit"), 50, 1, 500)
	offset := atoiClamp(r.URL.Query().Get("offset"), 0, 0, total)
	end := offset + limit
	if end > total {
		end = total
	}
	page := events[offset:end]
	if page == nil {
		page = []telemetry.EventRecord{}
	}
	writeJSON(w, map[string]any{"events": page, "total": total, "limit": limit, "offset": offset})
}

func atoiClamp(s string, def, lo, hi int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		n = def
	}
	if n < lo {
		n = lo
	}
	if n > hi {
		n = hi
	}
	return n
}

func (s Server) lens(w http.ResponseWriter, r *http.Request) {
	run := r.URL.Query().Get("run")
	if run == "" {
		httpError(w, "run is required", 400)
		return
	}
	manifest, err := provenance.BuildGraphLens(s.DB, provenance.GraphLensOptions{
		RunID:    run,
		Lens:     r.URL.Query().Get("lens"),
		Focus:    r.URL.Query().Get("focus"),
		Overlays: r.URL.Query()["overlay"],
		Limit:    atoiClamp(r.URL.Query().Get("limit"), 500, 1, 2000),
	})
	if err != nil {
		httpError(w, err.Error(), 500)
		return
	}
	writeJSON(w, manifest)
}

// --- causality DAG (the signature view) ---

type graphNode struct {
	ID      string         `json:"id"`
	Label   string         `json:"label"`
	Kind    string         `json:"kind"`    // event | policy | risk | response
	Subtype string         `json:"subtype"` // event_type | decision | severity | status
	Detail  string         `json:"detail"`
	Data    map[string]any `json:"data,omitempty"` // full record for the click-through detail panel
}

type graphEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Type string `json:"type"`
}

// causalEdgeTypes is the curated set surfaced in the DAG: the intent chain and
// the enforcement chain. The noisy structural plumbing (runtime_attempt_event,
// runtime_process_observed, ...) is intentionally dropped so the hero story --
// model intent -> action -> policy -> risk -> response -- reads clearly.
var causalEdgeTypes = map[string]bool{
	"llm_call":                      true,
	"llm_intent_caused":             true,
	"runtime_event_policy_decision": true,
	"policy_decision_risk_signal":   true,
	"risk_signal_response_action":   true,
}

func (s Server) graph(w http.ResponseWriter, r *http.Request) {
	run := r.URL.Query().Get("run")
	if run == "" {
		httpError(w, "run is required", 400)
		return
	}
	nodes, err := s.nodeLabels(run)
	if err != nil {
		httpError(w, err.Error(), 500)
		return
	}
	rows, err := s.DB.Query(`SELECT from_id, to_id, edge_type FROM graph_edges
		WHERE run_id = ? ORDER BY created_at`, run)
	if err != nil {
		httpError(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	edges := []graphEdge{}
	used := map[string]bool{}
	seenEdge := map[string]bool{}
	for rows.Next() {
		var e graphEdge
		if err := rows.Scan(&e.From, &e.To, &e.Type); err != nil {
			httpError(w, err.Error(), 500)
			return
		}
		if !causalEdgeTypes[e.Type] {
			continue
		}
		key := e.From + "|" + e.To + "|" + e.Type
		if seenEdge[key] {
			continue
		}
		seenEdge[key] = true
		edges = append(edges, e)
		used[e.From] = true
		used[e.To] = true
	}
	outNodes := []graphNode{}
	for id := range used {
		if n, ok := nodes[id]; ok {
			outNodes = append(outNodes, n)
		} else {
			outNodes = append(outNodes, graphNode{ID: id, Label: shortRef(id), Kind: "other"})
		}
	}
	writeJSON(w, map[string]any{"nodes": outNodes, "edges": edges})
}

// nodeLabels builds rich labels for every node a curated edge might reference:
// events by their event_type, and the enforcement nodes by their actual verdict
// (decision / severity / action), so the verdict shows up IN the graph.
func (s Server) nodeLabels(run string) (map[string]graphNode, error) {
	nodes := map[string]graphNode{}
	add := func(n graphNode) { nodes[n.ID] = n }

	evRows, err := s.DB.Query(`SELECT id, event_type, COALESCE(correlation_method,''), COALESCE(correlation_confidence,0), COALESCE(created_at,''), COALESCE(payload,'')
		FROM events WHERE run_id = ?`, run)
	if err != nil {
		return nil, err
	}
	for evRows.Next() {
		var id, etype, method, created, payload string
		var conf float64
		if err := evRows.Scan(&id, &etype, &method, &conf, &created, &payload); err != nil {
			evRows.Close()
			return nil, err
		}
		add(graphNode{ID: "runtime_event/" + id, Label: etype, Kind: "event", Subtype: etype, Detail: method, Data: map[string]any{
			"event_id": id, "event_type": etype, "correlation_method": method, "correlation_confidence": conf, "created_at": created, "payload": payload,
		}})
	}
	evRows.Close()

	pdRows, err := s.DB.Query(`SELECT id, decision, COALESCE(rule_id,''), COALESCE(reason,'') FROM policy_decisions WHERE run_id = ?`, run)
	if err != nil {
		return nil, err
	}
	for pdRows.Next() {
		var id, decision, rule, reason string
		if err := pdRows.Scan(&id, &decision, &rule, &reason); err != nil {
			pdRows.Close()
			return nil, err
		}
		add(graphNode{ID: "policy_decision/" + id, Label: "policy: " + decision, Kind: "policy", Subtype: decision, Detail: reason, Data: map[string]any{
			"decision": decision, "rule_id": rule, "reason": reason,
		}})
	}
	pdRows.Close()

	rsRows, err := s.DB.Query(`SELECT id, signal_type, severity, COALESCE(reason,''), COALESCE(recommended_action,'') FROM risk_signals WHERE run_id = ?`, run)
	if err != nil {
		return nil, err
	}
	for rsRows.Next() {
		var id, stype, severity, reason, action string
		if err := rsRows.Scan(&id, &stype, &severity, &reason, &action); err != nil {
			rsRows.Close()
			return nil, err
		}
		add(graphNode{ID: "risk_signal/" + id, Label: stype, Kind: "risk", Subtype: severity, Detail: "recommended: " + action, Data: map[string]any{
			"signal_type": stype, "severity": severity, "reason": reason, "recommended_action": action,
		}})
	}
	rsRows.Close()

	raRows, err := s.DB.Query(`SELECT id, action_type, COALESCE(status,''), COALESCE(target_type,''), COALESCE(target_id,'') FROM response_actions WHERE run_id = ?`, run)
	if err != nil {
		return nil, err
	}
	for raRows.Next() {
		var id, atype, status, ttype, tid string
		if err := raRows.Scan(&id, &atype, &status, &ttype, &tid); err != nil {
			raRows.Close()
			return nil, err
		}
		add(graphNode{ID: "response_action/" + id, Label: "response: " + atype, Kind: "response", Subtype: status, Detail: status, Data: map[string]any{
			"action_type": atype, "status": status, "target": ttype + "/" + tid,
		}})
	}
	raRows.Close()

	return nodes, nil
}

func shortRef(ref string) string {
	if i := lastSlash(ref); i >= 0 && i+1 < len(ref) {
		return ref[:i]
	}
	return ref
}

func lastSlash(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			return i
		}
	}
	return -1
}
