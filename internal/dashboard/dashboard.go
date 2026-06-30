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
	"bytes"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

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
	mux.HandleFunc("GET /api/artifact", s.artifact)
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

// --- artifact content preview (Side Panel) ---

const (
	artifactPreviewBytes = 64 * 1024  // text shown to the user
	artifactReadBytes    = 8 << 20    // cap on what we'll read at all
)

type artifactResp struct {
	Kind      string `json:"kind"` // text | diff | binary | unavailable
	Ref       string `json:"ref,omitempty"`
	Source    string `json:"source,omitempty"` // object | file
	SHA256    string `json:"sha256,omitempty"`
	Size      int64  `json:"size"`
	Mime      string `json:"mime,omitempty"`
	Truncated bool   `json:"truncated"`
	Redacted  bool   `json:"redacted"`
	Content   string `json:"content,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// artifact serves a bounded, type-aware, secret-redacted preview of the content
// behind a graph node — the provenance object it was materialized into (by
// source_id/hash) or a recorded artifact file. It never serves arbitrary paths:
// only content registered for this run, capped at artifactReadBytes.
func (s Server) artifact(w http.ResponseWriter, r *http.Request) {
	run := r.URL.Query().Get("run")
	node := r.URL.Query().Get("node")
	if run == "" || node == "" {
		httpError(w, "run and node are required", 400)
		return
	}
	path, hash, source := s.resolveArtifactPath(run, node)
	if path == "" {
		writeJSON(w, artifactResp{Kind: "unavailable", Reason: "no stored content for this node"})
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		writeJSON(w, artifactResp{Kind: "unavailable", Ref: hash, Source: source, Reason: "content not present on this host"})
		return
	}
	resp := artifactResp{Ref: hash, Source: source, Size: info.Size()}
	if info.Size() > artifactReadBytes {
		resp.Kind = "unavailable"
		resp.Reason = "artifact too large to preview"
		writeJSON(w, resp)
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		resp.Kind = "unavailable"
		resp.Reason = "content unreadable"
		writeJSON(w, resp)
		return
	}
	if resp.SHA256 = hash; resp.SHA256 == "" {
		sum := sha256.Sum256(data)
		resp.SHA256 = "sha256:" + hex.EncodeToString(sum[:])
	}
	// Artifact objects wrap the file in a provenance envelope; show the file the
	// node produced, not the metadata wrapper. (Evidence objects — events, policy,
	// etc. — are left as-is so the panel shows the full signed record.)
	mimePath := path
	if content, srcPath, ok := unwrapArtifactContent(data); ok {
		data = content
		if srcPath != "" {
			mimePath = srcPath
		}
	}
	preview := data
	if len(preview) > artifactPreviewBytes {
		preview = preview[:artifactPreviewBytes]
		resp.Truncated = true
	}
	if isBinaryContent(preview) {
		resp.Kind = "binary"
		resp.Mime = "application/octet-stream"
		resp.Reason = "binary content — hash and size only"
		writeJSON(w, resp)
		return
	}
	red, didRedact := redactSecrets(string(preview))
	resp.Content = red
	resp.Redacted = didRedact
	resp.Mime = mimeForPath(mimePath)
	if looksLikeDiff(red) {
		resp.Kind = "diff"
	} else {
		resp.Kind = "text"
	}
	writeJSON(w, resp)
}

// resolveArtifactPath maps a graph node to a content source recorded for this run:
// first the provenance object it was materialized into (matched by source_id or
// hash, accepting a "prefix/<id>" node form), then a recorded artifact result file.
func (s Server) resolveArtifactPath(run, node string) (path, hash, source string) {
	seg := node
	if i := strings.LastIndex(node, "/"); i >= 0 {
		seg = node[i+1:]
	}
	row := s.DB.QueryRow(`SELECT path, hash FROM provenance_objects
		WHERE run_id = ? AND (source_id = ? OR source_id = ? OR hash = ? OR hash = ?) LIMIT 1`,
		run, node, seg, node, "sha256:"+strings.TrimPrefix(seg, "sha256:"))
	if err := row.Scan(&path, &hash); err == nil && path != "" {
		return path, hash, "object"
	}
	var p string
	if err := s.DB.QueryRow(`SELECT result_ref FROM tool_calls WHERE run_id = ? AND result_ref = ? AND result_ref != '' LIMIT 1`, run, node).Scan(&p); err == nil && p != "" {
		return p, "", "file"
	}
	if err := s.DB.QueryRow(`SELECT artifact_result FROM fork_attempts WHERE artifact_result = ? AND artifact_result != '' LIMIT 1`, node).Scan(&p); err == nil && p != "" {
		return p, "", "file"
	}
	return "", "", ""
}

// unwrapArtifactContent returns the file content inside an "artifact"-type
// provenance object envelope (and its original path for mime detection). Evidence
// envelopes (other types) return ok=false so they display as their full record.
func unwrapArtifactContent(data []byte) (content []byte, path string, ok bool) {
	var obj struct {
		Schema  string `json:"schema"`
		Type    string `json:"type"`
		Payload struct {
			Content string `json:"content"`
			Path    string `json:"path"`
		} `json:"payload"`
	}
	if json.Unmarshal(data, &obj) != nil {
		return nil, "", false
	}
	if obj.Schema != "agentprov.provenance.object.v1" || obj.Type != "artifact" || obj.Payload.Content == "" {
		return nil, "", false
	}
	return []byte(obj.Payload.Content), obj.Payload.Path, true
}

func isBinaryContent(data []byte) bool {
	if bytes.IndexByte(data, 0) >= 0 {
		return true
	}
	return !utf8.Valid(data)
}

func looksLikeDiff(text string) bool {
	if strings.HasPrefix(text, "diff --git ") || strings.HasPrefix(text, "--- ") || strings.HasPrefix(text, "Index: ") {
		return true
	}
	return diffHunkRe.MatchString(text)
}

func mimeForPath(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return "application/json"
	case ".py":
		return "text/x-python"
	case ".diff", ".patch":
		return "text/x-diff"
	case ".md":
		return "text/markdown"
	case ".sh":
		return "text/x-shellscript"
	case ".js", ".ts":
		return "text/javascript"
	default:
		return "text/plain"
	}
}

var (
	diffHunkRe   = regexp.MustCompile(`(?m)^@@ .* @@`)
	pemKeyRe     = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)
	awsKeyRe     = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	kvSecretRe   = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|aws_secret_access_key|authorization)(["']?\s*[:=]\s*["']?)([^\s"',}]{4,})`)
)

// redactSecrets masks the obvious secret shapes (private keys, cloud keys,
// password/token assignments) so a previewed artifact can't leak credentials —
// the demo plants fake secrets that the poisoned dependency exfiltrates, and the
// preview must show "it touched a secret" without re-displaying it.
func redactSecrets(text string) (string, bool) {
	redacted := false
	mark := func(re *regexp.Regexp, repl func(string) string) {
		if re.MatchString(text) {
			text = re.ReplaceAllStringFunc(text, repl)
			redacted = true
		}
	}
	mark(pemKeyRe, func(string) string { return "-----BEGIN PRIVATE KEY----- ***REDACTED*** -----END PRIVATE KEY-----" })
	mark(awsKeyRe, func(string) string { return "AKIA****************" })
	mark(kvSecretRe, func(m string) string {
		g := kvSecretRe.FindStringSubmatch(m)
		return g[1] + g[2] + "***REDACTED***"
	})
	return text, redacted
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
