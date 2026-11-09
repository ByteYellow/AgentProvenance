package provenance

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

const endpointAssociationRule = "agentprov.endpoint_attribution/v2"

type endpointAssociation struct {
	RuleVersion  string               `json:"rule_version"`
	ObservedAt   string               `json:"observed_at,omitempty"`
	IngestedAt   string               `json:"ingested_at"`
	ContentMatch endpointContentMatch `json:"content_match"`
	SourceReads  endpointSourceReads  `json:"source_reads"`
	Execution    endpointExecution    `json:"execution"`
}

type endpointContentMatch struct {
	Status  string   `json:"status"`
	Markers []string `json:"markers,omitempty"`
	Paths   []string `json:"paths,omitempty"`
}

type endpointSourceReads struct {
	Status               string                  `json:"status"`
	Candidates           []endpointReadCandidate `json:"candidates"`
	UnresolvedReferences []string                `json:"unresolved_references,omitempty"`
}

type endpointReadCandidate struct {
	EventID      string   `json:"event_id"`
	Path         string   `json:"path"`
	ObservedAt   string   `json:"observed_at,omitempty"`
	ProcessID    string   `json:"process_id,omitempty"`
	ToolCallID   string   `json:"tool_call_id,omitempty"`
	Status       string   `json:"status"`
	Basis        []string `json:"basis"`
	EvidenceRefs []string `json:"evidence_refs"`
}

type endpointExecution struct {
	Status       string   `json:"status"`
	EventID      string   `json:"event_id,omitempty"`
	SessionID    string   `json:"session_id,omitempty"`
	ProcessID    string   `json:"process_id,omitempty"`
	ToolCallID   string   `json:"tool_call_id,omitempty"`
	Basis        []string `json:"basis,omitempty"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
}

// This is a lexical path identity, never a filesystem lookup on the importing
// machine. Relative paths keep an explicit context gap when cwd is unavailable.
func endpointFilePath(value, cwd string) (string, bool) {
	if value == "" {
		return "", false
	}
	if path.IsAbs(value) {
		return path.Clean(value), true
	}
	if path.IsAbs(cwd) && !strings.HasPrefix(value, "~") {
		return path.Clean(path.Join(cwd, value)), true
	}
	return path.Clean(value), false
}

func endpointTimeRange(value string) (time.Time, time.Time, bool) {
	at, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, time.Time{}, false
	}
	precision := time.Second
	if dot := strings.IndexByte(value, '.'); dot >= 0 {
		for i := dot + 1; i < len(value) && value[i] >= '0' && value[i] <= '9' && precision > time.Nanosecond; i++ {
			precision /= 10
		}
	}
	return at, at.Add(precision), true
}

func endpointReadOrder(read, capture string) string {
	rs, re, rok := endpointTimeRange(read)
	cs, ce, cok := endpointTimeRange(capture)
	if !rok || !cok {
		return "time_unknown"
	}
	if !rs.Before(ce) {
		return "read_after_capture"
	}
	if !re.After(cs) {
		return "read_before_capture"
	}
	return "time_precision_overlap"
}

func endpointFields(raw string) map[string]any {
	var value map[string]any
	if json.Unmarshal([]byte(raw), &value) != nil {
		return nil
	}
	if nested, ok := value["payload"].(map[string]any); ok {
		value = nested
	}
	if nested, ok := value["raw"].(map[string]any); ok {
		for k, v := range nested {
			if _, exists := value[k]; !exists {
				value[k] = v
			}
		}
	}
	return value
}

func endpointString(value map[string]any, keys ...string) string {
	for _, key := range keys {
		if s, ok := value[key].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func endpointBodyVersions(body []byte, cwd string) map[string][]string {
	var value struct {
		Files []struct {
			Path    string `json:"path"`
			Content any    `json:"content"`
		} `json:"files"`
	}
	versions := map[string][]string{}
	if json.Unmarshal(body, &value) != nil {
		return versions
	}
	for _, file := range value.Files {
		name, _ := endpointFilePath(file.Path, cwd)
		if content, ok := file.Content.(string); ok {
			versions[name] = append(versions[name], fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(content))))
		}
	}
	return versions
}

func buildEndpointAssociation(db *sql.Tx, run string, m endpointMeta, body []byte, paths []string, now string) (endpointAssociation, error) {
	a := endpointAssociation{RuleVersion: endpointAssociationRule, ObservedAt: m.ObservedAt, IngestedAt: now,
		ContentMatch: endpointContentMatch{Status: "not_matched", Paths: paths},
		SourceReads:  endpointSourceReads{Status: "unknown", Candidates: []endpointReadCandidate{}}, Execution: endpointExecution{Status: "unknown"}}
	for _, marker := range m.CanaryHits {
		if marker != "" && bytes.Contains(body, []byte(marker)) {
			a.ContentMatch.Markers = append(a.ContentMatch.Markers, marker)
		}
	}
	a.ContentMatch.Markers = dedupStrings(a.ContentMatch.Markers)
	if len(a.ContentMatch.Markers) > 0 {
		a.ContentMatch.Status = "matched"
	} else if len(dedupStrings(m.CanaryHits)) > 0 {
		a.ContentMatch.Status = "capture_reported"
	}
	var err error
	a.Execution, err = endpointExecutionAnchor(db, run, m)
	if err != nil {
		return a, err
	}
	requested := map[string]bool{}
	for _, ref := range m.SourceReadEvents {
		id := strings.TrimPrefix(ref, "runtime_event/")
		if id != "" && !requested[id] {
			requested[id] = true
			a.SourceReads.UnresolvedReferences = append(a.SourceReads.UnresolvedReferences, "runtime_event/"+id)
		}
	}
	sort.Strings(a.SourceReads.UnresolvedReferences)
	if len(paths) == 0 {
		a.SourceReads.Status = "path_unavailable"
		return a, nil
	}
	targets := map[string]bool{}
	for _, p := range paths {
		name, absolute := endpointFilePath(p, m.WorkingDirectory)
		targets[name] = absolute
	}
	versions := endpointBodyVersions(body, m.WorkingDirectory)
	resolved := map[string]bool{}
	rows, err := db.Query(`SELECT id,COALESCE(process_id,''),COALESCE(tool_call_id,''),payload,created_at FROM events
		WHERE run_id=? AND source!='endpoint_capture' AND event_type IN ('secret_path','file_open','openat') ORDER BY id`, run)
	if err != nil {
		return a, err
	}
	defer rows.Close()
	linked := 0
	for rows.Next() {
		var id, process, tool, raw, at string
		if err := rows.Scan(&id, &process, &tool, &raw, &at); err != nil {
			return a, err
		}
		p := endpointFields(raw)
		file, absolute := endpointFilePath(endpointString(p, "path"), endpointString(p, "cwd", "working_directory"))
		targetAbsolute, ok := targets[file]
		if !ok || file == "" {
			continue
		}
		order := endpointReadOrder(at, m.ObservedAt)
		if order == "read_after_capture" {
			continue
		}
		basis := []string{"structured_path_match", order}
		if !absolute || !targetAbsolute {
			basis = append(basis, "path_context_unknown")
		}
		version := endpointString(p, "content_sha256", "file_sha256")
		versionMatches := false
		if version != "" && len(versions[file]) > 0 {
			version = "sha256:" + strings.TrimPrefix(version, "sha256:")
			for _, hash := range versions[file] {
				if hash == version {
					versionMatches = true
				}
			}
			if !versionMatches {
				continue
			}
			basis = append(basis, "content_sha256_match")
		}
		c := endpointReadCandidate{EventID: id, Path: file, ObservedAt: at, ProcessID: process, ToolCallID: tool, Status: "candidate", Basis: basis, EvidenceRefs: []string{"runtime_event/" + id}}
		// A path/time candidate stays inferred. A capture-provided read reference
		// additionally needs the exact saved byte version and an execution anchor.
		if requested[id] && versionMatches && absolute && targetAbsolute && order == "read_before_capture" && a.Execution.Status == "bound" {
			c.Status = "linked"
			linked++
			resolved[id] = true
			c.Basis = append(c.Basis, "capture_source_reference")
			c.EvidenceRefs = append(c.EvidenceRefs, a.Execution.EvidenceRefs...)
		}
		a.SourceReads.Candidates = append(a.SourceReads.Candidates, c)
	}
	if err := rows.Err(); err != nil {
		return a, err
	}
	unresolved := a.SourceReads.UnresolvedReferences[:0]
	for _, ref := range a.SourceReads.UnresolvedReferences {
		if !resolved[strings.TrimPrefix(ref, "runtime_event/")] {
			unresolved = append(unresolved, ref)
		}
	}
	a.SourceReads.UnresolvedReferences = unresolved
	switch n := len(a.SourceReads.Candidates); {
	case linked > 0 && linked == n:
		a.SourceReads.Status = "linked"
	case linked > 0:
		a.SourceReads.Status = "partial"
	case n > 1:
		a.SourceReads.Status = "ambiguous"
	case n == 1:
		a.SourceReads.Status = "candidate"
	}
	return a, nil
}

func endpointExecutionAnchor(db *sql.Tx, run string, m endpointMeta) (endpointExecution, error) {
	a := endpointExecution{Status: "unknown"}
	if m.RuntimeEventID == "" {
		return a, nil
	}
	a.EventID = strings.TrimPrefix(m.RuntimeEventID, "runtime_event/")
	a.EvidenceRefs = []string{"runtime_event/" + a.EventID}
	var source, kind, raw, at string
	err := db.QueryRow(`SELECT source,event_type,payload,created_at,COALESCE(session_id,''),COALESCE(process_id,''),COALESCE(tool_call_id,'') FROM events WHERE run_id=? AND id=?`, run, a.EventID).Scan(&source, &kind, &raw, &at, &a.SessionID, &a.ProcessID, &a.ToolCallID)
	if err == sql.ErrNoRows {
		a.Basis = []string{"execution_reference_unavailable"}
		return a, nil
	}
	if err != nil {
		return a, err
	}
	fields := endpointFields(raw)
	host := endpointString(fields, "dst_host", "host", "dst_ip")
	if source == "endpoint_capture" || (kind != "network_connect" && kind != "private_cidr" && kind != "metadata_ip") || host == "" || !strings.EqualFold(strings.TrimSuffix(host, "."), strings.TrimSuffix(m.Host, ".")) || endpointReadOrder(at, m.ObservedAt) == "read_after_capture" {
		a.Status = "conflicting"
		a.Basis = []string{"execution_reference_conflict"}
		a.SessionID, a.ProcessID, a.ToolCallID = "", "", ""
		return a, nil
	}
	if a.ProcessID == "" && a.ToolCallID == "" {
		a.Basis = []string{"execution_identity_missing"}
		a.SessionID = ""
		return a, nil
	}
	a.Status = "bound"
	a.Basis = []string{"capture_operation_reference", "same_run", "destination_match"}
	return a, nil
}

func endpointEdgeMetadata(edge *GraphLensEdge, raw string) error {
	switch edge.EdgeType {
	case "endpoint_egress_payload", "sensitive_source_payload", "payload_egress_attempt", "confirmed_sensitive_data_flow", "candidate_sensitive_data_flow", "endpoint_execution_reference":
	default:
		return nil
	}
	var value struct {
		Association *endpointAssociation `json:"endpoint_association"`
		PayloadRef  string               `json:"payload_ref"`
	}
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return fmt.Errorf("endpoint edge %s: %w", edge.ID, err)
	}
	if value.Association == nil || value.Association.RuleVersion == "" {
		return nil
	}
	a := value.Association
	edge.Derived, edge.DerivationRule = true, a.RuleVersion
	edge.EvidenceRefs = dedupStrings([]string{edge.FromID, edge.ToID, value.PayloadRef})
	status := a.ContentMatch.Status
	switch edge.EdgeType {
	case "candidate_sensitive_data_flow", "confirmed_sensitive_data_flow":
		for _, c := range a.SourceReads.Candidates {
			if edge.FromID == "runtime_event/"+c.EventID {
				status = c.Status
				edge.EvidenceRefs = dedupStrings(append(edge.EvidenceRefs, c.EvidenceRefs...))
			}
		}
	case "endpoint_execution_reference":
		status = a.Execution.Status
		edge.EvidenceRefs = dedupStrings(append(edge.EvidenceRefs, a.Execution.EvidenceRefs...))
	}
	edge.Data = map[string]any{"association_status": status}
	return nil
}
