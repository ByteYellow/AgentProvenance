package dashboard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/provenance"
)

// Comparison records are read projections of saved evidence. Keys identify
// comparable fields or observed sets, never paired sessions or tool steps.
type ComparisonRecord struct {
	Dimension       string                      `json:"dimension"`
	Key             string                      `json:"key"`
	Label           string                      `json:"label"`
	Operation       string                      `json:"operation"`
	EvidenceKind    string                      `json:"evidence_kind,omitempty"`
	Mechanism       string                      `json:"mechanism,omitempty"`
	ComparisonScope string                      `json:"comparison_scope,omitempty"`
	Value           *agentcontext.SnapshotValue `json:"value"`
	Partial         bool                        `json:"partial"`
	Evidence        SearchSource                `json:"evidence"`
}

type ComparisonIssue struct {
	SourceID  string `json:"source_id"`
	Dimension string `json:"dimension"`
	Code      string `json:"code"`
}

type ComparisonPage struct {
	SchemaVersion string             `json:"schema_version"`
	RunID         string             `json:"run_id"`
	Records       []ComparisonRecord `json:"records"`
	Issues        []ComparisonIssue  `json:"issues"`
	SourcesRead   int                `json:"sources_read"`
	HasMore       bool               `json:"has_more"`
	NextCursor    string             `json:"next_cursor,omitempty"`
}

func (s Server) compareRecords(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Has("session") || q.Has("harness") {
		httpError(w, "Run comparison does not accept a session filter", http.StatusBadRequest)
		return
	}
	page, err := s.ComparisonRecords(r.Context(), q.Get("run"), q.Get("cursor"))
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, agentcontext.ErrInvalidArgument) {
			code = http.StatusBadRequest
		} else if errors.Is(err, sql.ErrNoRows) {
			code = http.StatusNotFound
		}
		httpError(w, err.Error(), code)
		return
	}
	writeJSON(w, page)
}

func (s Server) ComparisonRecords(ctx context.Context, run, cursor string) (ComparisonPage, error) {
	result := ComparisonPage{SchemaVersion: "agentprovenance.comparison_records/v1", RunID: run,
		Records: []ComparisonRecord{}, Issues: []ComparisonIssue{}}
	page, err := s.SearchSources(ctx, SearchSourceOptions{RunID: run, Cursor: cursor})
	if err != nil {
		return result, err
	}
	result.HasMore, result.NextCursor, result.SourcesRead = page.HasMore, page.NextCursor, len(page.Sources)
	issue := func(source SearchSource, dimension, code string) {
		result.Issues = append(result.Issues, ComparisonIssue{SourceID: source.ID, Dimension: dimension, Code: code})
	}
	add := func(source SearchSource, dimension, operation, label string, value any, known, partial bool, identity ...string) {
		if len(identity) == 0 {
			identity = []string{label}
		}
		key, _ := json.Marshal(append([]string{dimension, operation}, identity...))
		r := ComparisonRecord{Dimension: dimension, Key: string(key), Label: label, Operation: operation, Evidence: source, Partial: partial}
		if known {
			v := comparisonValue(value)
			r.Value = &v
		}
		result.Records = append(result.Records, r)
	}
	// Read a catalog page's event payloads in one query, closing it before any
	// object/content reader uses the connection (also works with a pool of one).
	ids := []string{}
	for _, source := range page.Sources {
		if source.Category == "runtime" {
			ids = append(ids, strings.TrimPrefix(source.Node, "runtime_event/"))
		}
	}
	eventBodies := map[string]string{}
	if len(ids) > 0 {
		encoded, _ := json.Marshal(ids)
		rows, err := s.DB.QueryContext(ctx, `SELECT id, CASE WHEN length(CAST(payload AS BLOB))<=? THEN payload ELSE '' END
		 FROM events WHERE run_id=? AND id IN (SELECT value FROM json_each(?))`, artifactReadBytes, run, string(encoded))
		if err != nil {
			return result, err
		}
		for rows.Next() {
			var id, body string
			if err = rows.Scan(&id, &body); err != nil {
				rows.Close()
				return result, err
			}
			eventBodies[id] = body
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return result, err
		}
	}
	for _, source := range page.Sources {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if entry := source.Entry; entry != nil {
			if entry.ExecutionScope == "prior_context" {
				continue
			}
			if entry.Kind == "task" || entry.Kind == "message" && entry.Role == "user" {
				add(source, "task", "recorded_task", source.Harness, entry.Content.SHA256, entry.Content.State == "stored" && entry.Content.SHA256 != "", entry.Status == "source_truncated" || entry.Content.Redacted)
				continue
			}
			if entry.Kind != "configuration" {
				continue
			}
			fields, reason, err := (agentcontext.Service{DB: s.DB}).SnapshotFields(ctx, *entry)
			if err != nil {
				return result, err
			}
			if reason != "" {
				issue(source, "configuration", reason)
			}
			if len(fields) == 0 {
				add(source, "configuration", "configuration_unavailable", source.Harness+" · "+entry.Status, nil, false, true)
			}
			for _, field := range fields {
				label := source.Harness + " · " + field.Path
				key, _ := json.Marshal([]string{"configuration", source.Harness, field.Path})
				value := field.Value
				result.Records = append(result.Records, ComparisonRecord{Dimension: "configuration", Key: string(key),
					Label: label, Operation: "recorded_configuration", Value: &value, Evidence: source,
					Partial: reason != "" || entry.Status == "source_truncated" || entry.Content.Redacted})
			}
			continue
		}
		if source.Kind == "artifact" || source.Kind == "llm_message" {
			data, state, err := s.readArtifactObject(run, source.Node)
			if err != nil {
				return result, err
			}
			if state != "" {
				issue(source, source.Category, state)
				continue
			}
			var object struct {
				Payload map[string]any `json:"payload"`
			}
			if decodeComparisonJSON(data, &object) != nil {
				issue(source, source.Category, "invalid_saved_object")
				continue
			}
			p := object.Payload
			if source.Kind == "llm_message" {
				var request bool
				if err := s.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM graph_edges WHERE run_id=? AND to_id=? AND edge_type='llm_request')`, run, source.Node).Scan(&request); err != nil {
					return result, err
				}
				if !request {
					continue
				}
				semantics, _ := p["semantics"].(map[string]any)
				observation := provenance.OutboundObservation{Kind: "model_turn", Host: firstStr(semantics, "host"),
					HasSecret: hasNonEmptyList(semantics, "canary_hits"), EvidenceRef: source.Node}
				s.addComparisonOutbound(source, observation, add)
				continue
			}
			path := firstStr(p, "path")
			if path == "" && strings.HasPrefix(source.SourceID, "workspace_file/") {
				path = strings.TrimPrefix(source.SourceID, "workspace_file/")
			}
			if path == "" {
				continue
			}
			state, hash := firstStr(p, "content_state"), ""
			redacted := boolFromRaw(p, "redacted")
			if ref := firstStr(p, "content_ref"); ref != "" {
				body, err := provenance.ReadTextContentPage(s.DB, run, ref, 0, utf8.UTFMax)
				if err != nil {
					state = "unavailable"
				} else {
					hash, state, redacted = body.SHA256, "stored", body.Redacted
				}
			} else if text, ok := p["content"].(string); ok {
				sum := sha256.Sum256([]byte(text))
				hash, state = hex.EncodeToString(sum[:]), "stored"
			}
			known := state == "stored" && hash != ""
			add(source, "files", "saved_file_version", path, map[string]any{"sha256": hash, "redacted": redacted}, known, redacted)
			if !known {
				issue(source, "files", "file_body_not_available")
			}
			continue
		}
		if source.Category != "runtime" {
			continue
		}
		body, exists := eventBodies[strings.TrimPrefix(source.Node, "runtime_event/")]
		if !exists {
			return result, fmt.Errorf("comparison source changed while reading: %s", source.ID)
		}
		var payload map[string]any
		if body == "" || decodeComparisonJSON([]byte(body), &payload) != nil {
			dimension := "runtime"
			if accessComparisonKind(source.Kind) {
				dimension = "access_control"
			}
			issue(source, dimension, "event_body_unavailable")
			continue
		}
		if inner, ok := payload["payload"].(map[string]any); ok {
			payload = inner
		}
		if raw, ok := payload["raw"].(map[string]any); ok {
			payload = raw
		}
		if accessComparisonKind(source.Kind) {
			records, issues := comparisonAccessControl(source, payload)
			result.Records = append(result.Records, records...)
			result.Issues = append(result.Issues, issues...)
			continue
		}
		if firstStr(payload, "observation_stage") == "attempt_and_result" &&
			(source.Kind == "file_open" || source.Kind == "secret_path" || source.Kind == "network_connect") {
			resultSource := source
			resultSource.Kind = "syscall_result"
			records, issues := comparisonAccessControl(resultSource, payload)
			for i := range records {
				records[i].Evidence = source
			}
			result.Records = append(result.Records, records...)
			result.Issues = append(result.Issues, issues...)
		}
		fields := func(keys ...string) map[string]any {
			out := map[string]any{}
			for _, key := range keys {
				if value, ok := payload[key]; ok {
					out[key] = value
				}
			}
			return out
		}
		switch source.Kind {
		case "file_open", "file_write", "secret_path", "file_rename", "file_unlink":
			path := firstStr(payload, "path", "filename")
			if path == "" {
				issue(source, "files", "file_target_not_recorded")
				continue
			}
			operation := source.Kind
			if source.SourceID == "record_file_diff" {
				operation = "recorded_file_change"
			}
			add(source, "files", operation, path, fields("op", "mode", "flags", "ret", "errno", "new_path"), true, false)
		case "network_connect", "metadata_ip", "private_cidr", "dns_query", "tls_write", "tls_read":
			op := "connection_attempt"
			host := firstStr(payload, "dst_host", "host", "dst_ip", "dst")
			path, port := "", comparisonScalar(payload, "port", "dst_port")
			value := fields("ret", "errno", "protocol")
			if source.Kind == "dns_query" {
				op = "dns_lookup"
			}
			if source.SourceID == "endpoint_capture" {
				op, path = "captured_request", firstStr(payload, "path")
				value = fields("policy_decision", "blocked", "status_code", "method")
				observation := provenance.OutboundObservation{Kind: endpointObservationKind(payload, ""), Host: host, Path: path,
					Blocked: boolFromRaw(payload, "blocked"), HasSecret: hasNonEmptyList(payload, "canary_hits"),
					IsSourceCode: boolFromRaw(payload, "codebase_payload") || boolFromRaw(payload, "is_git_bundle"),
					EvidenceRef:  source.Node}
				if n, ok := payload["bytes"].(json.Number); ok {
					count, _ := n.Int64()
					if count > 0 {
						observation.Bytes = int(count)
					}
				}
				observation.HasBehavioralMetadata = observation.Kind == "analytics_payload"
				s.addComparisonOutbound(source, observation, add)
			}
			if source.Kind == "tls_write" || source.Kind == "tls_read" {
				http, ok := payload["http"].(map[string]any)
				if !ok {
					issue(source, "network", "http_metadata_not_recorded")
					continue
				}
				host, path = firstStr(http, "host", "authority"), firstStr(http, "path", "target")
				value = map[string]any{}
				for _, key := range []string{"method", "status", "status_code", "protocol"} {
					if v, ok := http[key]; ok {
						value[key] = v
					}
				}
				op = "http_request_observed"
				if source.Kind == "tls_read" {
					op = "http_response_observed"
				}
			} else if source.SourceID != "endpoint_capture" {
				kind := "network"
				if source.Kind == "dns_query" {
					kind = "dns"
				}
				s.addComparisonOutbound(source, provenance.OutboundObservation{Kind: kind, Host: host, EvidenceRef: source.Node}, add)
			}
			if host == "" {
				issue(source, "network", "network_target_not_recorded")
			}
			label := host
			if port != "" {
				label += ":" + port
			}
			label += path
			if label == "" {
				label = "unknown"
			}
			add(source, "network", op, label, value, host != "" || len(value) > 0, host == "" || boolFromRaw(payload, "truncated"), host, port, path)
		}
	}
	return result, ctx.Err()
}

func (s Server) addComparisonOutbound(source SearchSource, observation provenance.OutboundObservation,
	add func(SearchSource, string, string, string, any, bool, bool, ...string)) {
	for _, surface := range provenance.BuildOutboundSurfaces([]provenance.OutboundObservation{observation}) {
		label := observation.Host + observation.Path
		if label == "" {
			label = "unknown"
		}
		add(source, "outbound", surface.ChannelClass, label, map[string]any{"data_class": surface.DataClass,
			"evidence_level": surface.EvidenceLevel, "decision": surface.Decision}, observation.Host != "", false, observation.Host, observation.Path)
	}
}

func decodeComparisonJSON(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return fmt.Errorf("unexpected data after saved JSON")
	}
	return nil
}

func comparisonScalar(value map[string]any, keys ...string) string {
	for _, key := range keys {
		switch v := value[key].(type) {
		case string:
			if v != "" {
				return v
			}
		case json.Number:
			return v.String()
		}
	}
	return ""
}

func comparisonValue(value any) agentcontext.SnapshotValue {
	encoded, _ := json.Marshal(value)
	sum := sha256.Sum256(encoded)
	r := agentcontext.SnapshotValue{Present: true, SHA256: hex.EncodeToString(sum[:]), Truncated: len(encoded) > 512}
	if r.Truncated {
		encoded = encoded[:512]
		for len(encoded) > 0 && !utf8.Valid(encoded) {
			encoded = encoded[:len(encoded)-1]
		}
	}
	r.Preview = string(encoded)
	return r
}
