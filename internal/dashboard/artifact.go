package dashboard

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/byteyellow/agentprovenance/internal/i18n"
	"github.com/byteyellow/agentprovenance/internal/provenance"
)

const (
	artifactPreviewBytes = 64 << 10
	artifactReadBytes    = 8 << 20 // Legacy envelopes only; new text uses bounded chunks.
	artifactVersionLimit = 50
)

type artifactVersion struct {
	Ref      string `json:"ref"`
	SourceID string `json:"source_id"`
}

type artifactResp struct {
	SchemaVersion   string            `json:"schema_version"`
	Kind            string            `json:"kind"` // text | diff | binary | unavailable
	Ref             string            `json:"ref,omitempty"`
	Source          string            `json:"source,omitempty"` // object | db; never a live workspace file
	ContentRef      string            `json:"content_ref,omitempty"`
	ContentState    string            `json:"content_state"`
	Integrity       string            `json:"integrity,omitempty"`
	SHA256          string            `json:"sha256,omitempty"` // Whole redacted display body, not the object envelope.
	Size            int64             `json:"size"`
	Mime            string            `json:"mime,omitempty"`
	Mode            string            `json:"mode"`
	Truncated       bool              `json:"truncated"` // Compatibility: this page does not contain the whole body.
	Redacted        bool              `json:"redacted"`
	Content         string            `json:"content,omitempty"`
	Reason          string            `json:"reason,omitempty"`
	Offset          int64             `json:"offset"`
	NextOffset      int64             `json:"next_offset"`
	TotalBytes      *int64            `json:"total_bytes"` // Null when the stored body is unavailable.
	HasMore         bool              `json:"has_more"`
	Versions        []artifactVersion `json:"versions,omitempty"`
	VersionsHasMore bool              `json:"versions_has_more,omitempty"`
}

// artifact reads only run-scoped saved evidence. A result_ref that names a live
// file is not a historical body. Paging never falls back to that file.
func (s Server) artifact(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	run, node, mode := q.Get("run"), q.Get("node"), q.Get("mode")
	if run == "" || node == "" {
		httpError(w, "run and node are required", http.StatusBadRequest)
		return
	}
	if mode == "" {
		mode = "body"
	}
	if mode != "body" && mode != "raw" {
		httpError(w, "mode must be body or raw", http.StatusBadRequest)
		return
	}
	offset, err := artifactRange(q.Get("offset"), 0)
	if err != nil {
		httpError(w, err.Error(), http.StatusBadRequest)
		return
	}
	limit, err := artifactRange(q.Get("limit"), artifactPreviewBytes)
	if err != nil || limit < utf8.UTFMax || limit > provenance.MaxContentPageBytes {
		httpError(w, "limit must be between 4 and 262144 bytes", http.StatusBadRequest)
		return
	}
	lang, _ := i18n.Parse(q.Get("view_lang"))
	resp := artifactResp{SchemaVersion: "agentprovenance.artifact_page/v1", Kind: "unavailable", ContentState: "legacy_not_recorded", Mode: mode}
	versions, more, err := s.artifactVersions(run, node)
	if err != nil {
		httpError(w, "saved evidence lookup failed", http.StatusInternalServerError)
		return
	}
	if len(versions) > 1 {
		resp.ContentState, resp.Reason = "ambiguous", "Multiple saved versions exist; select an exact object."
		resp.Versions, resp.VersionsHasMore = versions, more
		writeJSON(w, resp)
		return
	}
	var data []byte
	mimePath := "evidence.txt"
	if len(versions) == 0 {
		if strings.HasPrefix(node, "workspace_file/") {
			state, reason, found, err := s.artifactFileState(run, strings.TrimPrefix(node, "workspace_file/"))
			if err != nil {
				httpError(w, "recorded file capture lookup failed", http.StatusInternalServerError)
				return
			}
			if found {
				resp.Source, resp.Integrity, resp.ContentState, resp.Reason = "db", "database_record", state, reason
				writeJSON(w, resp)
				return
			}
		}
		content, found, err := s.nodeDBContentLocale(run, node, lang, mode)
		if err != nil {
			httpError(w, "recorded content lookup failed", http.StatusInternalServerError)
			return
		}
		if !found {
			resp.Reason = "No saved body for this node; current files are not historical evidence."
			writeJSON(w, resp)
			return
		}
		resp.Source, resp.Integrity = "db", "database_record"
		if content == nil {
			resp.ContentState, resp.Reason = "read_limit", "Legacy record exceeds the bounded read limit."
			writeJSON(w, resp)
			return
		}
		data = content
	} else {
		resp.Ref, resp.Source = versions[0].Ref, "object"
		var state string
		data, state, err = s.readArtifactObject(run, resp.Ref)
		if err != nil {
			httpError(w, "saved evidence lookup failed", http.StatusInternalServerError)
			return
		}
		if state != "" {
			resp.ContentState = state
			switch state {
			case "integrity_failure":
				resp.Reason = "Saved content failed its object hash or envelope check."
			case "read_limit":
				resp.Reason = "Legacy object exceeds the bounded read limit."
			default:
				resp.Reason = "Saved content is unavailable in this store."
			}
			writeJSON(w, resp)
			return
		}
		resp.Integrity = "object_hash_verified"
		var obj struct {
			Type    string `json:"type"`
			Payload struct {
				Kind         string  `json:"kind"`
				Path         string  `json:"path"`
				Content      *string `json:"content"`
				ContentRef   string  `json:"content_ref"`
				ContentState string  `json:"content_state"`
				Reason       string  `json:"reason"`
				Redacted     bool    `json:"redacted"`
			} `json:"payload"`
		}
		// Non-artifact objects may use a structured content field. Only decode
		// the body-specific payload after identifying an artifact envelope.
		var header struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal(data, &header)
		if mode == "body" && (header.Type == "artifact" || header.Type == "text_content") {
			if json.Unmarshal(data, &obj) != nil {
				resp.ContentState, resp.Reason = "integrity_failure", "Saved artifact has an invalid content descriptor."
				writeJSON(w, resp)
				return
			}
			p := obj.Payload
			if p.Kind == "stored_text" {
				p.ContentRef = resp.Ref
			}
			if p.ContentRef != "" {
				page, err := provenance.ReadTextContentPage(s.DB, run, p.ContentRef, offset, limit)
				if err != nil {
					if errors.Is(err, provenance.ErrContentRange) {
						httpError(w, err.Error(), http.StatusBadRequest)
						return
					}
					resp.ContentState, resp.Reason = "unavailable", "Saved text or its referenced chunks are missing or invalid."
					writeJSON(w, resp)
					return
				}
				resp.Kind, resp.ContentState, resp.ContentRef = "text", "stored", p.ContentRef
				resp.Content, resp.Mime, resp.Redacted = page.Content, page.MediaType, page.Redacted
				resp.SHA256, resp.Size, resp.TotalBytes = page.SHA256, page.TotalBytes, &page.TotalBytes
				resp.Offset, resp.NextOffset, resp.HasMore, resp.Truncated = page.Offset, page.NextOffset, page.HasMore, page.HasMore
				if strings.HasSuffix(p.Path, ".patch") || strings.HasSuffix(p.Path, ".diff") || looksLikeDiff(page.Content) {
					resp.Kind = "diff"
				}
				writeJSON(w, resp)
				return
			}
			if p.Content != nil {
				data, mimePath, resp.Redacted = []byte(*p.Content), p.Path, p.Redacted
			} else {
				resp.ContentState, resp.Reason = p.ContentState, p.Reason
				if resp.ContentState == "" {
					resp.ContentState = "legacy_not_recorded"
				}
				if resp.Reason == "" {
					resp.Reason = "Only artifact metadata was saved; select the raw record to inspect it."
				}
				writeJSON(w, resp)
				return
			}
		} else if mode == "body" {
			if rendered, ok := renderLLMMessageLocale(data, lang); ok {
				data, mimePath = rendered, "llm-message.txt"
			}
		}
	}
	if isBinaryContent(data) {
		resp.Kind, resp.ContentState, resp.Reason = "binary", "binary", "Binary content is not rendered as text."
		resp.Size = int64(len(data))
		writeJSON(w, resp)
		return
	}
	// Legacy objects can predate capture-time masking. Mask the whole bounded
	// body before slicing, otherwise page boundaries can expose partial secrets.
	text, redacted := redactSecrets(string(data))
	if offset > int64(len(text)) || offset < int64(len(text)) && !utf8.RuneStart(text[offset]) {
		httpError(w, "offset must be a stored UTF-8 byte boundary", http.StatusBadRequest)
		return
	}
	end := min(offset+limit, int64(len(text)))
	for end < int64(len(text)) && !utf8.RuneStart(text[end]) {
		end--
	}
	sum := sha256.Sum256([]byte(text))
	resp.Kind, resp.ContentState = "text", "stored"
	if mode == "body" && looksLikeDiff(text) {
		resp.Kind = "diff"
	}
	resp.Content, resp.Mime = text[offset:end], mimeForPath(mimePath)
	resp.Redacted = resp.Redacted || redacted
	resp.Size, resp.SHA256 = int64(len(text)), hex.EncodeToString(sum[:])
	resp.TotalBytes = &resp.Size
	resp.Offset, resp.NextOffset, resp.HasMore = offset, end, end < int64(len(text))
	resp.Truncated = resp.HasMore
	writeJSON(w, resp)
}

// A bounded file selection may omit a descriptor but still record a file event.
// Preserve its explicit capture state instead of labelling a new limit as legacy.
func (s Server) artifactFileState(run, path string) (string, string, bool, error) {
	rows, err := s.DB.Query(`SELECT DISTINCT substr(COALESCE(json_extract(p,'$.payload.content_state'),json_extract(p,'$.content_state'),'legacy_not_recorded'),1,128)
		FROM (SELECT CASE WHEN json_valid(payload) THEN payload ELSE '{}' END AS p FROM events
		WHERE run_id=? AND source='record_file_diff' AND event_type='file_write')
		WHERE COALESCE(json_extract(p,'$.payload.path'),json_extract(p,'$.path'))=? LIMIT 2`, run, path)
	if err != nil {
		return "", "", false, err
	}
	defer rows.Close()
	var states []string
	for rows.Next() {
		var state string
		if err := rows.Scan(&state); err != nil {
			return "", "", false, err
		}
		states = append(states, state)
	}
	if err := rows.Err(); err != nil {
		return "", "", false, err
	}
	if len(states) == 0 {
		return "", "", false, nil
	}
	if len(states) > 1 {
		return "ambiguous", "Saved file records disagree about capture state; inspect their exact events.", true, nil
	}
	state := states[0]
	reason := "No saved body for this node; current files are not historical evidence."
	switch state {
	case "collection_limit":
		reason = "File content was omitted by the capture budget."
	case "failed":
		reason = "Artifact evidence could not be stored."
	case "source_missing":
		reason = "The file was absent at post-execution capture."
	case "binary_omitted":
		reason = "Binary file content is not saved by the text capture path."
	case "stored":
		state, reason = "unavailable", "Saved content is unavailable in this store."
	case "legacy_not_recorded", "unavailable":
	default:
		state = "unavailable"
	}
	return state, reason, true, nil
}

func artifactRange(value string, fallback int64) (int64, error) {
	if value == "" {
		return fallback, nil
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid content page range")
	}
	return n, nil
}

// Object hashes are exact; source IDs can have immutable revisions. Do not
// silently select the first or newest revision, nor match unrelated basenames.
func (s Server) artifactVersions(run, node string) ([]artifactVersion, bool, error) {
	rows, err := s.DB.Query(`SELECT hash, source_id FROM provenance_objects WHERE run_id = ? AND hash = ?`, run, node)
	if err != nil {
		return nil, false, err
	}
	var versions []artifactVersion
	for rows.Next() {
		var v artifactVersion
		if err := rows.Scan(&v.Ref, &v.SourceID); err != nil {
			rows.Close()
			return nil, false, err
		}
		versions = append(versions, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(versions) > 0 || strings.HasPrefix(node, "sha256:") {
		return versions, false, err
	}
	source := node
	if strings.HasPrefix(node, "runtime_event/") {
		source = strings.TrimPrefix(node, "runtime_event/")
	}
	rows, err = s.DB.Query(`SELECT hash, source_id FROM provenance_objects WHERE run_id = ? AND source_id = ? ORDER BY hash LIMIT ?`, run, source, artifactVersionLimit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var v artifactVersion
		if err := rows.Scan(&v.Ref, &v.SourceID); err != nil {
			return nil, false, err
		}
		versions = append(versions, v)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	more := len(versions) > artifactVersionLimit
	if more {
		versions = versions[:artifactVersionLimit]
	}
	return versions, more, nil
}

func (s Server) readArtifactObject(run, ref string) ([]byte, string, error) {
	var path string
	if err := s.DB.QueryRow(`SELECT path FROM provenance_objects WHERE run_id = ? AND hash = ?`, run, ref).Scan(&path); err != nil {
		return nil, "", err
	}
	// Reject special files before opening; even a damaged object index must not
	// turn a read-only preview into a blocking FIFO/device read.
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, "unavailable", nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, "unavailable", nil
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, "unavailable", nil
	}
	if info.Size() > artifactReadBytes {
		return nil, "read_limit", nil
	}
	raw, err := io.ReadAll(io.LimitReader(f, artifactReadBytes+1))
	if err != nil {
		return nil, "unavailable", nil
	}
	if len(raw) > artifactReadBytes {
		return nil, "read_limit", nil
	}
	sum := sha256.Sum256(raw)
	if "sha256:"+hex.EncodeToString(sum[:]) != ref {
		return nil, "integrity_failure", nil
	}
	var envelope struct {
		Schema string `json:"schema"`
		RunID  string `json:"run_id"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.Schema != "agentprov.provenance.object.v1" || envelope.RunID != run {
		return nil, "integrity_failure", nil
	}
	return raw, "", nil
}

func (s Server) nodeDBContentLocale(run, node string, lang i18n.Locale, mode string) ([]byte, bool, error) {
	if strings.HasPrefix(node, "runtime_event/") {
		var eventType string
		var payload sql.NullString
		err := s.DB.QueryRow(`SELECT event_type, CASE WHEN length(CAST(COALESCE(payload,'') AS BLOB)) <= ? THEN COALESCE(payload,'') END
			FROM events WHERE run_id = ? AND id = ?`, artifactReadBytes, run, strings.TrimPrefix(node, "runtime_event/")).Scan(&eventType, &payload)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		if !payload.Valid {
			return nil, true, nil
		}
		if mode == "raw" {
			return []byte(payload.String), true, nil
		}
		var b bytes.Buffer
		fmt.Fprintf(&b, i18n.T(lang, "event: %s\n\n"), eventType)
		b.WriteString(payload.String)
		return b.Bytes(), true, nil
	}
	var cmd, savedStatus, savedPolicy sql.NullString
	err := s.DB.QueryRow(`SELECT CASE WHEN bytes <= ? THEN command END,
		CASE WHEN bytes <= ? THEN status END, CASE WHEN bytes <= ? THEN policy END
		FROM (SELECT COALESCE(command,'') AS command, COALESCE(status,'') AS status,
		COALESCE(policy_decision,'') AS policy,
		length(CAST(COALESCE(command,'') AS BLOB)) + length(CAST(COALESCE(status,'') AS BLOB)) + length(CAST(COALESCE(policy_decision,'') AS BLOB)) AS bytes
		FROM tool_calls WHERE run_id = ? AND id = ?)`, artifactReadBytes, artifactReadBytes, artifactReadBytes, run, node).Scan(&cmd, &savedStatus, &savedPolicy)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !cmd.Valid {
		return nil, true, nil
	}
	status, policy := savedStatus.String, savedPolicy.String
	if mode == "raw" {
		b, err := json.Marshal(map[string]string{"command": cmd.String, "status": status, "policy_decision": policy})
		return b, true, err
	}
	var b bytes.Buffer
	if status != "" {
		fmt.Fprintf(&b, i18n.T(lang, "status: %s"), status)
		if policy != "" && policy != "allow" {
			fmt.Fprintf(&b, "   (%s)", policy)
		}
		b.WriteString("\n\n")
	}
	b.WriteString(cmd.String)
	return b.Bytes(), true, nil
}
