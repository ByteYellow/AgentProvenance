package provenance

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/byteyellow/agentprovenance/internal/redact"
)

var ErrContentRange = errors.New("invalid content page range")
var ErrTextContentLimit = errors.New("text content exceeds capture limit")

const (
	MaxTextContentBytes = 32 << 20
	TextChunkBytes      = 128 << 10
	MaxContentPageBytes = 256 << 10
	textContentSchema   = "agentprovenance.text_content/v1"
)

type TextChunk struct {
	Ref   string `json:"ref"`
	Bytes int64  `json:"bytes"`
}

type TextManifest struct {
	SchemaVersion string      `json:"schema_version"`
	Bytes         int64       `json:"bytes"`
	SHA256        string      `json:"sha256"`
	MediaType     string      `json:"media_type"`
	Redacted      bool        `json:"redacted"`
	Chunks        []TextChunk `json:"chunks"`
}

type TextContentInput struct {
	RunID     string
	SourceID  string
	MediaType string
	Text      string
	// MaxBytes optionally narrows the source and redacted-byte budget.
	MaxBytes int64
}

type TextContent struct {
	Ref string `json:"ref"`
	TextManifest
}

type ContentPage struct {
	SchemaVersion string `json:"schema_version"`
	RunID         string `json:"run_id"`
	Ref           string `json:"ref"`
	Content       string `json:"content"`
	MediaType     string `json:"media_type"`
	Offset        int64  `json:"offset"`
	NextOffset    int64  `json:"next_offset"`
	TotalBytes    int64  `json:"total_bytes"`
	HasMore       bool   `json:"has_more"`
	SHA256        string `json:"sha256"`
	Redacted      bool   `json:"redacted"`
}

// PutTextContent masks the whole bounded value before splitting, so a secret
// spanning a chunk boundary cannot evade redaction. Chunks use existing signed
// provenance objects and remain below the historical bundle inline limit.
func (s ObjectStore) PutTextContent(input TextContentInput) (TextContent, error) {
	limit := int64(MaxTextContentBytes)
	if input.MaxBytes < 0 {
		return TextContent{}, fmt.Errorf("invalid text content budget")
	}
	if input.MaxBytes > 0 && input.MaxBytes < limit {
		limit = input.MaxBytes
	}
	if int64(len(input.Text)) > limit {
		return TextContent{}, fmt.Errorf("%w (%d bytes)", ErrTextContentLimit, limit)
	}
	if !utf8.ValidString(input.Text) {
		return TextContent{}, fmt.Errorf("text content is not UTF-8")
	}
	text, changed := redactText(input.Text, 0)
	if int64(len(text)) > limit {
		return TextContent{}, fmt.Errorf("%w after redaction (%d bytes)", ErrTextContentLimit, limit)
	}
	if input.MediaType == "" {
		input.MediaType = "text/plain; charset=utf-8"
	}
	sum := sha256.Sum256([]byte(text))
	manifest := TextManifest{
		SchemaVersion: textContentSchema, Bytes: int64(len(text)),
		SHA256: hex.EncodeToString(sum[:]), MediaType: input.MediaType,
		Redacted: changed, Chunks: []TextChunk{},
	}
	for pos := 0; pos < len(text); {
		end := pos + TextChunkBytes
		if end > len(text) {
			end = len(text)
		}
		for end < len(text) && !utf8.RuneStart(text[end]) {
			end--
		}
		part, err := s.PutExternalObject(ExternalObjectInput{
			Type: "text_chunk", RunID: input.RunID,
			SourceID: fmt.Sprintf("%s/chunk/%d", input.SourceID, len(manifest.Chunks)),
			Payload:  map[string]any{"kind": "text_chunk", "content": text[pos:end]},
		})
		if err != nil {
			return TextContent{}, err
		}
		manifest.Chunks = append(manifest.Chunks, TextChunk{Ref: part.Hash, Bytes: int64(end - pos)})
		pos = end
	}
	parents := make([]string, len(manifest.Chunks))
	for i, part := range manifest.Chunks {
		parents[i] = part.Ref
	}
	obj, err := s.PutExternalObject(ExternalObjectInput{
		Type: "text_content", RunID: input.RunID, SourceID: input.SourceID + "/content",
		Parents: parents, Payload: map[string]any{"kind": "stored_text", "text_manifest": manifest},
	})
	if err != nil {
		return TextContent{}, err
	}
	return TextContent{Ref: obj.Hash, TextManifest: manifest}, nil
}

// Decode JSON string escapes before matching credentials, including JSON tool
// arguments nested inside string values. Unchanged input keeps its source bytes.
func redactText(input string, depth int) (string, bool) {
	result, changed := redact.Redact(input)
	if depth >= 8 || !json.Valid([]byte(result)) {
		return result, changed
	}
	decoder := json.NewDecoder(bytes.NewBufferString(result))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil {
		return result, changed
	}
	modified := false
	var walk func(any) any
	walk = func(v any) any {
		switch x := v.(type) {
		case string:
			s, yes := redactText(x, depth+1)
			modified = modified || yes
			return s
		case []any:
			for i := range x {
				x[i] = walk(x[i])
			}
		case map[string]any:
			for key, val := range x {
				x[key] = walk(val)
			}
		}
		return v
	}
	value = walk(value)
	raw, err := json.Marshal(value)
	if err == nil {
		canonical, masked := redact.Redact(string(raw))
		if modified || masked {
			return canonical, true
		}
	}
	return result, changed
}

// VerifyTextContent validates the whole redacted byte stream, not just the
// manifest's own object hash. Reads remain page-bounded for large transcripts.
func VerifyTextContent(db *sql.DB, runID, ref string) error {
	hash := sha256.New()
	for offset := int64(0); ; {
		page, err := ReadTextContentPage(db, runID, ref, offset, MaxContentPageBytes)
		if err != nil {
			return err
		}
		_, _ = io.WriteString(hash, page.Content)
		if !page.HasMore {
			if hex.EncodeToString(hash.Sum(nil)) != page.SHA256 {
				return fmt.Errorf("text content digest mismatch")
			}
			return nil
		}
		if page.NextOffset <= offset {
			return fmt.Errorf("text content page did not advance")
		}
		offset = page.NextOffset
	}
}

// ReadTextContentPage uses run-scoped, hash-checked stored bytes, never a source
// transcript or a current workspace file. Offsets count redacted UTF-8 bytes.
func ReadTextContentPage(db *sql.DB, runID, ref string, offset, limit int64) (ContentPage, error) {
	var manifestObject struct {
		Payload struct {
			Kind     string       `json:"kind"`
			Manifest TextManifest `json:"text_manifest"`
		} `json:"payload"`
	}
	if err := readContentObject(db, runID, ref, &manifestObject); err != nil {
		return ContentPage{}, err
	}
	m := manifestObject.Payload.Manifest
	if manifestObject.Payload.Kind != "stored_text" || m.SchemaVersion != textContentSchema {
		return ContentPage{}, fmt.Errorf("unsupported text content manifest")
	}
	if m.Bytes < 0 || m.Bytes > MaxTextContentBytes || len(m.Chunks) > MaxTextContentBytes/(TextChunkBytes-utf8.UTFMax)+1 {
		return ContentPage{}, fmt.Errorf("invalid text content size")
	}
	var total int64
	for _, part := range m.Chunks {
		if part.Bytes <= 0 || part.Bytes > TextChunkBytes {
			return ContentPage{}, fmt.Errorf("invalid text chunk size")
		}
		total += part.Bytes
	}
	if total != m.Bytes {
		return ContentPage{}, fmt.Errorf("invalid text content length")
	}
	if offset < 0 || offset > m.Bytes {
		return ContentPage{}, fmt.Errorf("%w: offset exceeds stored content", ErrContentRange)
	}
	if limit <= 0 {
		limit = 64 << 10
	}
	if limit > MaxContentPageBytes {
		limit = MaxContentPageBytes
	}
	if limit < utf8.UTFMax {
		limit = utf8.UTFMax
	}
	end := offset + limit
	if end > m.Bytes {
		end = m.Bytes
	}
	var out strings.Builder
	var pos int64
	for _, part := range m.Chunks {
		next := pos + part.Bytes
		if next > offset && pos < end {
			var chunk struct {
				Payload struct {
					Kind    string `json:"kind"`
					Content string `json:"content"`
				} `json:"payload"`
			}
			if err := readContentObject(db, runID, part.Ref, &chunk); err != nil {
				return ContentPage{}, err
			}
			text := chunk.Payload.Content
			if chunk.Payload.Kind != "text_chunk" || int64(len(text)) != part.Bytes || !utf8.ValidString(text) {
				return ContentPage{}, fmt.Errorf("invalid stored text chunk")
			}
			start, stop := int64(0), part.Bytes
			if offset > pos {
				start = offset - pos
			}
			if start < part.Bytes && !utf8.RuneStart(text[start]) {
				return ContentPage{}, fmt.Errorf("%w: offset is not a UTF-8 boundary", ErrContentRange)
			}
			if end < next {
				stop = end - pos
				for stop > start && !utf8.RuneStart(text[stop]) {
					stop--
				}
			}
			out.WriteString(text[start:stop])
		}
		pos = next
		if pos >= end {
			break
		}
	}
	page := ContentPage{
		SchemaVersion: "agentprovenance.content_page/v1", RunID: runID, Ref: ref,
		Content: out.String(), MediaType: m.MediaType, Offset: offset,
		NextOffset: offset + int64(out.Len()), TotalBytes: m.Bytes, SHA256: m.SHA256, Redacted: m.Redacted,
	}
	page.HasMore = page.NextOffset < m.Bytes
	return page, nil
}

func readContentObject(db *sql.DB, runID, ref string, target any) error {
	if runID == "" || !strings.HasPrefix(ref, "sha256:") {
		return fmt.Errorf("run id and content hash are required")
	}
	var path string
	if err := db.QueryRow(`SELECT path FROM provenance_objects WHERE run_id = ? AND hash = ?`, runID, ref).Scan(&path); err != nil {
		return fmt.Errorf("stored content lookup: %w", err)
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("stored content is not a readable regular object")
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("stored content is unavailable: %w", err)
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("stored content is not a regular object")
	}
	raw, err := io.ReadAll(io.LimitReader(f, (2<<20)+1))
	if err != nil {
		return err
	}
	if len(raw) > 2<<20 {
		return fmt.Errorf("stored content object exceeds read limit")
	}
	sum := sha256.Sum256(raw)
	if "sha256:"+hex.EncodeToString(sum[:]) != ref {
		return fmt.Errorf("stored content hash mismatch")
	}
	var envelope struct {
		Schema string `json:"schema"`
		RunID  string `json:"run_id"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.Schema != "agentprov.provenance.object.v1" || envelope.RunID != runID {
		return fmt.Errorf("stored content schema or run mismatch")
	}
	return json.Unmarshal(raw, target)
}

// ReadObjectPayload loads a small registered object's payload. Large text lives
// in independently bounded chunks and must use ReadTextContentPage instead.
func ReadObjectPayload(db *sql.DB, runID, ref string, target any) error {
	var obj struct {
		Schema  string          `json:"schema"`
		RunID   string          `json:"run_id"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := readContentObject(db, runID, ref, &obj); err != nil {
		return err
	}
	if obj.Schema != "agentprov.provenance.object.v1" || obj.RunID != runID {
		return fmt.Errorf("stored object schema or run mismatch")
	}
	return json.Unmarshal(obj.Payload, target)
}
