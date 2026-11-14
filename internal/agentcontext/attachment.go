package agentcontext

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

type AttachmentRef struct {
	ContentRef
	SourceMediaType   string `json:"source_media_type"`
	SourceBytes       int64  `json:"source_bytes"`
	SourceSHA256      string `json:"source_sha256"`
	SourceDigestScope string `json:"source_digest_scope"`
	Width             int    `json:"width,omitempty"`
	Height            int    `json:"height,omitempty"`
	Transformation    string `json:"transformation,omitempty"`
	Privacy           string `json:"privacy,omitempty"`
}

// Data is transient and never serialized as context text or an entry field.
type AttachmentInput struct {
	MediaType    string
	Data         []byte
	SourceBytes  int64
	SourceSHA256 string
	DigestScope  string
	Reason       string
}

func notebookAttachment(media string, raw json.RawMessage) AttachmentInput {
	sum := sha256.Sum256(raw)
	a := AttachmentInput{MediaType: media, SourceBytes: int64(len(raw)), SourceSHA256: hex.EncodeToString(sum[:]), DigestScope: "source_json_value"}
	if media != "image/png" && media != "image/jpeg" {
		a.Reason = "unsupported_media_type"
		return a
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		a.Reason = "invalid_base64"
		return a
	}
	// Jupyter encoders may wrap base64 lines. No URLs, paths or arbitrary buffers
	// are followed; the JSONL byte and record budgets bound transient allocations.
	value = strings.NewReplacer("\r", "", "\n", "").Replace(value)
	if base64.StdEncoding.DecodedLen(len(value)) > provenance.MaxAttachmentBytes+2 {
		a.Reason = "attachment_size_limit"
		return a
	}
	data, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil {
		a.Reason = "invalid_base64"
		return a
	}
	if len(data) > provenance.MaxAttachmentBytes {
		a.Reason = "attachment_size_limit"
		return a
	}
	sum = sha256.Sum256(data)
	a.Data, a.SourceBytes, a.SourceSHA256, a.DigestScope = data, int64(len(data)), hex.EncodeToString(sum[:]), "decoded_source_bytes"
	return a
}

type attachmentBudget struct {
	known map[string]bool
	bytes int64
}

func loadAttachmentBudget(ctx context.Context, tx *sql.Tx, run string) (*attachmentBudget, error) {
	rows, err := tx.QueryContext(ctx, `SELECT hash,source_id FROM provenance_objects WHERE run_id=? AND object_type='attachment_content' LIMIT ?`, run, provenance.MaxAttachmentCount+1)
	if err != nil {
		return nil, err
	}
	var refs [][2]string
	for rows.Next() {
		var r [2]string
		if err := rows.Scan(&r[0], &r[1]); err != nil {
			rows.Close()
			return nil, err
		}
		refs = append(refs, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(refs) > provenance.MaxAttachmentCount {
		return nil, fmt.Errorf("run attachment count exceeds capture budget")
	}
	b := &attachmentBudget{known: map[string]bool{}}
	for _, r := range refs {
		a, err := provenance.ReadAttachmentManifest(tx, run, r[0])
		if err != nil {
			return nil, err
		}
		b.known[r[1]] = true
		b.bytes += a.Bytes
	}
	return b, nil
}

func (b *attachmentBudget) save(ctx context.Context, objects provenance.ObjectStore, run string, input AttachmentInput, retain bool) (AttachmentRef, error) {
	a := AttachmentRef{ContentRef: ContentRef{State: "omitted", MediaType: input.MediaType},
		SourceMediaType: input.MediaType, SourceBytes: input.SourceBytes, SourceSHA256: input.SourceSHA256, SourceDigestScope: input.DigestScope}
	if !retain {
		a.Reason = "capture_policy"
		return a, nil
	}
	if input.Reason != "" {
		a.Reason = input.Reason
		return a, nil
	}
	prepared, err := provenance.PrepareRasterAttachment(ctx, input.MediaType, input.Data)
	if err != nil {
		var invalid *provenance.AttachmentError
		if errors.As(err, &invalid) {
			a.Reason = invalid.Reason
			return a, nil
		}
		return a, err
	}
	m := prepared.Manifest()
	if m.SourceBytes != input.SourceBytes || m.SourceSHA256 != input.SourceSHA256 || input.DigestScope != "decoded_source_bytes" {
		return a, fmt.Errorf("attachment source identity mismatch")
	}
	known := b.known[prepared.SourceID()]
	if !known && (len(b.known) >= provenance.MaxAttachmentCount || b.bytes+m.Bytes > provenance.MaxRunAttachmentBytes) {
		a.Reason = "run_attachment_budget"
		return a, nil
	}
	saved, err := objects.PutAttachment(ctx, run, prepared)
	if err != nil {
		return a, err
	}
	if !known {
		b.known[prepared.SourceID()] = true
		b.bytes += m.Bytes
	}
	a.ContentRef = ContentRef{Ref: saved.Ref, State: "stored", Bytes: Number(m.Bytes), SHA256: m.SHA256, MediaType: m.MediaType, DigestScope: "stored_raster_bytes"}
	a.Width, a.Height, a.Transformation, a.Privacy = m.Width, m.Height, m.Transformation, m.Privacy
	return a, nil
}
