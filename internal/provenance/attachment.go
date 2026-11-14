package provenance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	_ "image/jpeg"
	"image/png"
	"io"
	"path/filepath"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/redact"
)

const (
	AttachmentSchema      = "agentprovenance.raster_attachment/v1"
	MaxAttachmentBytes    = 8 << 20
	MaxAttachmentPixels   = 16 << 20
	AttachmentChunkBytes  = 128 << 10
	MaxAttachmentCount    = 256
	MaxRunAttachmentBytes = 64 << 20
)

type AttachmentManifest struct {
	SchemaVersion   string      `json:"schema_version"`
	MediaType       string      `json:"media_type"`
	Bytes           int64       `json:"bytes"`
	SHA256          string      `json:"sha256"`
	Width           int         `json:"width"`
	Height          int         `json:"height"`
	SourceMediaType string      `json:"source_media_type"`
	SourceBytes     int64       `json:"source_bytes"`
	SourceSHA256    string      `json:"source_sha256"`
	Transformation  string      `json:"transformation"`
	Privacy         string      `json:"privacy"`
	Chunks          []TextChunk `json:"chunks"`
}

type Attachment struct {
	Ref string `json:"ref"`
	AttachmentManifest
}

// PreparedAttachment keeps the validated raster private. Only these bytes may
// enter the binary writer, which intentionally does not redact pixel data.
type PreparedAttachment struct {
	manifest AttachmentManifest
	data     []byte
}

func (p PreparedAttachment) Manifest() AttachmentManifest { return p.manifest }
func (p PreparedAttachment) SourceID() string {
	return "raster/v1/" + p.manifest.SourceSHA256 + "/" + p.manifest.SHA256
}

type AttachmentError struct{ Reason string }

func (e *AttachmentError) Error() string { return "attachment: " + e.Reason }

// PrepareRasterAttachment retains a derived, static PNG. Reencoding strips
// source metadata and trailing data; both source and retained digests are named.
func PrepareRasterAttachment(ctx context.Context, media string, data []byte) (PreparedAttachment, error) {
	bad := func(reason string) (PreparedAttachment, error) {
		return PreparedAttachment{}, &AttachmentError{Reason: reason}
	}
	if err := ctx.Err(); err != nil {
		return PreparedAttachment{}, err
	}
	if media != "image/png" && media != "image/jpeg" {
		return bad("unsupported_media_type")
	}
	if len(data) == 0 {
		return bad("invalid_image")
	}
	if len(data) > MaxAttachmentBytes {
		return bad("attachment_size_limit")
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || "image/"+format != media {
		return bad("invalid_image")
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > 8192 || cfg.Height > 8192 || int64(cfg.Width)*int64(cfg.Height) > MaxAttachmentPixels {
		return bad("attachment_pixel_limit")
	}
	im, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return bad("invalid_image")
	}
	if err := ctx.Err(); err != nil {
		return PreparedAttachment{}, err
	}
	var dst attachmentBuffer
	if err := png.Encode(&dst, im); err != nil {
		return bad("attachment_size_limit")
	}
	source, saved := sha256.Sum256(data), sha256.Sum256(dst.Bytes())
	m := AttachmentManifest{SchemaVersion: AttachmentSchema, MediaType: "image/png", Bytes: int64(dst.Len()),
		SHA256: hex.EncodeToString(saved[:]), Width: cfg.Width, Height: cfg.Height,
		SourceMediaType: media, SourceBytes: int64(len(data)), SourceSHA256: hex.EncodeToString(source[:]),
		Transformation: "raster_reencode/v1", Privacy: "visual_content_unredacted", Chunks: []TextChunk{}}
	return PreparedAttachment{manifest: m, data: dst.Bytes()}, nil
}

type attachmentBuffer struct{ bytes.Buffer }

func (b *attachmentBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > MaxAttachmentBytes {
		return 0, &AttachmentError{Reason: "attachment_size_limit"}
	}
	return b.Buffer.Write(p)
}

func (s ObjectStore) PutAttachment(ctx context.Context, run string, p PreparedAttachment) (Attachment, error) {
	if s.DB == nil || run == "" || len(p.data) == 0 {
		return Attachment{}, fmt.Errorf("validated attachment, database and run are required")
	}
	if s.Paths.Provenance == "" {
		s.Paths.Provenance = filepath.Join(s.Paths.Root, "provenance")
	}
	c := materializeContext{store: s, runID: run, refHash: map[string]string{}}
	m := p.manifest
	m.Chunks = []TextChunk{}
	parents := []string{}
	for pos := 0; pos < len(p.data); pos += AttachmentChunkBytes {
		if err := ctx.Err(); err != nil {
			return Attachment{}, err
		}
		end := min(pos+AttachmentChunkBytes, len(p.data))
		part := p.data[pos:end]
		sum := sha256.Sum256(part)
		obj := c.prepareObject(provenanceObject{Type: "attachment_chunk", SourceID: "raster/chunk/" + hex.EncodeToString(sum[:]),
			Payload: map[string]any{"kind": "raster_chunk", "encoding": "base64", "bytes": len(part)}})
		// Redact only the envelope. Regex matches in base64 are not pixel secrets.
		raw, err := json.Marshal(obj)
		if err != nil {
			return Attachment{}, err
		}
		if err = json.Unmarshal([]byte(redact.RedactString(string(raw))), &obj); err != nil {
			return Attachment{}, err
		}
		obj.Payload["data"] = part
		raw, err = json.Marshal(obj)
		if err != nil {
			return Attachment{}, err
		}
		ref, err := c.persistObject(obj, raw)
		if err != nil {
			return Attachment{}, err
		}
		m.Chunks = append(m.Chunks, TextChunk{Ref: ref, Bytes: int64(len(part))})
		parents = append(parents, ref)
	}
	obj, err := s.PutExternalObject(ExternalObjectInput{RunID: run, Type: "attachment_content", SourceID: p.SourceID(),
		Parents: parents, Payload: map[string]any{"kind": "stored_raster", "attachment_manifest": m}})
	return Attachment{Ref: obj.Hash, AttachmentManifest: m}, err
}

func ReadAttachmentManifest(db contentObjectReader, run, ref string) (Attachment, error) {
	var obj struct {
		Type    string   `json:"type"`
		Parents []string `json:"parents"`
		Payload struct {
			Kind     string             `json:"kind"`
			Manifest AttachmentManifest `json:"attachment_manifest"`
		} `json:"payload"`
	}
	if err := readContentObject(db, run, ref, &obj); err != nil {
		return Attachment{}, err
	}
	m := obj.Payload.Manifest
	validDigest := func(s string) bool {
		b, err := hex.DecodeString(s)
		return err == nil && len(b) == 32 && strings.ToLower(s) == s
	}
	if obj.Type != "attachment_content" || obj.Payload.Kind != "stored_raster" || m.SchemaVersion != AttachmentSchema ||
		m.MediaType != "image/png" || (m.SourceMediaType != "image/png" && m.SourceMediaType != "image/jpeg") ||
		m.Transformation != "raster_reencode/v1" || m.Privacy != "visual_content_unredacted" ||
		m.Bytes <= 0 || m.Bytes > MaxAttachmentBytes || m.SourceBytes <= 0 || m.SourceBytes > MaxAttachmentBytes ||
		m.Width <= 0 || m.Height <= 0 || m.Width > 8192 || m.Height > 8192 || int64(m.Width)*int64(m.Height) > MaxAttachmentPixels ||
		!validDigest(m.SHA256) || !validDigest(m.SourceSHA256) || len(m.Chunks) == 0 || len(m.Chunks) > MaxAttachmentBytes/AttachmentChunkBytes || len(obj.Parents) != len(m.Chunks) {
		return Attachment{}, fmt.Errorf("invalid attachment manifest")
	}
	parents := map[string]int{}
	for _, parent := range obj.Parents {
		parents[parent]++
	}
	var total int64
	for i, part := range m.Chunks {
		if part.Bytes <= 0 || part.Bytes > AttachmentChunkBytes || (i < len(m.Chunks)-1 && part.Bytes != AttachmentChunkBytes) || parents[part.Ref] == 0 {
			return Attachment{}, fmt.Errorf("invalid attachment chunk manifest")
		}
		parents[part.Ref]--
		total += part.Bytes
	}
	if total != m.Bytes {
		return Attachment{}, fmt.Errorf("invalid attachment length")
	}
	return Attachment{Ref: ref, AttachmentManifest: m}, nil
}

type AttachmentPage struct {
	SchemaVersion string `json:"schema_version"`
	RunID         string `json:"run_id"`
	Ref           string `json:"ref"`
	MediaType     string `json:"media_type"`
	Encoding      string `json:"encoding"`
	Data          []byte `json:"data"`
	Offset        int64  `json:"offset"`
	NextOffset    int64  `json:"next_offset"`
	TotalBytes    int64  `json:"total_bytes"`
	HasMore       bool   `json:"has_more"`
	SHA256        string `json:"sha256"`
}

func ReadAttachmentPage(ctx context.Context, db contentObjectReader, run, ref string, offset, limit int64) (AttachmentPage, error) {
	if err := ctx.Err(); err != nil {
		return AttachmentPage{}, err
	}
	a, err := ReadAttachmentManifest(db, run, ref)
	if err != nil {
		return AttachmentPage{}, err
	}
	if offset < 0 || offset > a.Bytes || limit < 1 || limit > MaxContentPageBytes {
		return AttachmentPage{}, ErrContentRange
	}
	end := min(offset+limit, a.Bytes)
	p := AttachmentPage{SchemaVersion: AttachmentSchema, RunID: run, Ref: ref, MediaType: a.MediaType, Encoding: "base64",
		Data: []byte{}, Offset: offset, NextOffset: end, TotalBytes: a.Bytes, HasMore: end < a.Bytes, SHA256: a.SHA256}
	var pos int64
	for _, part := range a.Chunks {
		if err := ctx.Err(); err != nil {
			return AttachmentPage{}, err
		}
		if pos < end && pos+part.Bytes > offset {
			var obj struct {
				Type    string `json:"type"`
				Payload struct {
					Kind     string `json:"kind"`
					Encoding string `json:"encoding"`
					Bytes    int64  `json:"bytes"`
					Data     []byte `json:"data"`
				} `json:"payload"`
			}
			if err := readContentObject(db, run, part.Ref, &obj); err != nil {
				return AttachmentPage{}, err
			}
			if obj.Type != "attachment_chunk" || obj.Payload.Kind != "raster_chunk" || obj.Payload.Encoding != "base64" || obj.Payload.Bytes != part.Bytes || int64(len(obj.Payload.Data)) != part.Bytes {
				return AttachmentPage{}, fmt.Errorf("invalid attachment chunk")
			}
			p.Data = append(p.Data, obj.Payload.Data[max(0, offset-pos):min(part.Bytes, end-pos)]...)
		}
		pos += part.Bytes
	}
	return p, nil
}

func VerifyAttachment(ctx context.Context, db contentObjectReader, run, ref string) error {
	a, err := ReadAttachmentManifest(db, run, ref)
	if err != nil {
		return err
	}
	var b bytes.Buffer
	for offset := int64(0); offset < a.Bytes; {
		p, err := ReadAttachmentPage(ctx, db, run, ref, offset, MaxContentPageBytes)
		if err != nil {
			return err
		}
		b.Write(p.Data)
		offset = p.NextOffset
	}
	sum := sha256.Sum256(b.Bytes())
	if hex.EncodeToString(sum[:]) != a.SHA256 {
		return fmt.Errorf("attachment digest mismatch")
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(b.Bytes()))
	if err != nil || cfg.Width != a.Width || cfg.Height != a.Height {
		return fmt.Errorf("attachment image dimensions mismatch")
	}
	_, err = png.Decode(bytes.NewReader(b.Bytes()))
	if err != nil {
		return fmt.Errorf("attachment image decode failed: %w", err)
	}
	// Encoder compression can change between Go versions. Validate the retained
	// PNG structure instead of requiring a byte-identical recompression.
	raw := b.Bytes()
	for pos := 8; pos+12 <= len(raw); {
		n := int64(binary.BigEndian.Uint32(raw[pos : pos+4]))
		end := int64(pos) + 12 + n
		if end > int64(len(raw)) {
			break
		}
		kind := string(raw[pos+4 : pos+8])
		switch kind {
		case "IHDR", "PLTE", "tRNS", "IDAT":
		case "IEND":
			if end == int64(len(raw)) {
				return nil
			}
			return fmt.Errorf("attachment contains trailing bytes")
		default:
			return fmt.Errorf("attachment contains source metadata")
		}
		pos = int(end)
	}
	return fmt.Errorf("invalid attachment PNG structure")
}

var _ io.Writer = (*attachmentBuffer)(nil)
