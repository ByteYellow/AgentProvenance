package agentcontext

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

const (
	maxComparisonBytes = 1 << 20
	maxSnapshotChanges = 200
	maxSnapshotPreview = 512
)

type SnapshotValue struct {
	Present   bool   `json:"present"`
	Preview   string `json:"preview,omitempty"`
	Truncated bool   `json:"truncated"`
	SHA256    string `json:"sha256,omitempty"`
}

type SnapshotChange struct {
	Path   string        `json:"path"`
	Before SnapshotValue `json:"before"`
	After  SnapshotValue `json:"after"`
}

// SnapshotComparison compares recorded values, not effective permissions.
// An absent field means "not recorded here", never allowed, denied, or revoked.
type SnapshotComparison struct {
	SchemaVersion string           `json:"schema_version"`
	Scope         string           `json:"scope"`
	Status        string           `json:"status"`
	Left          Entry            `json:"left"`
	Right         Entry            `json:"right"`
	Changes       []SnapshotChange `json:"changes"`
	HasMore       bool             `json:"has_more"`
	Reason        string           `json:"reason,omitempty"`
}

func (s Service) entry(ctx context.Context, runID, id string) (Entry, error) {
	if runID == "" || id == "" || len(runID) > 512 || len(id) > 512 {
		return Entry{}, fmt.Errorf("%w: run and entry ids are required", ErrInvalidArgument)
	}
	var hash, created string
	if err := s.DB.QueryRowContext(ctx, `SELECT object_hash, created_at FROM agent_context_entries WHERE run_id=? AND id=?`, runID, id).Scan(&hash, &created); err != nil {
		return Entry{}, err
	}
	var e Entry
	if err := provenance.ReadObjectPayload(s.DB, runID, hash, &e); err != nil {
		return Entry{}, err
	}
	if e.ID != id || e.RunID != runID || e.SchemaVersion != SchemaVersion {
		return Entry{}, fmt.Errorf("context entry identity mismatch")
	}
	e.ObjectHash, e.CreatedAt = hash, created
	return e, nil
}

func (s Service) CompareSnapshots(ctx context.Context, runID, leftID, rightRunID, rightID string) (SnapshotComparison, error) {
	if rightRunID == "" {
		rightRunID = runID
	}
	result := SnapshotComparison{SchemaVersion: SchemaVersion, Scope: "recorded_values", Status: "unknown", Changes: []SnapshotChange{}}
	var err error
	result.Left, err = s.entry(ctx, runID, leftID)
	if err != nil {
		return result, err
	}
	result.Right, err = s.entry(ctx, rightRunID, rightID)
	if err != nil {
		return result, err
	}
	kind := func(e Entry) string {
		if e.Kind == "message" && e.Role == "user" {
			return "task"
		}
		return e.Kind
	}
	leftKind, rightKind := kind(result.Left), kind(result.Right)
	if leftKind != rightKind || (leftKind != "task" && leftKind != "configuration" && leftKind != "approval") {
		return result, fmt.Errorf("%w: select two task, configuration, or approval records of the same kind", ErrInvalidArgument)
	}
	left, reason, err := s.comparisonBody(ctx, result.Left)
	if err != nil || reason != "" {
		result.Reason = reason
		return result, err
	}
	right, reason, err := s.comparisonBody(ctx, result.Right)
	if err != nil || reason != "" {
		result.Reason = reason
		return result, err
	}
	decode := func(b []byte) any {
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.UseNumber()
		var v, extra any
		if dec.Decode(&v) == nil && dec.Decode(&extra) == io.EOF {
			return v
		}
		return string(b)
	}
	a := map[string]any{"status": result.Left.Status, "content": decode(left)}
	b := map[string]any{"status": result.Right.Status, "content": decode(right)}
	result.Status = "same"
	if !reflect.DeepEqual(a, b) {
		result.Status = "different"
		diffSnapshots(&result, "", a, true, b, true, 0)
	}
	return result, nil
}

func (s Service) comparisonBody(ctx context.Context, e Entry) ([]byte, string, error) {
	if e.Content.State != "stored" {
		return nil, "content_not_recorded", nil
	}
	var body []byte
	for offset := int64(0); ; {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		p, err := provenance.ReadTextContentPage(s.DB, e.RunID, e.Content.Ref, offset, provenance.MaxContentPageBytes)
		if err != nil {
			return nil, "", err
		}
		if e.Content.Bytes == nil || p.TotalBytes != *e.Content.Bytes || p.SHA256 != e.Content.SHA256 {
			return nil, "", fmt.Errorf("context content metadata mismatch")
		}
		if p.TotalBytes > maxComparisonBytes {
			return nil, "comparison_content_limit", nil
		}
		body = append(body, p.Content...)
		if !p.HasMore {
			return body, "", nil
		}
		offset = p.NextOffset
	}
}

func diffSnapshots(out *SnapshotComparison, path string, a any, ap bool, b any, bp bool, depth int) {
	if ap == bp && reflect.DeepEqual(a, b) {
		return
	}
	if len(out.Changes) >= maxSnapshotChanges {
		out.HasMore = true
		return
	}
	if depth < 32 && ap && bp {
		am, aok := a.(map[string]any)
		bm, bok := b.(map[string]any)
		if aok && bok {
			keys := make([]string, 0, len(am)+len(bm))
			for key := range am {
				keys = append(keys, key)
			}
			for key := range bm {
				if _, ok := am[key]; !ok {
					keys = append(keys, key)
				}
			}
			sort.Strings(keys)
			for _, key := range keys {
				av, aexists := am[key]
				bv, bexists := bm[key]
				escaped := strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")
				diffSnapshots(out, path+"/"+escaped, av, aexists, bv, bexists, depth+1)
				if out.HasMore {
					break
				}
			}
			return
		}
		aa, aok := a.([]any)
		ba, bok := b.([]any)
		if aok && bok {
			for i := 0; i < max(len(aa), len(ba)); i++ {
				var av, bv any
				if i < len(aa) {
					av = aa[i]
				}
				if i < len(ba) {
					bv = ba[i]
				}
				diffSnapshots(out, path+"/"+strconv.Itoa(i), av, i < len(aa), bv, i < len(ba), depth+1)
				if out.HasMore {
					break
				}
			}
			return
		}
	}
	out.Changes = append(out.Changes, SnapshotChange{Path: path, Before: snapshotValue(a, ap), After: snapshotValue(b, bp)})
}

func snapshotValue(value any, present bool) SnapshotValue {
	result := SnapshotValue{Present: present}
	if !present {
		return result
	}
	b, _ := json.Marshal(value)
	hash := sha256.Sum256(b)
	result.SHA256 = hex.EncodeToString(hash[:])
	if len(b) > maxSnapshotPreview {
		result.Truncated = true
		b = b[:maxSnapshotPreview]
		for len(b) > 0 && !utf8.Valid(b) {
			b = b[:len(b)-1]
		}
	}
	result.Preview = string(b)
	return result
}
