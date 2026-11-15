package capturemanifest

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// A receiver receipt describes processed input, not the upstream collector's
// configuration or a continuous capture interval.
func (s Service) batch(ctx context.Context, run string, e evidence) (Record, error) {
	r := initial(e)
	var format, fileHash, eventHash, memberType string
	var read, ingested, skipped, failed int64
	if err := s.DB.QueryRowContext(ctx, `SELECT format,file_sha256,event_ids_sha256,
		read_count,ingested_count,skipped_count,failed_count,json_type(event_ids_json)
		FROM telemetry_batches WHERE id=? AND run_id=?`, e.id, run).
		Scan(&format, &fileHash, &eventHash, &read, &ingested, &skipped, &failed, &memberType); err != nil {
		return r, err
	}
	if strings.TrimSpace(format) == "" || read < 0 || ingested < 0 || skipped < 0 || failed < 0 ||
		ingested > read || skipped > read-ingested || failed > read-ingested-skipped ||
		(memberType != "array" && memberType != "null") {
		return r, fmt.Errorf("invalid telemetry batch receipt")
	}
	if _, err := time.Parse(time.RFC3339Nano, e.recordedAt); err != nil {
		return r, fmt.Errorf("invalid telemetry batch processing time")
	}
	if fileHash != "" {
		digest, err := hex.DecodeString(fileHash)
		if err != nil || len(digest) != sha256.Size {
			return r, fmt.Errorf("invalid telemetry batch input digest")
		}
	}
	// Stream membership validation instead of loading the complete input or ID
	// list. The ordered digest is the existing telemetry batch contract.
	rows, err := s.DB.QueryContext(ctx, `SELECT j.type,j.value,e.id FROM telemetry_batches b,
		json_each(CASE WHEN json_type(b.event_ids_json)='array' THEN b.event_ids_json ELSE '[]' END) j
		LEFT JOIN events e ON e.id=j.value AND e.run_id=b.run_id
		WHERE b.id=? AND b.run_id=? ORDER BY CAST(j.key AS INTEGER)`, e.id, run)
	if err != nil {
		return r, err
	}
	defer rows.Close()
	h := sha256.New()
	var count int64
	for rows.Next() {
		var kind string
		var id, found sql.NullString
		if err := rows.Scan(&kind, &id, &found); err != nil {
			return r, err
		}
		if kind != "text" || !id.Valid || id.String == "" || !found.Valid {
			return r, fmt.Errorf("invalid telemetry batch event membership")
		}
		_, _ = h.Write([]byte(id.String))
		_, _ = h.Write([]byte{0})
		count++
	}
	if err := rows.Err(); err != nil {
		return r, err
	}
	if count != ingested || hex.EncodeToString(h.Sum(nil)) != eventHash {
		return r, fmt.Errorf("telemetry batch membership digest mismatch")
	}
	r.EvidenceRef, r.Source, r.IdentityDomain = "telemetry_batch/"+e.id, "telemetry_jsonl", "ingest_batch"
	r.IntervalBasis, r.Status = "source_processing_range", "processed"
	r.Identity = map[string]string{"batch_id": e.id, "format": format, "event_ids_sha256": eventHash}
	if fileHash == "" {
		r.Issues = append(r.Issues, "input_digest_not_recorded")
	} else {
		r.Identity["file_sha256"] = fileHash
	}
	r.Issues = append(r.Issues, "upstream_capabilities_not_recorded", "upstream_loss_not_recorded")
	r.Loss = []Counter{{Name: "upstream_dropped_events", Scope: "collector", Value: nil, Basis: "not_recorded"}}
	for _, v := range []struct {
		name  string
		value int64
	}{{"read", read}, {"ingested", ingested}, {"skipped", skipped}, {"failed", failed}, {"unclassified", read - ingested - skipped - failed}} {
		value := strconv.FormatInt(v.value, 10)
		r.Counts = append(r.Counts, Counter{Name: v.name, Scope: "processing_range", ScopeID: e.id, Value: &value, Basis: "saved_batch_receipt"})
		if v.value > 0 && (v.name == "failed" || v.name == "skipped" || v.name == "unclassified") {
			r.Status = "partial"
			if v.name == "unclassified" {
				r.Issues = append(r.Issues, "row_dispositions_not_recorded")
			}
		}
	}
	return r, nil
}
