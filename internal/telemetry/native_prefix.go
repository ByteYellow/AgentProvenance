package telemetry

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

const NativePrefixSchema = "agentprovenance.native_spool_prefix/v1"
const maxNativePrefixBatches = 4096

// NativePrefix freezes the accepted spool backlog, not the kernel ring or the
// sensor's decoding queue. CollectorID and Sequence identify the accepting
// process epoch; Batches can be retried after that process exits.
type NativePrefix struct {
	SchemaVersion string              `json:"schema_version"`
	Boundary      string              `json:"boundary"`
	CollectorID   string              `json:"collector_id"`
	Sequence      uint64              `json:"sequence"`
	ObservedAt    time.Time           `json:"observed_at"`
	Counters      map[string]int64    `json:"counters"`
	Batches       []NativePrefixBatch `json:"batches"`
}

type NativePrefixBatch struct {
	ID         string `json:"id"`
	SHA256     string `json:"sha256"`
	EventCount int64  `json:"event_count"`
}

type NativePrefixProgress struct {
	State          string    `json:"state"` // pending or settled; settled includes reported drops/failures
	ObservedAt     time.Time `json:"observed_at"`
	Batches        int       `json:"batches"`
	PendingBatches int       `json:"pending_batches"`
	Events         int64     `json:"events"`
	Ingested       int64     `json:"ingested"`
	Dropped        int64     `json:"dropped"`
	Failed         int64     `json:"failed"`
	Pending        int64     `json:"pending"`
	CleanupPending int       `json:"cleanup_pending"`
	LastError      string    `json:"last_error,omitempty"`
	pending        []string
}

// SnapshotPrefix seals the current file under the capture lock, then snapshots
// metadata in one read transaction. Already committed batches need no replay.
// A partial JSON line must be completed before it can belong to a checkpoint.
func (n *NativeStream) SnapshotPrefix(ctx context.Context) (NativePrefix, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return NativePrefix{}, os.ErrClosed
	}
	if len(n.partial) != 0 {
		return NativePrefix{}, fmt.Errorf("native spool checkpoint has a partial input line")
	}
	if err := n.sealContext(ctx); err != nil {
		return NativePrefix{}, err
	}
	tx, err := n.service.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return NativePrefix{}, err
	}
	defer tx.Rollback()
	p := NativePrefix{SchemaVersion: NativePrefixSchema, Boundary: "accepted_spool", CollectorID: n.producerID,
		Sequence: n.accepted, ObservedAt: time.Now().UTC(), Counters: map[string]int64{}, Batches: []NativePrefixBatch{}}
	rows, err := tx.QueryContext(ctx, `SELECT id,file_sha256,event_count FROM telemetry_spool_batches
		WHERE format='native' AND (status IN ('queued','processing') OR (status='processed' AND spool_path!=''))
		ORDER BY id LIMIT ?`, maxNativePrefixBatches+1)
	if err != nil {
		return NativePrefix{}, err
	}
	for rows.Next() {
		var batch NativePrefixBatch
		if err := rows.Scan(&batch.ID, &batch.SHA256, &batch.EventCount); err != nil {
			rows.Close()
			return NativePrefix{}, err
		}
		p.Batches = append(p.Batches, batch)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return NativePrefix{}, err
	}
	if err := validateNativePrefix(p); err != nil {
		return NativePrefix{}, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT name,value FROM telemetry_native_counters`)
	if err != nil {
		return NativePrefix{}, err
	}
	for rows.Next() {
		var key string
		var value int64
		if err := rows.Scan(&key, &value); err != nil {
			rows.Close()
			return NativePrefix{}, err
		}
		p.Counters[key] = value
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return NativePrefix{}, err
	}
	var captured int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(event_count),0) FROM telemetry_spool_batches WHERE format='native'`).Scan(&captured); err != nil {
		return NativePrefix{}, err
	}
	p.Counters["captured"] = captured
	if err := tx.Commit(); err != nil {
		return NativePrefix{}, err
	}
	return p, nil
}

func validateNativePrefix(p NativePrefix) error {
	if p.SchemaVersion != NativePrefixSchema || p.Boundary != "accepted_spool" || p.CollectorID == "" || p.ObservedAt.IsZero() {
		return fmt.Errorf("invalid native spool checkpoint identity")
	}
	if len(p.Batches) > maxNativePrefixBatches {
		return fmt.Errorf("native spool checkpoint exceeds %d batches; retry after backlog decreases", maxNativePrefixBatches)
	}
	seen := make(map[string]bool, len(p.Batches))
	for _, batch := range p.Batches {
		hash, err := hex.DecodeString(batch.SHA256)
		if batch.ID == "" || seen[batch.ID] || err != nil || len(hash) != 32 || batch.EventCount < 0 || batch.EventCount > 4096 {
			return fmt.Errorf("invalid native spool checkpoint batch %q", batch.ID)
		}
		seen[batch.ID] = true
	}
	return nil
}

// ReadNativePrefix reads durable outcomes for exactly the checkpoint's batch
// set. Missing or changed metadata is an error, never an empty/complete range.
// It works after restart and payload cleanup using the retained batch ledger.
func ReadNativePrefix(ctx context.Context, db *sql.DB, p NativePrefix) (NativePrefixProgress, error) {
	if err := validateNativePrefix(p); err != nil {
		return NativePrefixProgress{}, err
	}
	r := NativePrefixProgress{State: "pending", ObservedAt: time.Now().UTC(), Batches: len(p.Batches)}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return r, err
	}
	defer tx.Rollback()
	for offset := 0; offset < len(p.Batches); offset += 128 {
		end := min(offset+128, len(p.Batches))
		expected := make(map[string]NativePrefixBatch, end-offset)
		args := make([]any, 0, end-offset)
		for _, batch := range p.Batches[offset:end] {
			expected[batch.ID] = batch
			args = append(args, batch.ID)
		}
		rows, err := tx.QueryContext(ctx, `SELECT id,format,file_sha256,event_count,status,
			ingested_count,dropped_count,failed_count,spool_path,error FROM telemetry_spool_batches WHERE id IN (`+
			strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")+`) ORDER BY id`, args...)
		if err != nil {
			return r, err
		}
		for rows.Next() {
			var id, format, hash, state, path, problem string
			var count, ingested, dropped, failed int64
			if err := rows.Scan(&id, &format, &hash, &count, &state, &ingested, &dropped, &failed, &path, &problem); err != nil {
				rows.Close()
				return r, err
			}
			batch := expected[id]
			if format != "native" || hash != batch.SHA256 || count != batch.EventCount ||
				ingested < 0 || dropped < 0 || failed < 0 || ingested > count || dropped > count || failed > count ||
				ingested+dropped+failed > count || (state != "queued" && state != "processing" && state != "processed") ||
				(state == "processed" && ingested+dropped+failed != count) {
				rows.Close()
				return r, fmt.Errorf("native spool checkpoint metadata conflict: %s", id)
			}
			delete(expected, id)
			r.Events += count
			r.Ingested += ingested
			r.Dropped += dropped
			r.Failed += failed
			r.Pending += count - ingested - dropped - failed
			if state != "processed" {
				r.PendingBatches++
				r.pending = append(r.pending, id)
			} else if path != "" {
				r.CleanupPending++
			}
			if problem != "" {
				r.LastError = problem
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return r, err
		}
		if len(expected) != 0 {
			return r, fmt.Errorf("native spool checkpoint batch metadata missing")
		}
	}
	if err := tx.Commit(); err != nil {
		return r, err
	}
	if r.PendingBatches == 0 {
		r.State = "settled"
	}
	return r, nil
}

// DrainPrefix retries only the frozen range. New capture remains enabled; a
// later batch cannot extend this wait. The caller supplies a deadline, or the
// default three-second budget applies. Expiry and loss retain their outcomes.
func (n *NativeStream) DrainPrefix(ctx context.Context, p NativePrefix) (result NativePrefixProgress, resultErr error) {
	if _, bounded := ctx.Deadline(); !bounded {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, ctx.Err())
		}
	}()
	progress, err := ReadNativePrefix(ctx, n.service.DB, p)
	for err == nil && progress.State != "settled" {
		for _, id := range progress.pending {
			if err := ctx.Err(); err != nil {
				return progress, err
			}
			if err := n.processBatchContext(ctx, id); err != nil {
				readCtx, cancel := context.WithTimeout(context.Background(), time.Second)
				latest, readErr := ReadNativePrefix(readCtx, n.service.DB, p)
				cancel()
				if readErr == nil {
					progress = latest
				}
				return progress, errors.Join(err, readErr)
			}
		}
		next, readErr := ReadNativePrefix(ctx, n.service.DB, p)
		if readErr != nil {
			return progress, readErr
		}
		progress = next
		if progress.State == "settled" {
			return progress, nil
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return progress, ctx.Err()
		case <-timer.C:
		}
	}
	return progress, err
}
