package telemetry

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"time"
)

const NativeScopePrefixSchema = "agentprovenance.native_scope_prefix/v1"

// A collector epoch and sealed batch sequence isolate reused kernel cgroup
// IDs, including across restart. This is capture accounting, not attribution.
type NativeScopePrefix struct {
	SchemaVersion string             `json:"schema_version"`
	CollectorID   string             `json:"collector_id"`
	CgroupID      string             `json:"cgroup_id"`
	After         uint64             `json:"after_sequence"`
	Through       uint64             `json:"through_sequence"`
	ObservedAt    time.Time          `json:"observed_at"`
	Batches       []NativeScopeBatch `json:"batches"`
}

type NativeScopeBatch struct {
	NativePrefixBatch
	FirstSequence uint64 `json:"first_sequence"`
	Matched       int64  `json:"matched_events"`
	Unscoped      int64  `json:"unscoped_events"`
}

func nativeScopeKey(event IngestEvent) string {
	if event.Source == "procfs_access_control" && event.EventType == "access_control_state" &&
		(event.CgroupID == "" || event.CgroupID == "0") && event.CaptureCgroupID != "" && event.CaptureCgroupID != "0" {
		return event.CaptureCgroupID
	}
	knownSource := event.Source == "agentprov_ebpf" || (event.Source == "procfs_access_control" && event.EventType == "access_control_state")
	if !knownSource || event.CgroupID == "0" {
		return ""
	}
	// mapNative retains procfs membership only when independently observed.
	return event.CgroupID
}

func recordNativeScopeOutcome(tx *sql.Tx, batch, group, outcome string, samplingGap bool) error {
	ingested, dropped, failed := 0, 0, 0
	switch outcome {
	case "ingested":
		ingested = 1
	case "expired_uncorrelated":
		dropped = 1
	case "invalid":
		failed = 1
	default:
		return fmt.Errorf("unknown native scope outcome %q", outcome)
	}
	gap := 0
	if samplingGap {
		gap = 1
	}
	result, err := tx.Exec(`UPDATE telemetry_native_scope_counts SET
		ingested_count=ingested_count+?,dropped_count=dropped_count+?,failed_count=failed_count+?,sampling_gap_count=sampling_gap_count+?
		WHERE batch_id=? AND cgroup_id=? AND ingested_count+dropped_count+failed_count<event_count`,
		ingested, dropped, failed, gap, batch, group)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return fmt.Errorf("native scope outcome metadata missing or exhausted: %s", batch)
	}
	return nil
}

// SnapshotScopePrefix enumerates the complete interval, including batches
// whose payload was already ingested and removed. Begin/end snapshots seal
// their current batch, so a batch cannot straddle either accepted boundary.
func (n *NativeStream) SnapshotScopePrefix(ctx context.Context, start, end NativePrefix, group string) (NativeScopePrefix, error) {
	p := NativeScopePrefix{SchemaVersion: NativeScopePrefixSchema, CollectorID: start.CollectorID, CgroupID: group,
		After: start.Sequence, Through: end.Sequence, ObservedAt: time.Now().UTC(), Batches: []NativeScopeBatch{}}
	if start.CollectorID != end.CollectorID || start.CollectorID != n.producerID {
		return p, fmt.Errorf("native scope checkpoint collector changed")
	}
	if err := validateNativePrefix(start); err != nil {
		return p, err
	}
	if err := validateNativePrefix(end); err != nil {
		return p, err
	}
	if p.Through < p.After || p.Through > math.MaxInt64 || group == "" || group == "0" {
		return p, fmt.Errorf("invalid native scope interval")
	}
	tx, err := n.service.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return p, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT b.id,b.file_sha256,b.event_count,b.native_first_sequence,
		COALESCE(SUM(CASE WHEN s.cgroup_id=? THEN s.event_count ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN s.cgroup_id='' THEN s.event_count ELSE 0 END),0),COALESCE(SUM(s.event_count),0)
		FROM telemetry_spool_batches b LEFT JOIN telemetry_native_scope_counts s ON s.batch_id=b.id
		WHERE b.format='native' AND b.native_collector_id=? AND b.native_first_sequence>? AND b.native_first_sequence<=? AND b.event_count>0
		GROUP BY b.id ORDER BY b.native_first_sequence LIMIT ?`, group, p.CollectorID, p.After, p.Through, maxNativePrefixBatches+1)
	if err != nil {
		return p, err
	}
	for rows.Next() {
		var b NativeScopeBatch
		var total int64
		if err := rows.Scan(&b.ID, &b.SHA256, &b.EventCount, &b.FirstSequence, &b.Matched, &b.Unscoped, &total); err != nil {
			rows.Close()
			return p, err
		}
		if total != b.EventCount {
			rows.Close()
			return p, fmt.Errorf("native scope membership missing: %s", b.ID)
		}
		p.Batches = append(p.Batches, b)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return p, err
	}
	if err := validateNativeScopePrefix(p); err != nil {
		return p, err
	}
	return p, tx.Commit()
}

func validateNativeScopePrefix(p NativeScopePrefix) error {
	if p.SchemaVersion != NativeScopePrefixSchema || p.CollectorID == "" || p.CgroupID == "" || p.CgroupID == "0" ||
		p.ObservedAt.IsZero() || p.Through < p.After || p.Through > math.MaxInt64 || len(p.Batches) > maxNativePrefixBatches {
		return fmt.Errorf("invalid native scope checkpoint")
	}
	next := p.After + 1
	seen := map[string]bool{}
	for _, b := range p.Batches {
		hash, err := hex.DecodeString(b.SHA256)
		if err != nil || len(hash) != 32 || b.ID == "" || seen[b.ID] || b.EventCount < 1 || b.EventCount > 4096 || b.FirstSequence != next ||
			b.Matched < 0 || b.Unscoped < 0 || b.Matched > b.EventCount || b.Unscoped > b.EventCount-b.Matched {
			return fmt.Errorf("native scope checkpoint membership conflict: %s", b.ID)
		}
		seen[b.ID] = true
		next += uint64(b.EventCount)
	}
	if next != p.Through+1 {
		return fmt.Errorf("native scope checkpoint sequence gap")
	}
	return nil
}

// ReadNativeScopePrefix includes unknown-cgroup rows conservatively. Unrelated
// cgroups keep their own TTL and outcomes without blocking this interval.
func ReadNativeScopePrefix(ctx context.Context, db *sql.DB, p NativeScopePrefix) (NativePrefixProgress, error) {
	r := NativePrefixProgress{State: "pending", ObservedAt: time.Now().UTC(), Batches: len(p.Batches)}
	if err := validateNativeScopePrefix(p); err != nil {
		return r, err
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return r, err
	}
	defer tx.Rollback()
	for _, b := range p.Batches {
		var format, collector, hash, state, path, problem string
		var count, first, ingested, dropped, failed int64
		if err := tx.QueryRowContext(ctx, `SELECT format,native_collector_id,file_sha256,event_count,native_first_sequence,status,
			spool_path,error,ingested_count,dropped_count,failed_count FROM telemetry_spool_batches WHERE id=?`, b.ID).
			Scan(&format, &collector, &hash, &count, &first, &state, &path, &problem, &ingested, &dropped, &failed); err != nil {
			return r, err
		}
		if format != "native" || collector != p.CollectorID || hash != b.SHA256 || count != b.EventCount || first != int64(b.FirstSequence) ||
			(state != "queued" && state != "processing" && state != "processed") {
			return r, fmt.Errorf("native scope checkpoint metadata conflict: %s", b.ID)
		}
		rows, err := tx.QueryContext(ctx, `SELECT cgroup_id,event_count,ingested_count,dropped_count,failed_count,sampling_gap_count
			FROM telemetry_native_scope_counts WHERE batch_id=?`, b.ID)
		if err != nil {
			return r, err
		}
		var total, totalIn, totalDrop, totalFail, matched, unscoped, pending int64
		for rows.Next() {
			var group string
			var events, in, drop, fail, gaps int64
			if err := rows.Scan(&group, &events, &in, &drop, &fail, &gaps); err != nil {
				rows.Close()
				return r, err
			}
			if events < 1 || in < 0 || drop < 0 || fail < 0 || in > events || drop > events-in || fail > events-in-drop || gaps < 0 || gaps > in {
				rows.Close()
				return r, fmt.Errorf("invalid native scope outcomes: %s", b.ID)
			}
			total, totalIn, totalDrop, totalFail = total+events, totalIn+in, totalDrop+drop, totalFail+fail
			if group == p.CgroupID || group == "" {
				if group == "" {
					unscoped = events
				} else {
					matched = events
				}
				r.Events, r.Ingested, r.Dropped, r.Failed = r.Events+events, r.Ingested+in, r.Dropped+drop, r.Failed+fail
				r.SamplingGaps += gaps
				pending += events - in - drop - fail
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return r, err
		}
		if total != count || totalIn != ingested || totalDrop != dropped || totalFail != failed || matched != b.Matched || unscoped != b.Unscoped ||
			(state == "processed" && totalIn+totalDrop+totalFail != total) {
			return r, fmt.Errorf("native scope checkpoint outcome conflict: %s", b.ID)
		}
		r.Pending += pending
		if pending != 0 {
			r.PendingBatches++
			r.pending = append(r.pending, b.ID)
		}
		if state == "processed" && path != "" {
			r.CleanupPending++
		}
		if problem != "" && pending != 0 {
			r.LastError = problem
		}
	}
	if err := tx.Commit(); err != nil {
		return r, err
	}
	if r.Pending == 0 {
		r.State = "settled"
	}
	return r, nil
}

func (n *NativeStream) DrainScopePrefix(ctx context.Context, p NativeScopePrefix) (NativePrefixProgress, error) {
	if _, bounded := ctx.Deadline(); !bounded {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
	}
	progress, err := ReadNativeScopePrefix(ctx, n.service.DB, p)
	for err == nil && progress.State != "settled" {
		for _, id := range progress.pending {
			if err := n.processBatchContext(ctx, id); err != nil {
				readCtx, cancel := context.WithTimeout(context.Background(), time.Second)
				latest, readErr := ReadNativeScopePrefix(readCtx, n.service.DB, p)
				cancel()
				if readErr == nil {
					progress = latest
				}
				return progress, errors.Join(err, readErr, ctx.Err())
			}
		}
		next, err := ReadNativeScopePrefix(ctx, n.service.DB, p)
		if err != nil {
			return progress, errors.Join(err, ctx.Err())
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
