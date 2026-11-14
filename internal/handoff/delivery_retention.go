package handoff

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/byteyellow/agentprovenance/internal/store"
)

// Storage describes the local transfer copy, outside the signed manifest.
type DeliveryStorage struct {
	State       string     `json:"state"`
	RetainUntil time.Time  `json:"retain_until"`
	RetiredAt   *time.Time `json:"retired_at,omitempty"`
	PurgedAt    *time.Time `json:"purged_at,omitempty"`
}

func (d Delivery) retired() bool { return d.Storage != nil && d.Storage.RetiredAt != nil }

type DeliveryCleanup struct {
	Scheduled      int   `json:"scheduled"`
	Retired        int   `json:"retired"`
	Purged         int   `json:"purged"`
	Failed         int   `json:"failed"`
	ReclaimedBytes int64 `json:"reclaimed_bytes"`
}

func (s *DeliveryService) scheduleRetention(ctx context.Context, tx *sql.Tx, a Attempt, id string) error {
	if s.Retention == 0 {
		return nil
	}
	until := s.Ledger.now().Add(s.Retention)
	if until.Before(a.Request.ValidUntil) {
		until = a.Request.ValidUntil
	}
	if until.UnixNano() <= 0 || !time.Unix(0, until.UnixNano()).Equal(until) {
		return fmt.Errorf("delivery retention deadline is outside the supported timestamp range")
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO execution_delivery_retention(delivery_id,retain_until_ns)
		VALUES(?,?) ON CONFLICT(delivery_id) DO NOTHING`, id, until.UnixNano())
	return err
}

// PruneAcknowledged retires only the sender's acknowledged transfer copies.
// Durable retirement precedes unlink; retries finish interrupted unlinks without
// re-exporting a retired operation or altering its manifest, receipt or ledger.
func (s *DeliveryService) PruneAcknowledged(ctx context.Context, limit int) (DeliveryCleanup, error) {
	var result DeliveryCleanup
	if err := s.validate(); err != nil {
		return result, err
	}
	if limit < 1 || limit > 1000 {
		return result, fmt.Errorf("delivery cleanup limit must be between 1 and 1000")
	}
	if s.Retention == 0 {
		return result, ctx.Err()
	}
	release, err := s.slot.acquire(ctx)
	if err != nil {
		return result, err
	}
	defer release()
	target := s.Ledger.Target
	rows, err := s.Ledger.DB.QueryContext(ctx, `SELECT d.id FROM execution_deliveries d
		JOIN execution_attempts a ON a.id=d.attempt_id
		LEFT JOIN execution_delivery_retention r ON r.delivery_id=d.id
		WHERE d.receiver_id=? AND d.receipt_json IS NOT NULL
		AND json_extract(a.request_json,'$.target.producer_id')=?
		AND json_extract(a.request_json,'$.target.instance_id')=?
		AND json_extract(a.request_json,'$.target.generation')=?
		AND (r.delivery_id IS NULL OR (r.purged_at_ns=0 AND r.retain_until_ns<=? AND a.expires_at_ns<=?))
		ORDER BY COALESCE(r.last_attempt_ns,0),d.created_at_ns,d.id LIMIT ?`,
		s.ReceiverID, target.ProducerID, target.InstanceID, target.Generation, s.Ledger.now().UnixNano(), s.Ledger.now().UnixNano(), limit)
	if err != nil {
		return result, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return result, err
		}
		ids = append(ids, id)
	}
	err = errors.Join(rows.Err(), rows.Close())
	if err != nil {
		return result, err
	}
	var failures []error
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return result, errors.Join(append(failures, err)...)
		}
		var d Delivery
		remove := false
		err := store.WithWriteTx(ctx, s.Ledger.DB, func(tx *sql.Tx) error {
			var err error
			d, err = s.read(ctx, tx, id)
			if err != nil {
				return err
			}
			a, err := readAttempt(ctx, tx, "a.id=?", d.Manifest.Identity.AttemptID)
			if err != nil {
				return err
			}
			if a.Request.Target != target || d.Manifest.ReceiverID != s.ReceiverID || IdentityOf(a) != d.Manifest.Identity || len(d.Receipt) == 0 {
				return ErrConflict
			}
			if d.Storage == nil {
				// Existing receipts get a full window from policy activation.
				return s.scheduleRetention(ctx, tx, a, id)
			}
			now := s.Ledger.now()
			if d.Storage.PurgedAt != nil || now.Before(d.Storage.RetainUntil) || now.Before(a.Request.ValidUntil) {
				return nil
			}
			_, err = tx.ExecContext(ctx, `UPDATE execution_delivery_retention
				SET retired_at_ns=CASE WHEN retired_at_ns=0 THEN ? ELSE retired_at_ns END,last_attempt_ns=? WHERE delivery_id=?`, now.UnixNano(), now.UnixNano(), id)
			remove = err == nil
			return err
		})
		if err == nil && d.Storage == nil {
			result.Scheduled++
		}
		if err == nil && remove {
			if !d.retired() {
				result.Retired++
			}
			var removed int64
			removed, err = removeDeliveryPackage(ctx, s.Paths, d.BundlePath)
			result.ReclaimedBytes += removed
			if err == nil {
				var update sql.Result
				update, err = s.Ledger.DB.ExecContext(ctx, `UPDATE execution_delivery_retention SET purged_at_ns=?
					WHERE delivery_id=? AND purged_at_ns=0`, s.Ledger.now().UnixNano(), id)
				if err == nil {
					var changed int64
					changed, err = update.RowsAffected()
					result.Purged += int(changed)
				}
			}
		}
		if err != nil {
			result.Failed++
			failures = append(failures, fmt.Errorf("delivery %s: %w", id, err))
		}
	}
	return result, errors.Join(failures...)
}
