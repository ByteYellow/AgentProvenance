package handoff

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/byteyellow/agentprovenance/internal/store"
)

type StopReceipt struct {
	SchemaVersion string    `json:"schema_version"`
	AttemptID     string    `json:"attempt_id"`
	OperationID   string    `json:"operation_id"`
	State         string    `json:"state"`
	RequestedAt   time.Time `json:"requested_at"`
}

// RequestStop acknowledges persistence of a request, not termination. The
// executor observes it independently of the client's connection lifetime.
func (l Ledger) RequestStop(ctx context.Context, p Principal, id, operation string) (StopReceipt, error) {
	if !validID(id) || !validID(operation) {
		return StopReceipt{}, ErrInvalid
	}
	var receipt StopReceipt
	err := store.WithWriteTx(ctx, l.DB, func(tx *sql.Tx) error {
		a, err := readAttempt(ctx, tx, "a.id=?", id)
		if err != nil {
			return err
		}
		if a.principalID != p.ID || a.Request.Target != l.Target || p.Authorize(a.Request.Source, a.Request.Target) != nil {
			return ErrForbidden
		}
		key := digest("execution-stop/v1", p.ProducerID, p.Namespace, operation)
		var previous, owner string
		var at int64
		err = tx.QueryRowContext(ctx, `SELECT attempt_id,principal_id,requested_at_ns FROM execution_stop_requests WHERE operation_key=?`, key).Scan(&previous, &owner, &at)
		switch {
		case err == nil:
			if owner != p.ID {
				return ErrForbidden
			}
			if previous != id {
				return ErrConflict
			}
		case errors.Is(err, sql.ErrNoRows):
			at = l.now().UnixNano()
			if _, err := tx.ExecContext(ctx, `INSERT INTO execution_stop_requests VALUES (?,?,?,?)`, key, id, p.ID, at); err != nil {
				return err
			}
		default:
			return err
		}
		receipt = StopReceipt{SchemaVersion: SchemaVersion, AttemptID: id, OperationID: operation,
			State: "requested", RequestedAt: time.Unix(0, at).UTC()}
		return nil
	})
	return receipt, err
}

func (l Ledger) stopRequested(ctx context.Context, id string) (bool, error) {
	var exists bool
	err := l.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM execution_stop_requests WHERE attempt_id=?)`, id).Scan(&exists)
	return exists, err
}
