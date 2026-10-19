package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
)

// WithWriteTx reserves the SQLite writer before the callback reads a snapshot.
// A deferred read transaction cannot upgrade a stale WAL snapshot, even with a
// busy handler. This zero-row write changes no schema metadata and lets the
// busy handler wait before any application reads or external writes occur.
// The database must already have an initialized schema.
func WithWriteTx(ctx context.Context, db *sql.DB, apply func(*sql.Tx) error) error {
	return WithTx(ctx, db, func(tx *sql.Tx) error {
		if err := RetryBusy(ctx, func() error {
			_, err := tx.ExecContext(ctx, `UPDATE schema_versions SET version=version WHERE 0`)
			return err
		}); err != nil {
			return err
		}
		return apply(tx)
	})
}

// WithTx pins the connection until commit or rollback has completed. The
// callback must not commit or roll back the transaction itself.
//
// SQLite can leave a transaction active after a failed COMMIT, while sql.Tx is
// already done. Discard that connection before it can return to the pool.
func WithTx(ctx context.Context, db *sql.DB, apply func(*sql.Tx) error) (err error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	discard := func() {
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
	}
	defer func() {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			discard()
			err = errors.Join(err, rollbackErr)
		}
	}()
	if err = apply(tx); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		discard()
	}
	return err
}
