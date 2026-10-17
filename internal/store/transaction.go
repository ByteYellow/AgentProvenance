package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
)

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
