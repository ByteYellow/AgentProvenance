package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// IsBusy includes extended SQLITE_BUSY/SQLITE_LOCKED result codes. Other
// storage failures must retain their original error and are not retried.
func IsBusy(err error) bool {
	var coded interface{ Code() int }
	return errors.As(err, &coded) && (coded.Code()&255 == 5 || coded.Code()&255 == 6)
}

// RetryBusy retries an atomic statement or a transaction that rolls back on
// failure. The connection busy timeout bounds each attempt; the caller's
// context can end the wait sooner. Never wrap non-idempotent external work.
func RetryBusy(ctx context.Context, operation func() error) error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err = operation()
		if !IsBusy(err) || attempt == 2 {
			return err
		}
		timer := time.NewTimer(time.Duration(attempt+1) * 10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return err
}

func ExecRetry(ctx context.Context, db *sql.DB, query string, args ...any) (sql.Result, error) {
	var result sql.Result
	err := RetryBusy(ctx, func() error {
		var err error
		result, err = db.ExecContext(ctx, query, args...)
		return err
	})
	return result, err
}
