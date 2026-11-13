package store

import (
	"context"
	"database/sql"
)

// The handoff ledger is separate from legacy run IDs. Cross-producer references
// remain qualified instead of changing the identity of existing signed records.
func ensureHandoffSchema(db *sql.DB) error {
	return WithWriteTx(context.Background(), db, func(tx *sql.Tx) error {
		for _, stmt := range []string{
			`CREATE TABLE IF NOT EXISTS execution_dispatches (
				dispatch_key TEXT PRIMARY KEY,
				principal_id TEXT NOT NULL,
				source_key TEXT NOT NULL,
				source_json TEXT NOT NULL,
				dispatch_id TEXT NOT NULL,
				created_at_ns INTEGER NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS execution_attempts (
				sequence INTEGER PRIMARY KEY AUTOINCREMENT,
				id TEXT NOT NULL UNIQUE,
				dispatch_key TEXT NOT NULL REFERENCES execution_dispatches(dispatch_key),
				attempt_number INTEGER NOT NULL,
				operation_key TEXT NOT NULL UNIQUE,
				request_hash TEXT NOT NULL,
				request_json TEXT NOT NULL,
				local_run_id TEXT NOT NULL UNIQUE,
				execution_state TEXT NOT NULL,
				capture_state TEXT NOT NULL,
				delivery_state TEXT NOT NULL,
				revision INTEGER NOT NULL,
				created_at_ns INTEGER NOT NULL,
				updated_at_ns INTEGER NOT NULL,
				expires_at_ns INTEGER NOT NULL,
				UNIQUE(dispatch_key, attempt_number)
			)`,
			`CREATE INDEX IF NOT EXISTS idx_execution_dispatch_source ON execution_dispatches(source_key, dispatch_key)`,
			`CREATE INDEX IF NOT EXISTS idx_execution_attempt_dispatch ON execution_attempts(dispatch_key, sequence)`,
			`CREATE TABLE IF NOT EXISTS execution_attempt_history (
				attempt_id TEXT NOT NULL REFERENCES execution_attempts(id),
				revision INTEGER NOT NULL,
				state_json TEXT NOT NULL,
				reason TEXT NOT NULL,
				evidence_json TEXT NOT NULL,
				created_at_ns INTEGER NOT NULL,
				PRIMARY KEY(attempt_id, revision)
			)`,
		} {
			if _, err := tx.Exec(stmt); err != nil {
				return err
			}
		}
		return nil
	})
}
