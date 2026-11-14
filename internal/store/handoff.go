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
			`CREATE INDEX IF NOT EXISTS idx_execution_source_admission_lookup ON provenance_objects(source_id)
				WHERE object_type='execution_source_admission'`,
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
			`CREATE TABLE IF NOT EXISTS execution_stop_requests (
				operation_key TEXT PRIMARY KEY,
				attempt_id TEXT NOT NULL REFERENCES execution_attempts(id),
				principal_id TEXT NOT NULL,
				requested_at_ns INTEGER NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS idx_execution_stop_attempt ON execution_stop_requests(attempt_id)`,
			`CREATE TABLE IF NOT EXISTS execution_deliveries (
				id TEXT PRIMARY KEY,
				attempt_id TEXT NOT NULL REFERENCES execution_attempts(id),
				operation_id TEXT NOT NULL,
				receiver_id TEXT NOT NULL,
				package_version INTEGER NOT NULL,
				manifest_json BLOB NOT NULL,
				manifest_sha256 TEXT NOT NULL,
				bundle_path TEXT NOT NULL,
				receipt_json BLOB,
				created_at_ns INTEGER NOT NULL,
				UNIQUE(attempt_id, operation_id),
				UNIQUE(attempt_id, receiver_id, package_version)
			)`,
			`CREATE TABLE IF NOT EXISTS execution_delivery_retention (
				delivery_id TEXT PRIMARY KEY REFERENCES execution_deliveries(id),
				retain_until_ns INTEGER NOT NULL,
				retired_at_ns INTEGER NOT NULL DEFAULT 0,
				purged_at_ns INTEGER NOT NULL DEFAULT 0,
				last_attempt_ns INTEGER NOT NULL DEFAULT 0
			)`,
			`CREATE INDEX IF NOT EXISTS idx_execution_delivery_retention_due ON execution_delivery_retention(purged_at_ns,retain_until_ns)`,
			`CREATE INDEX IF NOT EXISTS idx_execution_delivery_acknowledged ON execution_deliveries(receiver_id,created_at_ns,id) WHERE receipt_json IS NOT NULL`,
			`CREATE TABLE IF NOT EXISTS execution_delivery_receipts (
				receipt_key TEXT PRIMARY KEY,
				target_key TEXT NOT NULL,
				attempt_id TEXT NOT NULL,
				receiver_id TEXT NOT NULL,
				package_version INTEGER NOT NULL,
				manifest_json BLOB NOT NULL,
				manifest_sha256 TEXT NOT NULL,
				bundle_path TEXT NOT NULL,
				receipt_json BLOB NOT NULL,
				created_at_ns INTEGER NOT NULL,
				UNIQUE(target_key, attempt_id, receiver_id, package_version)
			)`,
		} {
			if _, err := tx.Exec(stmt); err != nil {
				return err
			}
		}
		return nil
	})
}
