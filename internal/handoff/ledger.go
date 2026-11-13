package handoff

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/byteyellow/agentprovenance/internal/store"
)

type Ledger struct {
	DB     *sql.DB
	Target Target
	Now    func() time.Time
}

type Attempt struct {
	SchemaVersion string    `json:"schema_version"`
	Sequence      int64     `json:"sequence"`
	ID            string    `json:"id"`
	Number        int       `json:"attempt_number"`
	RequestHash   string    `json:"request_hash"`
	DigestVersion string    `json:"digest_version"`
	Request       Request   `json:"request"`
	LocalRunID    string    `json:"local_run_id"`
	State         State     `json:"state"`
	Revision      int64     `json:"revision"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	principalID   string
}

func (l Ledger) now() time.Time {
	if l.Now != nil {
		return l.Now().UTC()
	}
	return time.Now().UTC()
}

// Admit stores dispatch, operation, attempt and initial history atomically.
// No external command is started here, including when a transaction is retried.
func (l Ledger) Admit(ctx context.Context, principal Principal, request Request) (Attempt, bool, error) {
	r, raw, hash, err := request.Canonical()
	if err != nil {
		return Attempt{}, false, err
	}
	if err := principal.Authorize(r.Source, r.Target); err != nil {
		return Attempt{}, false, err
	}
	if r.Target != l.Target {
		return Attempt{}, false, ErrForbidden
	}
	now := l.now()
	if !now.Before(r.ValidUntil) {
		return Attempt{}, false, ErrExpired
	}
	if r.ValidUntil.Sub(now) > MaxValidity {
		return Attempt{}, false, fmt.Errorf("%w: valid_until exceeds 24 hours", ErrInvalid)
	}
	var result Attempt
	reused := false
	err = store.WithWriteTx(ctx, l.DB, func(tx *sql.Tx) error {
		// The deadline is checked again after reserving the SQLite writer.
		now = l.now()
		if !now.Before(r.ValidUntil) {
			return ErrExpired
		}
		existing, err := readAttempt(ctx, tx, "a.operation_key=?", operationKey(r))
		if err == nil {
			if existing.principalID != principal.ID {
				return ErrForbidden
			}
			if existing.RequestHash != hash {
				return ErrConflict
			}
			result, reused = existing, true
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		dkey := dispatchKey(r)
		var owner, source string
		err = tx.QueryRowContext(ctx, `SELECT principal_id, source_key FROM execution_dispatches WHERE dispatch_key=?`, dkey).Scan(&owner, &source)
		number := 1
		switch {
		case errors.Is(err, sql.ErrNoRows):
			if r.PreviousAttemptID != "" {
				return fmt.Errorf("%w: reexecution requires an existing dispatch", ErrConflict)
			}
			sourceJSON, err := json.Marshal(r.Source)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO execution_dispatches
				(dispatch_key,principal_id,source_key,source_json,dispatch_id,created_at_ns) VALUES (?,?,?,?,?,?)`,
				dkey, principal.ID, sourceKey(r.Source), string(sourceJSON), r.DispatchID, now.UnixNano()); err != nil {
				return err
			}
		case err != nil:
			return err
		default:
			if owner != principal.ID {
				return ErrForbidden
			}
			if source != sourceKey(r.Source) || r.PreviousAttemptID == "" {
				return fmt.Errorf("%w: existing dispatch requires an explicit reexecution", ErrConflict)
			}
			previous, err := readAttempt(ctx, tx, "a.dispatch_key=? ORDER BY a.attempt_number DESC LIMIT 1", dkey)
			if err != nil {
				return err
			}
			if previous.ID != r.PreviousAttemptID || !previous.State.Execution.CanReexecute() {
				return fmt.Errorf("%w: reexecution must reference the latest stopped or unknown attempt", ErrConflict)
			}
			number = previous.Number + 1
		}
		id, err := newID("execution")
		if err != nil {
			return err
		}
		runID, err := newID("run")
		if err != nil {
			return err
		}
		state := InitialState()
		insert, err := tx.ExecContext(ctx, `INSERT INTO execution_attempts
			(id,dispatch_key,attempt_number,operation_key,request_hash,request_json,local_run_id,
			 execution_state,capture_state,delivery_state,revision,created_at_ns,updated_at_ns,expires_at_ns)
			VALUES (?,?,?,?,?,?,?,?,?,?,1,?,?,?)`,
			id, dkey, number, operationKey(r), hash, string(raw), runID, state.Execution, state.Capture,
			state.Delivery, now.UnixNano(), now.UnixNano(), r.ValidUntil.UnixNano())
		if err != nil {
			return err
		}
		sequence, err := insert.LastInsertId()
		if err != nil {
			return err
		}
		result = Attempt{SchemaVersion: SchemaVersion, Sequence: sequence, ID: id, Number: number,
			RequestHash: hash, DigestVersion: DigestVersion, Request: r, LocalRunID: runID,
			State: state, Revision: 1, CreatedAt: now, UpdatedAt: now, principalID: principal.ID}
		return appendHistory(ctx, tx, result, "dispatch_accepted", nil)
	})
	if err != nil {
		return Attempt{}, false, err
	}
	return result, reused, nil
}

func (l Ledger) Get(ctx context.Context, principal Principal, id string) (Attempt, error) {
	a, err := readAttempt(ctx, l.DB, "a.id=?", id)
	if err != nil {
		return Attempt{}, err
	}
	if a.principalID != principal.ID || principal.Authorize(a.Request.Source, a.Request.Target) != nil {
		return Attempt{}, ErrForbidden
	}
	return a, nil
}

type Page struct {
	SchemaVersion string    `json:"schema_version"`
	Attempts      []Attempt `json:"attempts"`
	NextAfter     int64     `json:"next_after,omitempty"`
}

func (l Ledger) List(ctx context.Context, principal Principal, source Source, after int64, limit int) (Page, error) {
	if err := source.Validate(); err != nil {
		return Page{}, err
	}
	if err := principal.Authorize(source, l.Target); err != nil {
		return Page{}, err
	}
	if after < 0 || limit < 1 || limit > 100 {
		return Page{}, fmt.Errorf("%w: invalid page bounds", ErrInvalid)
	}
	rows, err := l.DB.QueryContext(ctx, attemptSelect+` WHERE d.source_key=? AND d.principal_id=? AND a.sequence>? ORDER BY a.sequence LIMIT ?`,
		sourceKey(source), principal.ID, after, limit+1)
	if err != nil {
		return Page{}, err
	}
	defer rows.Close()
	page := Page{SchemaVersion: SchemaVersion, Attempts: []Attempt{}}
	for rows.Next() {
		a, err := scanAttempt(rows)
		if err != nil {
			return Page{}, err
		}
		if principal.Authorize(a.Request.Source, a.Request.Target) != nil {
			return Page{}, ErrForbidden
		}
		if len(page.Attempts) == limit {
			page.NextAfter = page.Attempts[len(page.Attempts)-1].Sequence
			break
		}
		page.Attempts = append(page.Attempts, a)
	}
	if err := rows.Err(); err != nil {
		return Page{}, err
	}
	return page, nil
}

// AdvanceExecution is an executor-side compare-and-swap. Only the winner of
// accepted -> starting may launch a command. A restarted executor must inspect
// starting/running attempts; it must not transition them back to accepted.
func (l Ledger) AdvanceExecution(ctx context.Context, id string, revision int64, next ExecutionState, reason string, refs []string) (Attempt, error) {
	if !validID(reason) || len(refs) > 64 {
		return Attempt{}, fmt.Errorf("%w: transition reason or evidence references", ErrInvalid)
	}
	for _, ref := range refs {
		if !validID(ref) {
			return Attempt{}, fmt.Errorf("%w: invalid evidence reference", ErrInvalid)
		}
	}
	var result Attempt
	err := store.WithWriteTx(ctx, l.DB, func(tx *sql.Tx) error {
		a, err := readAttempt(ctx, tx, "a.id=?", id)
		if err != nil {
			return err
		}
		if l.Target != a.Request.Target {
			return ErrForbidden
		}
		if a.Revision != revision {
			return ErrStale
		}
		if !a.State.Execution.CanTransition(next) {
			return transitionError(a.State.Execution, next)
		}
		if (next == Running || next == Succeeded || next == Failed || next == Cancelled) && len(refs) == 0 {
			return fmt.Errorf("%w: observed execution states require evidence references", ErrInvalid)
		}
		if a.State.Execution == Unknown && len(refs) == 0 {
			return fmt.Errorf("%w: recovery requires evidence", ErrInvalid)
		}
		a.State.Execution = next
		a.Revision++
		a.UpdatedAt = l.now()
		if _, err := tx.ExecContext(ctx, `UPDATE execution_attempts SET execution_state=?,revision=?,updated_at_ns=? WHERE id=?`,
			next, a.Revision, a.UpdatedAt.UnixNano(), a.ID); err != nil {
			return err
		}
		if err := appendHistory(ctx, tx, a, reason, refs); err != nil {
			return err
		}
		result = a
		return nil
	})
	if err != nil {
		return Attempt{}, err
	}
	return result, nil
}

const attemptSelect = `SELECT a.sequence,a.id,a.attempt_number,a.request_hash,a.request_json,a.local_run_id,
	a.execution_state,a.capture_state,a.delivery_state,a.revision,a.created_at_ns,a.updated_at_ns,d.principal_id
	FROM execution_attempts a JOIN execution_dispatches d ON d.dispatch_key=a.dispatch_key`

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readAttempt(ctx context.Context, q queryer, predicate string, args ...any) (Attempt, error) {
	a, err := scanAttempt(q.QueryRowContext(ctx, attemptSelect+" WHERE "+predicate, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return Attempt{}, ErrNotFound
	}
	return a, err
}

type scanner interface {
	Scan(...any) error
}

func scanAttempt(row scanner) (Attempt, error) {
	var a Attempt
	var raw string
	var created, updated int64
	if err := row.Scan(&a.Sequence, &a.ID, &a.Number, &a.RequestHash, &raw, &a.LocalRunID,
		&a.State.Execution, &a.State.Capture, &a.State.Delivery, &a.Revision, &created, &updated, &a.principalID); err != nil {
		return Attempt{}, err
	}
	if err := json.Unmarshal([]byte(raw), &a.Request); err != nil {
		return Attempt{}, fmt.Errorf("decode saved execution request: %w", err)
	}
	a.SchemaVersion, a.DigestVersion = SchemaVersion, DigestVersion
	a.CreatedAt, a.UpdatedAt = time.Unix(0, created).UTC(), time.Unix(0, updated).UTC()
	return a, nil
}

func appendHistory(ctx context.Context, tx *sql.Tx, a Attempt, reason string, refs []string) error {
	if refs == nil {
		refs = []string{}
	}
	state, err := json.Marshal(a.State)
	if err != nil {
		return err
	}
	evidence, err := json.Marshal(refs)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO execution_attempt_history
		(attempt_id,revision,state_json,reason,evidence_json,created_at_ns) VALUES (?,?,?,?,?,?)`,
		a.ID, a.Revision, string(state), reason, string(evidence), a.UpdatedAt.UnixNano())
	return err
}

func newID(prefix string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return prefix + "-" + hex.EncodeToString(b[:]), nil
}
