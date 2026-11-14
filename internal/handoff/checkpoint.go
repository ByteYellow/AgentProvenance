package handoff

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/byteyellow/agentprovenance/internal/store"
)

const checkpointType = "execution_checkpoint"

type Output struct {
	State         string `json:"state"`
	Ref           string `json:"ref,omitempty"`
	ObservedBytes *int64 `json:"observed_bytes,omitempty"`
	RetainedBytes *int64 `json:"retained_bytes,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

type Checkpoint struct {
	SchemaVersion string                 `json:"schema_version"`
	AttemptID     string                 `json:"attempt_id"`
	Revision      int64                  `json:"revision"`
	Source        Source                 `json:"source"`
	Target        Target                 `json:"target"`
	DispatchID    string                 `json:"dispatch_id"`
	RequestHash   string                 `json:"request_hash"`
	DigestVersion string                 `json:"digest_version"`
	State         State                  `json:"state"`
	Reason        string                 `json:"reason"`
	At            time.Time              `json:"at"`
	Scope         *record.ExecutionScope `json:"scope,omitempty"`
	Result        *record.Result         `json:"result,omitempty"`
	Stdout        *Output                `json:"stdout,omitempty"`
	Stderr        *Output                `json:"stderr,omitempty"`
	Error         string                 `json:"error,omitempty"`
	Capture       *NativeCaptureReport   `json:"capture_report,omitempty"`
}

type Report struct {
	SchemaVersion string      `json:"schema_version"`
	Attempt       Attempt     `json:"attempt"`
	CheckpointRef string      `json:"checkpoint_ref,omitempty"`
	Checkpoint    *Checkpoint `json:"checkpoint,omitempty"`
	StopRequested bool        `json:"stop_requested"`
}

// Report reads a coherent attempt/checkpoint view while other workers write.
func (l Ledger) Report(ctx context.Context, p Principal, id string) (Report, error) {
	tx, err := l.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Report{}, err
	}
	defer tx.Rollback()
	a, err := readAttempt(ctx, tx, "a.id=?", id)
	if err != nil {
		return Report{}, err
	}
	if a.principalID != p.ID || p.Authorize(a.Request.Source, a.Request.Target) != nil {
		return Report{}, ErrForbidden
	}
	r := Report{SchemaVersion: SchemaVersion, Attempt: a}
	r.Checkpoint, r.CheckpointRef, err = readCheckpoint(ctx, tx, a)
	if err != nil {
		return Report{}, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM execution_stop_requests WHERE attempt_id=?)`, id).Scan(&r.StopRequested); err != nil {
		return Report{}, err
	}
	return r, tx.Commit()
}

type checkpointReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryRow(string, ...any) *sql.Row
}

func readCheckpoint(ctx context.Context, db checkpointReader, a Attempt) (*Checkpoint, string, error) {
	var ref string
	err := db.QueryRowContext(ctx, `SELECT hash FROM provenance_objects WHERE run_id=? AND object_type=?
		ORDER BY source_id DESC LIMIT 1`, a.LocalRunID, checkpointType).Scan(&ref)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	var c Checkpoint
	if err := provenance.ReadObjectPayload(db, a.LocalRunID, ref, &c); err != nil {
		return nil, "", err
	}
	if c.SchemaVersion != SchemaVersion || c.AttemptID != a.ID || c.Target != a.Request.Target ||
		c.Source != a.Request.Source || c.RequestHash != a.RequestHash || c.DigestVersion != a.DigestVersion ||
		c.Revision > a.Revision {
		return nil, "", fmt.Errorf("execution checkpoint identity mismatch")
	}
	return &c, ref, nil
}

// saveCheckpoint commits state, history and the content-addressed observation
// index in one transaction. Uncommitted object files are merely orphan blobs.
func (e *Executor) saveCheckpoint(ctx context.Context, a Attempt, c Checkpoint) (Attempt, error) {
	return e.commitCheckpoint(ctx, a, c, false)
}

// Capture completion may race an independently acknowledged delivery. Merge
// only that dimension, without overwriting another execution/capture change.
func (e *Executor) commitCheckpoint(ctx context.Context, a Attempt, c Checkpoint, captureOnly bool) (Attempt, error) {
	var saved Attempt
	err := store.WithWriteTx(ctx, e.Ledger.DB, func(tx *sql.Tx) error {
		current, err := readAttempt(ctx, tx, "a.id=?", a.ID)
		if err != nil {
			return err
		}
		if current.Request.Target != e.Ledger.Target {
			return ErrForbidden
		}
		if current.Revision != a.Revision {
			if !captureOnly || current.State.Execution != a.State.Execution || current.State.Capture != a.State.Capture {
				return ErrStale
			}
			a = current
			c.State.Delivery = current.State.Delivery
		}
		if c.State.Execution != a.State.Execution && !a.State.Execution.CanTransition(c.State.Execution) {
			return transitionError(a.State.Execution, c.State.Execution)
		}
		if c.State.Capture != a.State.Capture && !a.State.Capture.CanTransition(c.State.Capture) {
			return fmt.Errorf("%w: invalid capture transition", ErrConflict)
		}
		if c.State.Delivery != a.State.Delivery || !validID(c.Reason) {
			return ErrInvalid
		}
		previous, previousRef, err := readCheckpoint(ctx, tx, a)
		if err != nil {
			return err
		}
		if c.Scope == nil && previous != nil {
			c.Scope = previous.Scope
		}
		if c.Capture == nil && previous != nil {
			c.Capture = previous.Capture
			if c.Capture != nil && c.State.Capture == Incomplete {
				copy := *c.Capture
				copy.State = Incomplete
				copy.Issues = append(append([]string{}, copy.Issues...), c.Reason)
				c.Capture = &copy
			}
		}
		if c.Capture != nil {
			copy := *c.Capture
			copy.State = c.State.Capture
			c.Capture = &copy
		}
		a.Revision++
		a.State, a.UpdatedAt = c.State, e.Ledger.now()
		c.SchemaVersion, c.AttemptID, c.Revision, c.At = SchemaVersion, a.ID, a.Revision, a.UpdatedAt
		c.Source, c.Target, c.DispatchID = a.Request.Source, a.Request.Target, a.Request.DispatchID
		c.RequestHash, c.DigestVersion = a.RequestHash, a.DigestVersion
		raw, err := json.Marshal(c)
		if err != nil {
			return err
		}
		var payload map[string]any
		if err := json.Unmarshal(raw, &payload); err != nil {
			return err
		}
		parents := []string{}
		if previousRef != "" {
			parents = append(parents, previousRef)
		}
		for _, out := range []*Output{c.Stdout, c.Stderr} {
			if out != nil && out.Ref != "" {
				parents = append(parents, out.Ref)
			}
		}
		obj, err := (provenance.ObjectStore{DB: e.Ledger.DB, Paths: e.Paths, Tx: tx}).PutExternalObject(provenance.ExternalObjectInput{
			Type: checkpointType, RunID: a.LocalRunID, SourceID: fmt.Sprintf("%s/%020d", a.ID, a.Revision), Parents: parents,
			Refs: map[string]any{"attempt_id": a.ID, "dispatch_id": a.Request.DispatchID}, Payload: payload,
		})
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE execution_attempts SET execution_state=?,capture_state=?,revision=?,updated_at_ns=? WHERE id=?`,
			a.State.Execution, a.State.Capture, a.Revision, a.UpdatedAt.UnixNano(), a.ID); err != nil {
			return err
		}
		if err := appendHistory(ctx, tx, a, c.Reason, []string{obj.Hash}); err != nil {
			return err
		}
		saved = a
		return nil
	})
	return saved, err
}
