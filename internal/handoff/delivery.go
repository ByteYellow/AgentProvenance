package handoff

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/store"
)

// DeliveryService owns one bounded export at a time. Keys and receiver identity
// are trusted deployment configuration, never supplied by the submitting model.
type DeliveryService struct {
	Ledger      Ledger
	Paths       store.Paths
	SignKey     ed25519.PrivateKey
	ReceiverID  string
	ReceiverKey ed25519.PublicKey
	slot        deliverySlot
}

type deliverySlot struct {
	once sync.Once
	ch   chan struct{}
}

func (s *deliverySlot) acquire(ctx context.Context) (func(), error) {
	s.once.Do(func() { s.ch = make(chan struct{}, 1) })
	select {
	case s.ch <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-s.ch
			return nil, err
		}
		return func() { <-s.ch }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type Delivery struct {
	Manifest       DeliveryManifest `json:"manifest"`
	Envelope       json.RawMessage  `json:"envelope"`
	ManifestSHA256 string           `json:"manifest_sha256"`
	Receipt        json.RawMessage  `json:"receipt,omitempty"`
	BundlePath     string           `json:"-"`
}

func (s *DeliveryService) validate() error {
	if s.Ledger.DB == nil || s.Paths.Root == "" || s.Ledger.Target.Validate() != nil ||
		!validID(s.ReceiverID) || len(s.SignKey) != ed25519.PrivateKeySize || len(s.ReceiverKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid delivery service configuration")
	}
	return nil
}

// Prepare freezes a coherent database view and publishes an immutable package
// before recording the outbox entry. Reusing an operation returns those bytes.
func (s *DeliveryService) Prepare(ctx context.Context, p Principal, attemptID, operationID string) (Delivery, bool, error) {
	if err := s.validate(); err != nil {
		return Delivery{}, false, err
	}
	if !validID(operationID) {
		return Delivery{}, false, ErrInvalid
	}
	authorized, err := s.Ledger.Get(ctx, p, attemptID)
	if err != nil {
		return Delivery{}, false, err
	}
	if authorized.Request.Target != s.Ledger.Target {
		return Delivery{}, false, ErrForbidden
	}
	release, err := s.slot.acquire(ctx)
	if err != nil {
		return Delivery{}, false, err
	}
	defer release()
	id := digest("execution-delivery/v1", attemptID, operationID)
	if existing, err := s.read(ctx, s.Ledger.DB, id); err == nil {
		if existing.Manifest.ReceiverID != s.ReceiverID {
			return Delivery{}, false, ErrConflict
		}
		if err := checkDeliveryFile(ctx, existing.BundlePath, existing.Manifest); err != nil {
			return Delivery{}, false, err
		}
		return existing, true, nil
	} else if !errors.Is(err, ErrNotFound) {
		return Delivery{}, false, err
	}
	root := filepath.Join(s.Paths.Artifacts, "execution-deliveries")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return Delivery{}, false, err
	}
	work, err := os.MkdirTemp(root, ".prepare-")
	if err != nil {
		return Delivery{}, false, err
	}
	defer os.RemoveAll(work)
	frozenPaths := store.ResolvePaths(filepath.Join(work, "projection"))
	if err := os.MkdirAll(frozenPaths.Root, 0o700); err != nil {
		return Delivery{}, false, err
	}
	if _, err := s.Ledger.DB.ExecContext(ctx, "VACUUM INTO ?", frozenPaths.DB); err != nil {
		return Delivery{}, false, err
	}
	if _, err := store.Init(frozenPaths.Root); err != nil {
		return Delivery{}, false, err
	}
	db, err := store.Open(frozenPaths)
	if err != nil {
		return Delivery{}, false, err
	}
	defer db.Close()
	frozenLedger := s.Ledger
	frozenLedger.DB = db
	report, err := frozenLedger.Report(ctx, p, attemptID)
	if err != nil {
		return Delivery{}, false, err
	}
	if report.Checkpoint == nil || !report.Attempt.State.Execution.CanReexecute() {
		return Delivery{}, false, fmt.Errorf("%w: execution checkpoint is not ready for delivery", ErrConflict)
	}
	version, previousHash, err := latestDelivery(ctx, db, attemptID, s.ReceiverID)
	if err != nil {
		return Delivery{}, false, err
	}
	// Transfer the saved projection without rerunning analysis. Rematerializing
	// objects here changes index timestamps and breaks append-only reimports.
	info, err := (forensics.Service{DB: db, Paths: frozenPaths}).ExportBundleBounded(ctx, report.Attempt.LocalRunID, forensics.MaxStrictBundleBytes)
	if err != nil {
		return Delivery{}, false, err
	}
	m := DeliveryManifest{SchemaVersion: DeliverySchema, ID: id, Identity: IdentityOf(report.Attempt), ReceiverID: s.ReceiverID,
		PackageVersion: version + 1, PreviousManifestSHA256: previousHash, AttemptRevision: report.Attempt.Revision,
		CheckpointRef: report.CheckpointRef, State: report.Attempt.State, BundleSHA256: info.SHA256, BundleBytes: info.SizeBytes,
		SnapshotAt: s.Ledger.now()}
	if err := m.validate(); err != nil {
		return Delivery{}, false, err
	}
	if err := checkDeliveryFile(ctx, info.Path, m); err != nil {
		return Delivery{}, false, err
	}
	if err := checkDeliveryCheckpoint(ctx, info.Path, m); err != nil {
		return Delivery{}, false, err
	}
	env, err := signDelivery(deliveryPredicate, id, info.SHA256, m, s.SignKey)
	if err != nil {
		return Delivery{}, false, err
	}
	archive := filepath.Join(work, "archive")
	if err := os.Mkdir(archive, 0o700); err != nil {
		return Delivery{}, false, err
	}
	if err := os.Rename(info.Path, filepath.Join(archive, "bundle.json")); err != nil {
		return Delivery{}, false, err
	}
	if err := os.WriteFile(filepath.Join(archive, "manifest.dsse.json"), env, 0o600); err != nil {
		return Delivery{}, false, err
	}
	for _, name := range []string{"bundle.json", "manifest.dsse.json", ""} {
		if err := syncDeliveryPath(filepath.Join(archive, name)); err != nil {
			return Delivery{}, false, err
		}
	}
	// A unique directory permits concurrent processes to race the SQL CAS without
	// replacing a previously published package. Losing exports are unreferenced.
	final := filepath.Join(root, "package-"+filepath.Base(work)[len(".prepare-"):])
	if err := os.Rename(archive, final); err != nil {
		return Delivery{}, false, err
	}
	if err := syncDeliveryPath(root); err != nil {
		return Delivery{}, false, err
	}
	d := Delivery{Manifest: m, Envelope: env, ManifestSHA256: attest.DigestSHA256(env), BundlePath: filepath.Join(final, "bundle.json")}
	reused := false
	err = store.WithWriteTx(ctx, s.Ledger.DB, func(tx *sql.Tx) error {
		if existing, err := s.read(ctx, tx, id); err == nil {
			if existing.Manifest.ReceiverID != s.ReceiverID {
				return ErrConflict
			}
			d, reused = existing, true
			return nil
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		v, prev, err := latestDelivery(ctx, tx, attemptID, s.ReceiverID)
		if err != nil {
			return err
		}
		if v != version || prev != previousHash {
			return ErrStale
		}
		a, err := readAttempt(ctx, tx, "a.id=?", attemptID)
		if err != nil {
			return err
		}
		if a.principalID != p.ID || p.Authorize(a.Request.Source, a.Request.Target) != nil || IdentityOf(a) != m.Identity {
			return ErrForbidden
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO execution_deliveries
			(id,attempt_id,operation_id,receiver_id,package_version,manifest_json,manifest_sha256,bundle_path,created_at_ns)
			VALUES (?,?,?,?,?,?,?,?,?)`, id, attemptID, operationID, s.ReceiverID, m.PackageVersion, []byte(env), d.ManifestSHA256, d.BundlePath, s.Ledger.now().UnixNano()); err != nil {
			return err
		}
		return s.deliveryTransition(ctx, tx, a, Transferring, "delivery_prepared", d.ManifestSHA256)
	})
	if err != nil {
		return Delivery{}, false, err
	}
	if reused {
		if err := checkDeliveryFile(ctx, d.BundlePath, d.Manifest); err != nil {
			return Delivery{}, false, err
		}
	}
	return d, reused, nil
}

func latestDelivery(ctx context.Context, q queryer, attempt, receiver string) (int64, string, error) {
	var version int64
	var hash string
	err := q.QueryRowContext(ctx, `SELECT package_version,manifest_sha256 FROM execution_deliveries
		WHERE attempt_id=? AND receiver_id=? ORDER BY package_version DESC LIMIT 1`, attempt, receiver).Scan(&version, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", nil
	}
	return version, hash, err
}

func (s *DeliveryService) read(ctx context.Context, q queryer, id string) (Delivery, error) {
	var d Delivery
	var envelope, receipt []byte
	err := q.QueryRowContext(ctx, `SELECT manifest_json,manifest_sha256,bundle_path,receipt_json FROM execution_deliveries WHERE id=?`, id).
		Scan(&envelope, &d.ManifestSHA256, &d.BundlePath, &receipt)
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	if err != nil {
		return d, err
	}
	d.Envelope, d.Receipt = envelope, receipt
	if attest.DigestSHA256(d.Envelope) != d.ManifestSHA256 {
		return d, fmt.Errorf("saved delivery manifest digest mismatch")
	}
	d.Manifest, err = verifyManifest(d.Envelope, s.SignKey.Public().(ed25519.PublicKey))
	if err == nil && d.Manifest.ID != id {
		err = fmt.Errorf("saved delivery identity mismatch")
	}
	return d, err
}

func (s *DeliveryService) Get(ctx context.Context, p Principal, id string) (Delivery, error) {
	if err := s.validate(); err != nil {
		return Delivery{}, err
	}
	d, err := s.read(ctx, s.Ledger.DB, id)
	if err != nil {
		return Delivery{}, err
	}
	if _, err := s.Ledger.Get(ctx, p, d.Manifest.Identity.AttemptID); err != nil {
		return Delivery{}, err
	}
	return d, nil
}

// Acknowledge updates only delivery state. All outstanding packages, including
// older versions or other receivers, must have receipts before the summary ACK.
func (s *DeliveryService) Acknowledge(ctx context.Context, p Principal, id string, raw []byte) (Delivery, error) {
	if len(raw) > MaxEnvelopeBytes {
		return Delivery{}, ErrInvalid
	}
	raw = append([]byte(nil), raw...)
	d, err := s.Get(ctx, p, id)
	if err != nil {
		return Delivery{}, err
	}
	var r DeliveryReceipt
	subject, err := verifyDelivery(raw, s.ReceiverKey, receiptPredicate, &r)
	if err != nil {
		return Delivery{}, err
	}
	if !r.matches(d.Manifest, d.ManifestSHA256) || r.ReceiverID != s.ReceiverID ||
		subject.Name != "execution-delivery/"+id || subject.Digest["sha256"] != d.ManifestSHA256 {
		return Delivery{}, ErrConflict
	}
	err = store.WithWriteTx(ctx, s.Ledger.DB, func(tx *sql.Tx) error {
		a, err := readAttempt(ctx, tx, "a.id=?", d.Manifest.Identity.AttemptID)
		if err != nil {
			return err
		}
		if a.principalID != p.ID || p.Authorize(a.Request.Source, a.Request.Target) != nil {
			return ErrForbidden
		}
		stored, err := s.read(ctx, tx, id)
		if err != nil {
			return err
		}
		if len(stored.Receipt) != 0 {
			d = stored
			return nil
		}
		if _, err := tx.ExecContext(ctx, "UPDATE execution_deliveries SET receipt_json=? WHERE id=?", raw, id); err != nil {
			return err
		}
		var pending int
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM execution_deliveries WHERE attempt_id=? AND receipt_json IS NULL)`, a.ID).Scan(&pending); err != nil {
			return err
		}
		next := Transferring
		if pending == 0 {
			next = Acknowledged
		}
		if err := s.deliveryTransition(ctx, tx, a, next, "delivery_receipt_persisted", attest.DigestSHA256(raw)); err != nil {
			return err
		}
		d.Receipt = append([]byte(nil), raw...)
		return nil
	})
	return d, err
}

func (s *DeliveryService) deliveryTransition(ctx context.Context, tx *sql.Tx, a Attempt, next DeliveryState, reason, ref string) error {
	if a.State.Delivery != next && !a.State.Delivery.CanTransition(next) {
		// ACK remains terminal for each package. Only a newly persisted package
		// can extend the attempt's range and reopen its aggregate delivery state.
		if a.State.Delivery != Acknowledged || next != Transferring || reason != "delivery_prepared" {
			return ErrConflict
		}
		var pending bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM execution_deliveries WHERE attempt_id=? AND receipt_json IS NULL)`, a.ID).Scan(&pending); err != nil {
			return err
		}
		if !pending {
			return ErrConflict
		}
	}
	a.State.Delivery, a.Revision, a.UpdatedAt = next, a.Revision+1, s.Ledger.now()
	if _, err := tx.ExecContext(ctx, `UPDATE execution_attempts SET delivery_state=?,revision=?,updated_at_ns=? WHERE id=?`,
		next, a.Revision, a.UpdatedAt.UnixNano(), a.ID); err != nil {
		return err
	}
	return appendHistory(ctx, tx, a, reason, []string{"sha256:" + ref})
}
