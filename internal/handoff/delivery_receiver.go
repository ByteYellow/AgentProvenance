package handoff

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/store"
)

type DeliveryReceiver struct {
	DB        *sql.DB
	Paths     store.Paths
	ID        string
	SignKey   ed25519.PrivateKey
	Target    Target
	TargetKey ed25519.PublicKey
	Caller    Principal
	Now       func() time.Time
	slot      deliverySlot
}

// Receive expects an identity saved from an authenticated admission. Trust is
// pinned to TargetKey, not the envelope's keyid or an uploaded public key.
func (s *DeliveryReceiver) Receive(ctx context.Context, expected ExecutionIdentity, envelope []byte, bundle io.Reader) ([]byte, error) {
	if len(envelope) > MaxEnvelopeBytes {
		return nil, ErrInvalid
	}
	envelope = append([]byte(nil), envelope...)
	if s.DB == nil || s.Paths.Root == "" || !validID(s.ID) || len(s.SignKey) != ed25519.PrivateKeySize ||
		len(s.TargetKey) != ed25519.PublicKeySize || s.Target.Validate() != nil || bundle == nil {
		return nil, fmt.Errorf("invalid delivery receiver configuration")
	}
	m, err := s.VerifyManifest(expected, envelope)
	if err != nil {
		return nil, err
	}
	manifestHash := attest.DigestSHA256(envelope)
	release, err := s.slot.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if receipt, path, err := s.saved(ctx, s.DB, m, manifestHash); err == nil {
		if err := checkDeliveryFile(ctx, path, m); err != nil {
			return nil, err
		}
		return receipt, nil
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return s.receiveNew(ctx, expected, envelope, bundle, m, manifestHash)
}

// VerifyManifest allows a pull client to authenticate the package before
// opening its body stream. The receiver repeats the check before persistence.
func (s *DeliveryReceiver) VerifyManifest(expected ExecutionIdentity, envelope []byte) (DeliveryManifest, error) {
	if expected.validate() != nil || expected.Target != s.Target || s.Caller.Authorize(expected.Source, expected.Target) != nil {
		return DeliveryManifest{}, ErrForbidden
	}
	m, err := verifyManifest(envelope, s.TargetKey)
	if err != nil {
		return DeliveryManifest{}, err
	}
	if m.Identity != expected || m.ReceiverID != s.ID {
		return DeliveryManifest{}, ErrForbidden
	}
	return m, nil
}

func (s *DeliveryReceiver) receiveNew(ctx context.Context, expected ExecutionIdentity, envelope []byte, bundle io.Reader, m DeliveryManifest, manifestHash string) ([]byte, error) {
	if err := s.checkPredecessor(ctx, s.DB, m); err != nil {
		return nil, err
	}
	root := filepath.Join(s.Paths.Artifacts, "execution-delivery-inbox")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	work, err := os.MkdirTemp(root, ".receive-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)
	path := filepath.Join(work, "bundle.json")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, h), io.LimitReader(&deliveryReader{ctx, bundle}, m.BundleBytes+1))
	closeErr := f.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return nil, err
	}
	if n != m.BundleBytes || hex.EncodeToString(h.Sum(nil)) != m.BundleSHA256 {
		return nil, fmt.Errorf("%w: delivery bundle digest or size mismatch", ErrConflict)
	}
	if err := checkDeliveryCheckpoint(ctx, path, m); err != nil {
		return nil, err
	}
	var receipt []byte
	_, err = (forensics.Service{DB: s.DB, Paths: s.Paths}).ImportBundleStrictWithCommit(ctx, path, expected.LocalRunID,
		func(tx *sql.Tx, archivePath string) error {
			if existing, _, err := s.saved(ctx, tx, m, manifestHash); err == nil {
				receipt = existing
				return nil
			} else if !errors.Is(err, ErrNotFound) {
				return err
			}
			if err := s.checkPredecessor(ctx, tx, m); err != nil {
				return err
			}
			now := time.Now().UTC()
			if s.Now != nil {
				now = s.Now().UTC()
			}
			r := DeliveryReceipt{SchemaVersion: ReceiptSchema, DeliveryID: m.ID, Identity: expected, ReceiverID: s.ID,
				PackageVersion: m.PackageVersion, ManifestSHA256: manifestHash, BundleSHA256: m.BundleSHA256,
				BundleBytes: m.BundleBytes, Status: "persisted", ReceivedAt: now}
			var err error
			receipt, err = signDelivery(receiptPredicate, m.ID, manifestHash, r, s.SignKey)
			if err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO execution_delivery_receipts
				(receipt_key,target_key,attempt_id,receiver_id,package_version,manifest_json,manifest_sha256,bundle_path,receipt_json,created_at_ns)
				VALUES (?,?,?,?,?,?,?,?,?,?)`, receiptKey(m), targetKey(m.Identity.Target), expected.AttemptID, s.ID,
				m.PackageVersion, envelope, manifestHash, archivePath, receipt, now.UnixNano())
			return err
		})
	if err != nil {
		return nil, err
	}
	return receipt, nil
}

func targetKey(t Target) string {
	return digest("execution-target/v1", t.ProducerID, t.InstanceID, t.Generation)
}
func receiptKey(m DeliveryManifest) string {
	return digest("execution-receipt/v1", targetKey(m.Identity.Target), m.ReceiverID, m.ID)
}

func (s *DeliveryReceiver) saved(ctx context.Context, q queryer, m DeliveryManifest, hash string) ([]byte, string, error) {
	var raw []byte
	var stored, path string
	err := q.QueryRowContext(ctx, `SELECT manifest_sha256,receipt_json,bundle_path FROM execution_delivery_receipts WHERE receipt_key=?`, receiptKey(m)).Scan(&stored, &raw, &path)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", ErrNotFound
	}
	if err != nil {
		return nil, "", err
	}
	if stored != hash {
		return nil, "", ErrConflict
	}
	var r DeliveryReceipt
	subject, err := verifyDelivery(raw, s.SignKey.Public().(ed25519.PublicKey), receiptPredicate, &r)
	if err != nil {
		return nil, "", err
	}
	if !r.matches(m, hash) || subject.Name != "execution-delivery/"+m.ID || subject.Digest["sha256"] != hash {
		return nil, "", fmt.Errorf("saved delivery receipt mismatch")
	}
	return raw, path, nil
}

func (s *DeliveryReceiver) checkPredecessor(ctx context.Context, q queryer, m DeliveryManifest) error {
	var version int64
	var hash string
	err := q.QueryRowContext(ctx, `SELECT package_version,manifest_sha256 FROM execution_delivery_receipts
		WHERE target_key=? AND attempt_id=? AND receiver_id=? ORDER BY package_version DESC LIMIT 1`,
		targetKey(m.Identity.Target), m.Identity.AttemptID, s.ID).Scan(&version, &hash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if m.PackageVersion != version+1 || m.PreviousManifestSHA256 != hash {
		return fmt.Errorf("%w: delivery predecessor is missing or conflicts", ErrConflict)
	}
	return nil
}

type deliveryReader struct {
	ctx   context.Context
	input io.Reader
}

func (r *deliveryReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.input.Read(p)
}

func checkDeliveryFile(ctx context.Context, path string, m DeliveryManifest) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return checkDeliveryHandle(ctx, f, m)
}

func checkDeliveryHandle(ctx context.Context, f *os.File, m DeliveryManifest) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != m.BundleBytes {
		return fmt.Errorf("delivery file size or type mismatch")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(&deliveryReader{ctx, f}, m.BundleBytes+1))
	if err != nil {
		return err
	}
	if n != m.BundleBytes || hex.EncodeToString(h.Sum(nil)) != m.BundleSHA256 {
		return fmt.Errorf("delivery file digest mismatch")
	}
	return nil
}

func checkDeliveryCheckpoint(ctx context.Context, path string, m DeliveryManifest) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var b struct {
		RunID   string `json:"run_id"`
		Objects []struct {
			Hash  string `json:"hash"`
			RunID string `json:"run_id"`
			Type  string `json:"object_type"`
		} `json:"provenance_objects"`
		Blobs []struct {
			Hash    string `json:"hash"`
			Content string `json:"content_b64"`
		} `json:"object_blobs"`
	}
	if err := json.NewDecoder(io.LimitReader(&deliveryReader{ctx, f}, m.BundleBytes+1)).Decode(&b); err != nil {
		return err
	}
	if b.RunID != m.Identity.LocalRunID {
		return fmt.Errorf("%w: delivery run mismatch", ErrConflict)
	}
	found := false
	for _, o := range b.Objects {
		if o.Hash == m.CheckpointRef && o.Type == checkpointType && o.RunID == b.RunID {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("%w: delivery checkpoint index missing", ErrConflict)
	}
	for _, blob := range b.Blobs {
		if blob.Hash != m.CheckpointRef {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(blob.Content)
		if err != nil {
			return err
		}
		if "sha256:"+attest.DigestSHA256(raw) != m.CheckpointRef {
			return fmt.Errorf("delivery checkpoint digest mismatch")
		}
		var obj struct {
			Schema  string     `json:"schema"`
			Type    string     `json:"type"`
			RunID   string     `json:"run_id"`
			Payload Checkpoint `json:"payload"`
		}
		if err := json.Unmarshal(raw, &obj); err != nil {
			return err
		}
		c := obj.Payload
		if obj.Schema != "agentprov.provenance.object.v1" || obj.Type != checkpointType || obj.RunID != b.RunID ||
			c.SchemaVersion != SchemaVersion || c.Source != m.Identity.Source || c.Target != m.Identity.Target ||
			c.AttemptID != m.Identity.AttemptID || c.DispatchID != m.Identity.DispatchID || c.RequestHash != m.Identity.RequestHash ||
			c.DigestVersion != m.Identity.DigestVersion || c.Revision < 1 || c.Revision > m.AttemptRevision ||
			c.State.Execution != m.State.Execution || c.State.Capture != m.State.Capture {
			return fmt.Errorf("%w: delivery checkpoint identity or state mismatch", ErrConflict)
		}
		return ctx.Err()
	}
	return fmt.Errorf("%w: delivery checkpoint body missing", ErrConflict)
}

func syncDeliveryPath(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}
