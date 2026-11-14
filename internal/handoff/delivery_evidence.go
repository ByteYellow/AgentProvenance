package handoff

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/provenance"
)

const DeliveryEvidenceSchema = "agentprovenance.execution_delivery_evidence/v1"
const deliveryEvidenceType = "execution_delivery_evidence"

// DeliveryEvidence retains portable verification material. The verifier fields
// are public Ed25519 keys; their trust anchors are the caller admission's hashes.
type DeliveryEvidence struct {
	SchemaVersion    string `json:"schema_version"`
	AdmissionRef     string `json:"admission_ref"`
	Manifest         []byte `json:"manifest"`
	Receipt          []byte `json:"receipt"`
	TargetVerifier   string `json:"target_verifier"`
	ReceiverVerifier string `json:"receiver_verifier"`
}

func deliveryEvidenceID(ref string, version int64) string {
	return fmt.Sprintf("%s/%020d", strings.TrimPrefix(ref, "sha256:"), version)
}

func readSourceAdmission(ctx context.Context, q checkpointReader, run, ref string) (SourceAdmission, error) {
	var a SourceAdmission
	var kind, source string
	if err := q.QueryRowContext(ctx, `SELECT object_type,source_id FROM provenance_objects WHERE run_id=? AND hash=?`, run, ref).Scan(&kind, &source); err != nil {
		return a, err
	}
	if err := provenance.ReadObjectPayload(q, run, ref, &a); err != nil {
		return a, err
	}
	key := digest("source-admission/v1", operationKey(Request{Source: a.Identity.Source, OperationID: a.OperationID}), targetKey(a.Identity.Target))
	if kind != sourceAdmissionType || source != key || a.SchemaVersion != SourceAdmissionSchema || a.Identity.validate() != nil ||
		a.Identity.Source.RunID != run || !validID(a.PrincipalID) || !validID(a.OperationID) || !validID(a.ReceiverID) ||
		a.AttemptNumber < 1 || a.AcceptedAt.IsZero() || !validDigest(a.TargetKeySHA256) || !validDigest(a.ReceiverKeySHA256) ||
		(a.PreviousAttemptID != "" && !validID(a.PreviousAttemptID)) {
		return a, fmt.Errorf("%w: invalid saved source admission", ErrConflict)
	}
	var count int
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM provenance_objects WHERE object_type='execution_source_admission' AND source_id=?`, key).Scan(&count); err != nil {
		return a, err
	}
	if count != 1 {
		return a, fmt.Errorf("%w: conflicting source admission", ErrConflict)
	}
	return a, ctx.Err()
}

func (p DeliveryEvidence) verify() (DeliveryManifest, DeliveryReceipt, error) {
	var receipt DeliveryReceipt
	if p.SchemaVersion != DeliveryEvidenceSchema || !strings.HasPrefix(p.AdmissionRef, "sha256:") ||
		!validDigest(strings.TrimPrefix(p.AdmissionRef, "sha256:")) {
		return DeliveryManifest{}, receipt, fmt.Errorf("%w: invalid delivery evidence", ErrConflict)
	}
	target, err := hex.DecodeString(p.TargetVerifier)
	if err != nil || len(target) != ed25519.PublicKeySize {
		return DeliveryManifest{}, receipt, fmt.Errorf("%w: invalid target verifier", ErrConflict)
	}
	receiver, err := hex.DecodeString(p.ReceiverVerifier)
	if err != nil || len(receiver) != ed25519.PublicKeySize {
		return DeliveryManifest{}, receipt, fmt.Errorf("%w: invalid receiver verifier", ErrConflict)
	}
	m, err := verifyManifest(p.Manifest, ed25519.PublicKey(target))
	if err != nil {
		return m, receipt, err
	}
	hash := attest.DigestSHA256(p.Manifest)
	subject, err := verifyDelivery(p.Receipt, ed25519.PublicKey(receiver), receiptPredicate, &receipt)
	if err != nil {
		return m, receipt, err
	}
	if !receipt.matches(m, hash) || subject.Name != "execution-delivery/"+m.ID || subject.Digest["sha256"] != hash {
		return m, receipt, fmt.Errorf("%w: delivery receipt identity mismatch", ErrConflict)
	}
	return m, receipt, nil
}

func (p DeliveryEvidence) matchesAdmission(a SourceAdmission, m DeliveryManifest) bool {
	target, _ := hex.DecodeString(p.TargetVerifier)
	receiver, _ := hex.DecodeString(p.ReceiverVerifier)
	return a.Identity == m.Identity && a.ReceiverID == m.ReceiverID &&
		a.TargetKeySHA256 == attest.DigestSHA256(target) && a.ReceiverKeySHA256 == attest.DigestSHA256(receiver)
}

// Called inside the receipt transaction. A failed link write must not produce
// a successful receipt; replay can finish the same admission without execution.
func (s *DeliveryReceiver) saveDeliveryEvidence(ctx context.Context, tx *sql.Tx, m DeliveryManifest, envelope, receipt []byte) error {
	if s.SourceAdmissionRef == "" {
		return nil
	}
	a, err := readSourceAdmission(ctx, tx, m.Identity.Source.RunID, s.SourceAdmissionRef)
	if err != nil {
		return err
	}
	p := DeliveryEvidence{SchemaVersion: DeliveryEvidenceSchema, AdmissionRef: s.SourceAdmissionRef,
		Manifest: envelope, Receipt: receipt, TargetVerifier: hex.EncodeToString(s.TargetKey),
		ReceiverVerifier: hex.EncodeToString(s.SignKey.Public().(ed25519.PublicKey))}
	if !p.matchesAdmission(a, m) || a.PrincipalID != s.Caller.ID {
		return fmt.Errorf("%w: delivery source admission changed", ErrConflict)
	}
	key := deliveryEvidenceID(p.AdmissionRef, m.PackageVersion)
	var count int
	var ref string
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(MIN(hash),'') FROM provenance_objects
		WHERE run_id=? AND object_type='execution_delivery_evidence' AND source_id=?`, m.Identity.LocalRunID, key).Scan(&count, &ref); err != nil {
		return err
	}
	if count > 1 {
		return fmt.Errorf("%w: conflicting delivery evidence", ErrConflict)
	}
	if count == 0 {
		obj, err := (provenance.ObjectStore{DB: s.DB, Paths: s.Paths, Tx: tx}).PutExternalObject(provenance.ExternalObjectInput{
			Type: deliveryEvidenceType, SourceID: key, RunID: m.Identity.LocalRunID, Parents: []string{m.CheckpointRef},
			Payload: map[string]any{"schema_version": p.SchemaVersion, "admission_ref": p.AdmissionRef,
				"manifest": p.Manifest, "receipt": p.Receipt, "target_verifier": p.TargetVerifier, "receiver_verifier": p.ReceiverVerifier},
		})
		if err != nil {
			return err
		}
		ref = obj.Hash
	}
	var saved DeliveryEvidence
	if err := provenance.ReadObjectPayload(tx, m.Identity.LocalRunID, ref, &saved); err != nil {
		return err
	}
	wantJSON, _ := json.Marshal(p)
	savedJSON, _ := json.Marshal(saved)
	if !bytes.Equal(wantJSON, savedJSON) {
		return fmt.Errorf("%w: saved delivery evidence changed", ErrConflict)
	}
	_, _, err = saved.verify()
	return err
}
