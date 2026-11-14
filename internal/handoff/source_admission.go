package handoff

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"fmt"
	"time"

	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
)

const SourceAdmissionSchema = "agentprovenance.execution_source_admission/v1"
const sourceAdmissionType = "execution_source_admission"

// SourceAdmission records the router's independently checked admission, without
// retaining command bodies or credential paths. State changes travel separately
// in execution checkpoints and delivery receipts.
type SourceAdmission struct {
	SchemaVersion     string            `json:"schema_version"`
	Identity          ExecutionIdentity `json:"identity"`
	PrincipalID       string            `json:"principal_id"`
	OperationID       string            `json:"operation_id"`
	PreviousAttemptID string            `json:"previous_attempt_id,omitempty"`
	AttemptNumber     int               `json:"attempt_number"`
	AcceptedAt        time.Time         `json:"accepted_at"`
	TargetKeySHA256   string            `json:"target_key_sha256"`
	ReceiverID        string            `json:"receiver_id"`
	ReceiverKeySHA256 string            `json:"receiver_key_sha256"`
}

// RecordAdmission must be called with the locally prepared request and the
// response from the configured authenticated endpoint, before collecting its
// evidence. An uploaded delivery manifest is not an admission source.
func (s *DeliveryReceiver) RecordAdmission(ctx context.Context, prepared Request, attempt Attempt) (string, error) {
	if s.DB == nil || s.Paths.Root == "" || !validID(s.ID) || len(s.SignKey) != ed25519.PrivateKeySize || len(s.TargetKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid source admission configuration")
	}
	request, _, expected, err := prepared.Canonical()
	if err != nil {
		return "", err
	}
	if request.Target != s.Target || s.Caller.Authorize(request.Source, request.Target) != nil {
		return "", ErrForbidden
	}
	_, _, actual, err := attempt.Request.Canonical()
	identity := IdentityOf(attempt)
	if err != nil || attempt.SchemaVersion != SchemaVersion || identity.validate() != nil ||
		expected != actual || attempt.RequestHash != expected || attempt.Number < 1 || attempt.CreatedAt.IsZero() {
		return "", fmt.Errorf("%w: source admission does not match prepared request", ErrConflict)
	}
	want := SourceAdmission{SchemaVersion: SourceAdmissionSchema, Identity: identity,
		PrincipalID: s.Caller.ID, OperationID: request.OperationID, PreviousAttemptID: request.PreviousAttemptID,
		AttemptNumber: attempt.Number, AcceptedAt: attempt.CreatedAt.UTC(), TargetKeySHA256: attest.DigestSHA256(s.TargetKey),
		ReceiverID: s.ID, ReceiverKeySHA256: attest.DigestSHA256(s.SignKey.Public().(ed25519.PublicKey))}
	key := digest("source-admission/v1", operationKey(request), targetKey(request.Target))
	var ref string
	err = store.WithWriteTx(ctx, s.DB, func(tx *sql.Tx) error {
		var count int
		var run string
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(MIN(hash),''),COALESCE(MIN(run_id),'')
			FROM provenance_objects WHERE object_type='execution_source_admission' AND source_id=?`, key).Scan(&count, &ref, &run); err != nil {
			return err
		}
		if count > 1 || count == 1 && run != request.Source.RunID {
			return fmt.Errorf("%w: conflicting source admission", ErrConflict)
		}
		if count == 0 {
			obj, err := (provenance.ObjectStore{DB: s.DB, Paths: s.Paths, Tx: tx}).PutExternalObject(provenance.ExternalObjectInput{
				Type: sourceAdmissionType, SourceID: key, RunID: request.Source.RunID,
				Payload: map[string]any{
					"schema_version": want.SchemaVersion, "identity": want.Identity, "principal_id": want.PrincipalID,
					"operation_id": want.OperationID, "previous_attempt_id": want.PreviousAttemptID,
					"attempt_number": want.AttemptNumber, "accepted_at": want.AcceptedAt,
					"target_key_sha256": want.TargetKeySHA256, "receiver_id": want.ReceiverID, "receiver_key_sha256": want.ReceiverKeySHA256,
				},
			})
			if err != nil {
				return err
			}
			ref = obj.Hash
		}
		// Verify the content-addressed readback, including any redaction applied
		// by the object store, before making it an identity anchor.
		var saved SourceAdmission
		if err := provenance.ReadObjectPayload(tx, request.Source.RunID, ref, &saved); err != nil {
			return err
		}
		saved.AcceptedAt = saved.AcceptedAt.UTC()
		if saved != want {
			return fmt.Errorf("%w: saved source admission identity changed", ErrConflict)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return ref, nil
}
