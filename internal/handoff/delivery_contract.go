package handoff

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/forensics"
)

const (
	DeliverySchema    = "agentprovenance.execution_delivery/v1"
	ReceiptSchema     = "agentprovenance.execution_receipt/v1"
	deliveryPredicate = "https://agentprovenance.dev/ExecutionDelivery/v1"
	receiptPredicate  = "https://agentprovenance.dev/ExecutionReceipt/v1"
	MaxEnvelopeBytes  = 64 << 10
)

// ExecutionIdentity is obtained from an authenticated admission, independently
// of the package being received. Native IDs remain qualified on both sides.
type ExecutionIdentity struct {
	Source        Source `json:"source"`
	Target        Target `json:"target"`
	DispatchID    string `json:"dispatch_id"`
	AttemptID     string `json:"attempt_id"`
	RequestHash   string `json:"request_hash"`
	DigestVersion string `json:"digest_version"`
	LocalRunID    string `json:"local_run_id"`
}

func IdentityOf(a Attempt) ExecutionIdentity {
	return ExecutionIdentity{a.Request.Source, a.Request.Target, a.Request.DispatchID,
		a.ID, a.RequestHash, a.DigestVersion, a.LocalRunID}
}

func (i ExecutionIdentity) validate() error {
	if i.Source.Validate() != nil || i.Target.Validate() != nil ||
		!validID(i.DispatchID) || !validID(i.AttemptID) || !validID(i.LocalRunID) ||
		!validDigest(i.RequestHash) || i.DigestVersion != DigestVersion {
		return fmt.Errorf("%w: invalid delivery execution identity", ErrInvalid)
	}
	return nil
}

// The range is the exact immutable bundle, not a claim that all kernel events
// have arrived. Capture state and its checkpoint travel separately from ACK.
type DeliveryManifest struct {
	SchemaVersion          string            `json:"schema_version"`
	ID                     string            `json:"id"`
	Identity               ExecutionIdentity `json:"identity"`
	ReceiverID             string            `json:"receiver_id"`
	PackageVersion         int64             `json:"package_version"`
	PreviousManifestSHA256 string            `json:"previous_manifest_sha256,omitempty"`
	AttemptRevision        int64             `json:"attempt_revision"`
	CheckpointRef          string            `json:"checkpoint_ref"`
	State                  State             `json:"state"`
	BundleSHA256           string            `json:"bundle_sha256"`
	BundleBytes            int64             `json:"bundle_bytes"`
	SnapshotAt             time.Time         `json:"snapshot_at"`
}

func (m DeliveryManifest) validate() error {
	if m.SchemaVersion != DeliverySchema || !validDigest(m.ID) || m.Identity.validate() != nil ||
		!validID(m.ReceiverID) || m.PackageVersion < 1 || m.AttemptRevision < 1 ||
		!validDigest(m.BundleSHA256) || !strings.HasPrefix(m.CheckpointRef, "sha256:") || !validDigest(strings.TrimPrefix(m.CheckpointRef, "sha256:")) ||
		m.BundleBytes < 1 || m.BundleBytes > forensics.MaxStrictBundleBytes || m.SnapshotAt.IsZero() {
		return fmt.Errorf("%w: invalid delivery manifest", ErrInvalid)
	}
	if (m.PackageVersion == 1 && m.PreviousManifestSHA256 != "") ||
		(m.PackageVersion > 1 && !validDigest(m.PreviousManifestSHA256)) {
		return fmt.Errorf("%w: invalid delivery predecessor", ErrInvalid)
	}
	if !m.State.Execution.CanReexecute() {
		return fmt.Errorf("%w: execution has not reached a deliverable state", ErrConflict)
	}
	switch m.State.Capture {
	case NotReady, Collecting, Draining, Sealed, Incomplete:
	default:
		return fmt.Errorf("%w: invalid capture state", ErrInvalid)
	}
	switch m.State.Delivery {
	case Pending, Transferring, Acknowledged, Conflict:
	default:
		return fmt.Errorf("%w: invalid delivery state", ErrInvalid)
	}
	return nil
}

type DeliveryReceipt struct {
	SchemaVersion  string            `json:"schema_version"`
	DeliveryID     string            `json:"delivery_id"`
	Identity       ExecutionIdentity `json:"identity"`
	ReceiverID     string            `json:"receiver_id"`
	PackageVersion int64             `json:"package_version"`
	ManifestSHA256 string            `json:"manifest_sha256"`
	BundleSHA256   string            `json:"bundle_sha256"`
	BundleBytes    int64             `json:"bundle_bytes"`
	Status         string            `json:"status"`
	ReceivedAt     time.Time         `json:"received_at"`
}

func (r DeliveryReceipt) matches(m DeliveryManifest, manifestHash string) bool {
	return r.SchemaVersion == ReceiptSchema && r.DeliveryID == m.ID && r.Identity == m.Identity &&
		r.ReceiverID == m.ReceiverID && r.PackageVersion == m.PackageVersion &&
		r.ManifestSHA256 == manifestHash && r.BundleSHA256 == m.BundleSHA256 &&
		r.BundleBytes == m.BundleBytes && r.Status == "persisted" && !r.ReceivedAt.IsZero()
}

func signDelivery(predicate, id, hash string, claim any, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid delivery signing key")
	}
	s := attest.NewStatement("execution-delivery/"+id, hash, claim)
	s.PredicateType = predicate
	env, err := attest.Sign(s, key, attest.KeyID(key.Public().(ed25519.PublicKey)))
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(env)
	if len(raw) > MaxEnvelopeBytes {
		return nil, fmt.Errorf("delivery envelope too large")
	}
	return raw, err
}

// Decode the authenticated payload again into exact types, retaining int64
// precision instead of passing the generic Statement.Predicate through floats.
func verifyDelivery(raw []byte, pub ed25519.PublicKey, predicate string, claim any) (attest.Subject, error) {
	if len(raw) > MaxEnvelopeBytes {
		return attest.Subject{}, fmt.Errorf("%w: delivery envelope too large", ErrInvalid)
	}
	var env attest.Envelope
	if err := decodeDeliveryJSON(raw, &env); err != nil {
		return attest.Subject{}, err
	}
	if env.PayloadType != "application/vnd.in-toto+json" {
		return attest.Subject{}, ErrInvalid
	}
	s, err := attest.Verify(env, pub)
	if err != nil {
		return attest.Subject{}, fmt.Errorf("%w: invalid delivery signature", ErrForbidden)
	}
	if s.Type != attest.StatementType || s.PredicateType != predicate || len(s.Subject) != 1 ||
		len(s.Subject[0].Digest) != 1 || !validDigest(s.Subject[0].Digest["sha256"]) {
		return attest.Subject{}, fmt.Errorf("%w: invalid delivery statement", ErrInvalid)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return attest.Subject{}, err
	}
	var typed struct {
		Type          string           `json:"_type"`
		Subject       []attest.Subject `json:"subject"`
		PredicateType string           `json:"predicateType"`
		Predicate     json.RawMessage  `json:"predicate"`
	}
	if err := decodeDeliveryJSON(payload, &typed); err != nil {
		return attest.Subject{}, err
	}
	if err := decodeDeliveryJSON(typed.Predicate, claim); err != nil {
		return attest.Subject{}, err
	}
	return s.Subject[0], nil
}

func decodeDeliveryJSON(raw []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("%w: trailing delivery data", ErrInvalid)
	}
	return nil
}

func validDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	b, err := hex.DecodeString(s)
	return err == nil && hex.EncodeToString(b) == s
}

func verifyManifest(raw []byte, pub ed25519.PublicKey) (DeliveryManifest, error) {
	var m DeliveryManifest
	subject, err := verifyDelivery(raw, pub, deliveryPredicate, &m)
	if err != nil {
		return m, err
	}
	if err := m.validate(); err != nil {
		return m, err
	}
	if subject.Name != "execution-delivery/"+m.ID || subject.Digest["sha256"] != m.BundleSHA256 {
		return m, fmt.Errorf("%w: delivery subject mismatch", ErrInvalid)
	}
	return m, nil
}
