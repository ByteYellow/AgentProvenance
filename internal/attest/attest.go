// Package attest provides capture-time, off-host-verifiable signing for
// evidence - the difference between an audit log and an audit log a defender can
// trust after host compromise.
//
// AgentProvenance's `graph verify` recomputes hashes from a SQLite file the
// attacker controls post-root: rewrite the row, recompute the chain, verify
// passes. That is integrity against corruption, not tamper-evidence against the
// HIDS threat model. This package signs an evidence digest with a key at capture
// time so that, even if the store is later rewritten, the signature over the
// original digest no longer verifies.
//
// The formats are deliberately standard rather than bespoke:
//   - the payload is an in-toto Statement (subject digests + a predicate),
//   - the envelope is DSSE (Dead Simple Signing Envelope, the in-toto/SLSA
//     transport), with ed25519 signatures.
//
// The signing key here is a local ed25519 key (file/env). Anchoring it in a TPM
// or remote KMS so it is unobtainable after root, and posting the chain head to
// an external transparency log, are deployment concerns layered on top of this
// primitive; the wire format does not change.
package attest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// StatementType and PredicateType identify the in-toto payload.
const (
	StatementType        = "https://in-toto.io/Statement/v1"
	DefaultPredicateType = "https://agentprovenance.dev/Evidence/v1"
	dssePayloadType      = "application/vnd.in-toto+json"
)

// Subject is a signed-over artifact identified by its content digest.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"` // e.g. {"sha256": "..."}
}

// Statement is an in-toto v1 statement: what is being attested (subjects) and
// the claim about it (predicate).
type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     any       `json:"predicate,omitempty"`
}

// Envelope is a DSSE envelope carrying a base64 payload and ed25519 signatures.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"` // base64(canonical statement JSON)
	Signatures  []Signature `json:"signatures"`
}

// Signature is one DSSE signature: base64(sig) plus an optional key id.
type Signature struct {
	KeyID string `json:"keyid,omitempty"`
	Sig   string `json:"sig"`
}

// DigestSHA256 returns the hex sha256 of data, the canonical subject digest.
func DigestSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// NewStatement builds an in-toto statement over a single subject digest.
func NewStatement(subjectName, sha256hex string, predicate any) Statement {
	return Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: subjectName, Digest: map[string]string{"sha256": sha256hex}}},
		PredicateType: DefaultPredicateType,
		Predicate:     predicate,
	}
}

// Sign produces a DSSE envelope over the statement. The pre-authentication
// encoding (PAE) follows the DSSE spec so the signature is bound to both the
// payload type and the payload bytes.
func Sign(stmt Statement, key ed25519.PrivateKey, keyID string) (Envelope, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Envelope{}, fmt.Errorf("attest: invalid private key size")
	}
	payload, err := json.Marshal(stmt)
	if err != nil {
		return Envelope{}, fmt.Errorf("attest: marshal statement: %w", err)
	}
	sig := ed25519.Sign(key, pae(dssePayloadType, payload))
	return Envelope{
		PayloadType: dssePayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []Signature{{KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(sig)}},
	}, nil
}

// Verify checks that at least one signature on the envelope is valid for pub and
// returns the decoded statement. It fails closed: any decode error, or no valid
// signature, is an error.
func Verify(env Envelope, pub ed25519.PublicKey) (Statement, error) {
	if len(pub) != ed25519.PublicKeySize {
		return Statement{}, fmt.Errorf("attest: invalid public key size")
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return Statement{}, fmt.Errorf("attest: decode payload: %w", err)
	}
	signed := pae(env.PayloadType, payload)
	ok := false
	for _, s := range env.Signatures {
		raw, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil {
			continue
		}
		if ed25519.Verify(pub, signed, raw) {
			ok = true
			break
		}
	}
	if !ok {
		return Statement{}, fmt.Errorf("attest: no valid signature for key")
	}
	var stmt Statement
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return Statement{}, fmt.Errorf("attest: unmarshal statement: %w", err)
	}
	return stmt, nil
}

// pae is the DSSE Pre-Authentication Encoding:
//
//	"DSSEv1 " + len(type) + " " + type + " " + len(body) + " " + body
func pae(payloadType string, body []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(body), body))
}
