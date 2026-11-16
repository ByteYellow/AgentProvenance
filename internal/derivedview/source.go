package derivedview

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/byteyellow/agentprovenance/internal/attest"
)

const maxSourceSignatures = 16

type sourceRead struct {
	digest string
	err    error
}

type sourceAttestation struct {
	signature     SignatureResult
	subjectDigest string
}

type sourceVerification struct {
	results []SourceResult
	reads   map[string]sourceRead
	err     error
}

func verifySources(ctx context.Context, sources []Source, inventory *inventory, policy TrustPolicy) sourceVerification {
	v := sourceVerification{reads: map[string]sourceRead{}}
	if len(sources) > inventory.paths.limits.MaxEntries {
		v.err = fmt.Errorf("%w: source count", ErrLimit)
		return v
	}
	for _, source := range sources {
		r := SourceResult{SourceID: source.ID, Status: SignatureNotChecked, Cryptographic: IntegrityNotChecked}
		if source.Signature == nil && source.Digest.Path != "" {
			r.Status = SignatureUnsigned
		}
		if source.Kind == KindForensicsBundle {
			r.Role = RoleProducer
		}
		v.results = append(v.results, r)
	}
	keyIDs := make([]string, 0, len(policy.Keys))
	for id := range policy.Keys {
		keyIDs = append(keyIDs, id)
	}
	sort.Strings(keyIDs)
	attestations := map[string]sourceAttestation{}
	for i, source := range sources {
		if err := ctx.Err(); err != nil {
			v.err = err
			return v
		}
		r := &v.results[i]
		if source.Signature == nil || source.Kind != KindForensicsBundle {
			continue
		}
		if source.Digest.Path == "" || source.Signature.Path == "" {
			r.Reason = "source bundle or attestation is a commitment without delivered bytes"
			continue
		}
		bundle, hasBundle := inventory.entries[source.Digest.Path]
		signature, hasSignature := inventory.entries[source.Signature.Path]
		if !hasBundle || !hasSignature {
			r.Status, r.Reason = SignatureInvalid, "referenced source bundle or attestation is missing"
			continue
		}
		attestation, found := attestations[signature.name]
		if !found {
			var raw bytes.Buffer
			var read sourceRead
			if signature.size > inventory.paths.limits.MaxSignatureBytes {
				read.err = fmt.Errorf("%w: original DSSE envelope %q", ErrLimit, signature.name)
			} else {
				read.digest, read.err = streamEntry(ctx, signature, &raw)
			}
			v.reads[signature.name] = read
			if read.err != nil {
				attestation.signature = SignatureResult{Status: SignatureInvalid, Cryptographic: IntegrityNotChecked, Role: RoleProducer, Reason: "source attestation could not be read within limits"}
				if v.err == nil {
					v.err = read.err
				}
			} else {
				var err error
				attestation, err = verifySourceEnvelope(ctx, raw.Bytes(), policy, keyIDs)
				if err != nil {
					v.err = err
					return v
				}
			}
			attestations[signature.name] = attestation
		}
		r.Status, r.Cryptographic, r.Trusted = attestation.signature.Status, attestation.signature.Cryptographic, attestation.signature.Trusted
		r.KeyID, r.Reason = attestation.signature.KeyID, attestation.signature.Reason
		if attestation.subjectDigest == "" {
			continue
		}
		read, found := v.reads[bundle.name]
		if !found {
			read.digest, read.err = streamEntry(ctx, bundle, nil)
			v.reads[bundle.name] = read
			if read.err != nil && v.err == nil {
				v.err = read.err
			}
		}
		if read.err != nil {
			r.Status, r.Trusted, r.Reason = SignatureInvalid, false, "source bundle could not be read within limits"
		} else if read.digest != attestation.subjectDigest {
			r.Status, r.Trusted, r.Reason = SignatureInvalid, false, "first subject SHA256 does not match delivered source bytes"
		}
		// Source reference hashes are checked by the outer file inventory. A
		// reformatted envelope or a different genuine original can retain a valid
		// original signature while failing the exporter's inventory commitment.
	}
	return v
}

func verifySourceEnvelope(ctx context.Context, raw []byte, policy TrustPolicy, keyIDs []string) (sourceAttestation, error) {
	a := sourceAttestation{signature: SignatureResult{Status: SignatureInvalid, Cryptographic: IntegrityNotChecked, Role: RoleProducer}}
	invalid := func(reason string) (sourceAttestation, error) {
		a.signature.Reason = reason
		return a, nil
	}
	var env attest.Envelope
	if err := decodeStrict(raw, &env); err != nil {
		return invalid("invalid original DSSE JSON")
	}
	envelopeFields, err := sourceFields(raw, "payloadType", "payload", "signatures")
	if err != nil {
		return invalid("unexpected original DSSE members")
	}
	if env.PayloadType != "application/vnd.in-toto+json" || len(env.Signatures) == 0 || len(env.Signatures) > maxSourceSignatures {
		return invalid("unexpected original DSSE type or signature count")
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(env.Payload)
	if err != nil || base64.StdEncoding.EncodeToString(payload) != env.Payload {
		return invalid("invalid original DSSE payload encoding")
	}
	var stmt struct {
		Type          string           `json:"_type"`
		Subject       []attest.Subject `json:"subject"`
		PredicateType string           `json:"predicateType"`
		Predicate     json.RawMessage  `json:"predicate"`
	}
	if err := decodeStrict(payload, &stmt); err != nil {
		return invalid("invalid original in-toto JSON")
	}
	fields, err := sourceFields(payload, "_type", "subject", "predicateType", "predicate")
	if err != nil || stmt.Type != attest.StatementType || stmt.PredicateType != attest.DefaultPredicateType || len(stmt.Subject) == 0 {
		return invalid("unexpected original in-toto type, predicate type or subjects")
	}
	var subjectJSON []json.RawMessage
	if err := json.Unmarshal(fields["subject"], &subjectJSON); err != nil {
		return invalid("invalid original subjects")
	}
	for _, subject := range subjectJSON {
		if _, err := sourceFields(subject, "name", "digest"); err != nil {
			return invalid("unexpected original subject members")
		}
	}
	var predicate map[string]json.RawMessage
	if err := json.Unmarshal(stmt.Predicate, &predicate); err != nil {
		return invalid("original predicate must be an object")
	}
	for key := range predicate {
		if (strings.EqualFold(key, "run_id") && key != "run_id") || (strings.EqualFold(key, "kind") && key != "kind") {
			return invalid("ambiguous original predicate member")
		}
	}
	var runID, kind string
	if json.Unmarshal(predicate["run_id"], &runID) != nil || json.Unmarshal(predicate["kind"], &kind) != nil ||
		runID == "" || strings.ContainsRune(runID, utf8.RuneError) || kind != KindForensicsBundle || stmt.Subject[0].Name != "forensics/"+runID {
		return invalid("original subject name and forensics predicate do not match")
	}
	digest := stmt.Subject[0].Digest["sha256"]
	if !validDigest(digest) {
		return invalid("first original subject requires a SHA256 digest")
	}
	for key := range stmt.Subject[0].Digest {
		if strings.EqualFold(key, "sha256") && key != "sha256" {
			return invalid("ambiguous original subject digest")
		}
	}
	// Forensics exports pretty-print envelopes. Accept insignificant whitespace
	// and member order without reserializing the signed payload or weakening
	// duplicate-key and exact field-name validation.
	var signatureJSON []json.RawMessage
	if err := json.Unmarshal(envelopeFields["signatures"], &signatureJSON); err != nil || len(signatureJSON) != len(env.Signatures) {
		return invalid("invalid original signatures")
	}
	for i, signature := range env.Signatures {
		if _, err := sourceFields(signatureJSON[i], "keyid", "sig"); err != nil || len(signature.KeyID) > 256 || strings.ContainsRune(signature.KeyID, utf8.RuneError) {
			return invalid("invalid original signature members or key ID")
		}
		sig, err := base64.StdEncoding.Strict().DecodeString(signature.Sig)
		if err != nil || len(sig) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(sig) != signature.Sig {
			return invalid("invalid original signature encoding")
		}
	}
	a.subjectDigest = digest
	for _, signature := range env.Signatures {
		candidates := []string{signature.KeyID}
		if signature.KeyID == "" {
			candidates = keyIDs
		}
		candidate := SignatureResult{Status: SignatureUnknownKey, Cryptographic: IntegrityNotChecked, Role: RoleProducer, KeyID: signature.KeyID, Reason: "no matching external source key"}
		one := env
		one.Signatures = []attest.Signature{signature}
		for _, id := range candidates {
			if err := ctx.Err(); err != nil {
				return a, err
			}
			key, known := policy.Keys[id]
			if !known {
				continue
			}
			checked := SignatureResult{Status: SignatureInvalid, Cryptographic: IntegrityNotChecked, Role: RoleProducer, KeyID: id, Reason: "invalid external source public key"}
			if len(key.PublicKey) == ed25519.PublicKeySize {
				if _, err := attest.Verify(one, key.PublicKey); err != nil {
					checked.Cryptographic, checked.Reason = IntegrityFailed, "original Ed25519 signature verification failed"
				} else {
					checked.Status, checked.Cryptographic, checked.Reason = SignatureUntrustedRole, IntegrityPassed, "external policy does not authorize the producer role"
					for _, role := range key.Roles {
						if role == RoleProducer {
							checked.Status, checked.Trusted, checked.Reason = SignatureValid, true, ""
							return sourceAttestation{signature: checked, subjectDigest: digest}, nil
						}
					}
				}
			}
			if signature.KeyID == "" && checked.Status == SignatureInvalid {
				// Without a claimed key ID, failure against an unrelated external
				// key leaves the signer unknown rather than identifying a bad key.
				continue
			}
			if candidate.Status == SignatureUnknownKey || sourceSignatureRank(checked.Status) > sourceSignatureRank(candidate.Status) {
				candidate = checked
			}
		}
		if a.signature.Reason == "" || sourceSignatureRank(candidate.Status) > sourceSignatureRank(a.signature.Status) {
			a.signature = candidate
		}
	}
	return a, ctx.Err()
}

func sourceSignatureRank(status SignatureStatus) int {
	switch status {
	case SignatureValid:
		return 4
	case SignatureUntrustedRole:
		return 3
	case SignatureUnknownKey:
		return 2
	default:
		return 1
	}
}

// Call only after decodeStrict has rejected duplicate keys throughout the input.
func sourceFields(raw []byte, allowed ...string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	for name := range fields {
		found := false
		for _, key := range allowed {
			found = found || name == key
		}
		if !found {
			return nil, fmt.Errorf("unexpected JSON member")
		}
	}
	return fields, nil
}
