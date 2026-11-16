package derivedview

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"

	"github.com/byteyellow/agentprovenance/internal/attest"
)

func initialResult() Result {
	return Result{
		ManifestStatus: "not_checked", FileIntegrity: IntegrityNotChecked,
		DerivedSignature: SignatureResult{Status: SignatureNotChecked, Cryptographic: IntegrityNotChecked},
		Derivation:       "not_checked", DeclaredCoverage: Coverage{State: CoverageUnknown},
	}
}

// VerifyFS checks a frozen FS without executing its contents. Directory entries
// must expose symlink types and support batched ReadDir. Prefer VerifyDirectory
// for native directories and VerifyZIP for archives: zip.Reader's FS hides some
// unsafe/duplicate raw archive names and must not be passed to this function.
//
// A nil error means verification completed, not that evidence is trusted. Inspect
// FileIntegrity and DerivedSignature separately. Malformed/unsafe inputs, I/O,
// limits and cancellation return an error together with a partial result.
func VerifyFS(ctx context.Context, fsys fs.FS, policy TrustPolicy, limits Limits) (Result, error) {
	r := initialResult()
	l, err := effectiveLimits(limits)
	if err != nil {
		return r, err
	}
	s, err := scanFS(ctx, fsys, l)
	if err != nil {
		return failedInput(r, err)
	}
	return verifyEntries(ctx, s, policy)
}

// VerifyDirectory opens a read-only directory root, refusing a symlink root.
// The directory must remain frozen during verification, as with exported replay
// snapshots. The verifier never extracts the package or modifies its files.
func VerifyDirectory(ctx context.Context, root string, policy TrustPolicy, limits Limits) (Result, error) {
	if err := ctx.Err(); err != nil {
		return initialResult(), err
	}
	fsys, closeRoot, err := openDirectory(root)
	if err != nil {
		return failedInput(initialResult(), err)
	}
	defer closeRoot()
	return VerifyFS(ctx, fsys, policy, limits)
}

func failedInput(r Result, err error) (Result, error) {
	if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		r.FileIntegrity = IntegrityFailed
	}
	return r, err
}

func verifyEntries(ctx context.Context, s *inventory, policy TrustPolicy) (Result, error) {
	r := initialResult()
	manifestEntry, hasManifest := s.entries[ManifestPath]
	signatureEntry, hasSignature := s.entries[SignaturePath]
	r.DerivedSignature.Status = SignatureUnsigned
	if !hasManifest {
		r.ManifestStatus = "missing"
		if hasSignature {
			r.DerivedSignature.Status = SignatureInvalid
			return failedInput(r, fmt.Errorf("%w: signature without manifest", ErrInvalid))
		}
		return r, ctx.Err()
	}
	var raw bytes.Buffer
	if _, err := streamEntry(ctx, manifestEntry, &raw); err != nil {
		return failedInput(r, err)
	}
	m, err := parseManifest(raw.Bytes())
	if err != nil {
		r.ManifestStatus = "invalid"
		if hasSignature {
			r.DerivedSignature.Status = SignatureInvalid
		}
		return failedInput(r, err)
	}
	r.ManifestStatus, r.Manifest, r.DeclaredCoverage = "present", &m, m.Coverage
	for _, source := range m.Sources {
		status := SignatureUnsigned
		if source.Signature != nil {
			status = SignatureNotChecked
		}
		r.SourceSignatures = append(r.SourceSignatures, SourceResult{SourceID: source.ID, Status: status})
	}
	if len(m.Files) > s.paths.limits.MaxEntries {
		return failedInput(r, fmt.Errorf("%w: manifest file count", ErrLimit))
	}
	if hasSignature {
		var signature bytes.Buffer
		if _, err := streamEntry(ctx, signatureEntry, &signature); err != nil {
			r.DerivedSignature.Status = SignatureInvalid
			return failedInput(r, err)
		}
		r.DerivedSignature = verifySignature(m, raw.Bytes(), signature.Bytes(), policy)
	}
	seen := make(map[string]bool, len(m.Files))
	var declaredBytes int64
	for _, file := range m.Files {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		if file.Bytes > s.paths.limits.MaxFileBytes || file.Bytes > s.paths.limits.MaxTotalBytes-declaredBytes {
			return failedInput(r, fmt.Errorf("%w: declared payload bytes", ErrLimit))
		}
		declaredBytes += file.Bytes
		seen[file.Path] = true
		e, found := s.entries[file.Path]
		if !found {
			r.Issues = append(r.Issues, Issue{Code: "missing_file", Path: file.Path})
			continue
		}
		if e.size != file.Bytes {
			r.Issues = append(r.Issues, Issue{Code: "length_mismatch", Path: file.Path})
			continue
		}
		digest, err := streamEntry(ctx, e, nil)
		if err != nil {
			return failedInput(r, fmt.Errorf("read %q: %w", file.Path, err))
		}
		if digest != file.SHA256 {
			r.Issues = append(r.Issues, Issue{Code: "digest_mismatch", Path: file.Path})
		}
	}
	for _, name := range sortedNames(s.entries) {
		if !seen[name] && name != ManifestPath && name != SignaturePath {
			r.Issues = append(r.Issues, Issue{Code: "extra_file", Path: name})
		}
	}
	if err := ctx.Err(); err != nil {
		return r, err
	}
	r.FileIntegrity = IntegrityPassed
	if len(r.Issues) != 0 {
		r.FileIntegrity = IntegrityFailed
	}
	return r, nil
}

func verifySignature(m Manifest, manifest, raw []byte, policy TrustPolicy) SignatureResult {
	r := SignatureResult{
		Status: SignatureInvalid, Cryptographic: IntegrityNotChecked,
		KeyID: m.Exporter.KeyID, Role: m.Exporter.Role,
	}
	invalid := func(reason string) SignatureResult {
		r.Status, r.Reason = SignatureInvalid, reason
		return r
	}
	var env attest.Envelope
	if err := decodeStrict(raw, &env); err != nil {
		return invalid(err.Error())
	}
	// Strict canonical metadata rejects case-insensitive struct aliases, unknown
	// fields, alternate base64 encodings and ambiguous JSON spellings uniformly.
	canonical, err := json.Marshal(env)
	if err != nil || !bytes.Equal(canonical, raw) {
		return invalid("noncanonical signature envelope")
	}
	if env.PayloadType != "application/vnd.in-toto+json" || len(env.Signatures) != 1 || env.Signatures[0].KeyID != m.Exporter.KeyID {
		return invalid("unexpected DSSE type, signature count or key ID")
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(env.Payload)
	if err != nil || base64.StdEncoding.EncodeToString(payload) != env.Payload {
		return invalid("invalid DSSE payload encoding")
	}
	want, err := json.Marshal(statement(m.Exporter, manifest))
	if err != nil || !bytes.Equal(payload, want) {
		return invalid("DSSE statement does not bind this manifest and exporter")
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(env.Signatures[0].Sig)
	if err != nil || len(sig) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(sig) != env.Signatures[0].Sig {
		return invalid("invalid signature encoding")
	}
	trustedKey, known := policy.Keys[m.Exporter.KeyID]
	var pub ed25519.PublicKey
	if known {
		pub = trustedKey.PublicKey
		if len(pub) != ed25519.PublicKeySize {
			return invalid("invalid external policy key")
		}
	} else if m.Exporter.PublicKey != "" {
		pub, _ = base64.StdEncoding.Strict().DecodeString(m.Exporter.PublicKey)
	}
	if len(pub) == 0 {
		r.Status, r.Reason = SignatureUnknownKey, "no public key available"
		return r
	}
	if _, err := attest.Verify(env, pub); err != nil {
		r.Cryptographic = IntegrityFailed
		return invalid("Ed25519 signature verification failed")
	}
	r.Cryptographic = IntegrityPassed
	if known && m.Exporter.PublicKey != "" && m.Exporter.PublicKey != base64.StdEncoding.EncodeToString(pub) {
		return invalid("package key differs from external policy key")
	}
	if !known {
		r.Status, r.Reason = SignatureUnknownKey, "signer is not in the external trust policy"
		return r
	}
	for _, role := range trustedKey.Roles {
		if role == RoleExporter {
			r.Status, r.Trusted = SignatureValid, true
			return r
		}
	}
	r.Status, r.Reason = SignatureUntrustedRole, "external policy does not authorize the exporter role"
	return r
}
