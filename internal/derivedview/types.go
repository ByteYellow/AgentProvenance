// Package derivedview signs and independently verifies frozen reader payloads.
// It does not export, extract, execute, fetch, or recompute evidence. Callers
// supply their existing inventory and write the returned metadata themselves.
package derivedview

import (
	"crypto/ed25519"
	"errors"
)

const (
	SchemaVersion = "https://agentprovenance.dev/DerivedView/v1"
	ManifestPath  = "manifest.json"
	SignaturePath = "manifest.signature"
	RoleExporter  = "exporter"
	RoleProducer  = "producer"

	KindForensicsBundle = "forensics_bundle"
)

// File matches the path/length/hash representation used by ReplayFile.
type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// Reference may name a private commitment rather than a delivered file. A Path,
// when supplied, must resolve to an exact member of Files. No URL is fetched.
type Reference struct {
	SHA256 string `json:"sha256"`
	Path   string `json:"path,omitempty"`
}

// KindForensicsBundle references unchanged original JSON and its DSSE envelope.
// Hash-only references remain commitments, with no original verification.
type Source struct {
	ID            string     `json:"id"`
	Kind          string     `json:"kind"`
	Digest        Reference  `json:"digest"`
	Signature     *Reference `json:"signature,omitempty"`
	TrustPolicyID string     `json:"trust_policy_id,omitempty"`
}

type Rules struct {
	Version              string `json:"version"`
	SHA256               string `json:"sha256"`
	ImplementationSHA256 string `json:"implementation_sha256"`
}

// PublicKey is optional base64 Ed25519 key material, never a trust anchor.
type Exporter struct {
	ID        string `json:"id"`
	KeyID     string `json:"key_id"`
	Role      string `json:"role"`
	PublicKey string `json:"public_key,omitempty"`
}

type Gap struct {
	Category string `json:"category"`
	Count    int64  `json:"count"`
	Reason   string `json:"reason"`
}

type Capability struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

type CoverageState string

const (
	CoverageComplete CoverageState = "complete_within_declared_scope"
	CoverageGaps     CoverageState = "gaps"
	CoverageUnknown  CoverageState = "unknown"
)

// Coverage is the exporter's signed claim, not a measurement by this verifier.
type Coverage struct {
	State        CoverageState `json:"state"`
	Scope        string        `json:"scope,omitempty"`
	Gaps         []Gap         `json:"gaps,omitempty"`
	Capabilities []Capability  `json:"capabilities,omitempty"`
}

// Manifest is the versioned DerivedView/v1 assertion. CreatedAt is an ordinary
// RFC3339 timestamp, not a trusted timestamp. Exclusions contain only categories,
// counts and privacy-reviewed reasons, never implicit original attachments.
type Manifest struct {
	SchemaVersion       string     `json:"schema_version"`
	Sources             []Source   `json:"sources"`
	Selection           Reference  `json:"selection"`
	Projection          Rules      `json:"projection"`
	IncludedRecords     *Reference `json:"included_records,omitempty"`
	IncludedAttachments *Reference `json:"included_attachments,omitempty"`
	Exclusions          []Gap      `json:"exclusions,omitempty"`
	Coverage            Coverage   `json:"coverage"`
	Files               []File     `json:"files"`
	FilesSHA256         string     `json:"files_sha256"`
	Exporter            Exporter   `json:"exporter"`
	CreatedAt           string     `json:"created_at"`
	TrustPolicyID       string     `json:"trust_policy_id,omitempty"`
}

// TrustPolicy must come from the recipient, independently of the package. An
// empty policy trusts nobody. Derived signatures require RoleExporter; original
// source signatures require RoleProducer. An empty source signature key ID may
// be resolved by verifying against these externally configured keys only.
// ID is descriptive; a matching package policy ID never grants trust.
type TrustPolicy struct {
	ID   string
	Keys map[string]TrustedKey
}

type TrustedKey struct {
	PublicKey ed25519.PublicKey
	Roles     []string
}

type IntegrityStatus string

const (
	IntegrityPassed     IntegrityStatus = "passed"
	IntegrityFailed     IntegrityStatus = "failed"
	IntegrityNotChecked IntegrityStatus = "not_checked"
)

type SignatureStatus string

const (
	SignatureValid         SignatureStatus = "valid"
	SignatureUnknownKey    SignatureStatus = "unknown_key"
	SignatureUntrustedRole SignatureStatus = "untrusted_role"
	SignatureInvalid       SignatureStatus = "invalid"
	SignatureUnsigned      SignatureStatus = "unsigned"
	SignatureNotChecked    SignatureStatus = "not_checked"
)

type SignatureResult struct {
	Status        SignatureStatus `json:"status"`
	Cryptographic IntegrityStatus `json:"cryptographic"`
	Trusted       bool            `json:"trusted"`
	KeyID         string          `json:"key_id,omitempty"`
	Role          string          `json:"role,omitempty"`
	Reason        string          `json:"reason,omitempty"`
}

// SourceResult reports the original separately from the exporter's inventory.
// Cryptographic may pass while Status is invalid if the first signed subject
// does not match the delivered original. Trusted requires both that binding and
// an externally authorized producer. Undelivered commitments are not_checked;
// delivered originals with no signature reference are unsigned.
type SourceResult struct {
	SourceID      string          `json:"source_id"`
	Status        SignatureStatus `json:"status"`
	Cryptographic IntegrityStatus `json:"cryptographic"`
	Trusted       bool            `json:"trusted"`
	// KeyID is the matching external key ID for legacy envelopes with no keyid.
	KeyID  string `json:"key_id,omitempty"`
	Role   string `json:"role,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type Issue struct {
	Code string `json:"code"`
	Path string `json:"path,omitempty"`
}

type Result struct {
	ManifestStatus   string          `json:"manifest_status"` // present, missing, invalid, not_checked
	Manifest         *Manifest       `json:"manifest,omitempty"`
	FileIntegrity    IntegrityStatus `json:"file_integrity"`
	DerivedSignature SignatureResult `json:"derived_signature"`
	SourceSignatures []SourceResult  `json:"source_signatures,omitempty"`
	Derivation       string          `json:"derivation"` // always not_checked
	DeclaredCoverage Coverage        `json:"declared_coverage"`
	Issues           []Issue         `json:"issues,omitempty"`
}

// Limits bound both metadata and streamed payload processing. Zero fields use
// DefaultLimits; negative values are errors. MaxEntries includes directories
// (including implicit ZIP parents) and the two reserved metadata files. Byte
// totals include metadata, not ZIP headers. MaxSignatureBytes also caps each
// delivered original DSSE envelope before decoding; original JSON is streamed
// under the ordinary file and total byte limits, without decompression.
type Limits struct {
	MaxEntries          int
	MaxFileBytes        int64
	MaxTotalBytes       int64
	MaxManifestBytes    int64
	MaxSignatureBytes   int64
	MaxZIPBytes         int64
	MaxZIPMetadataBytes int64
	MaxPathBytes        int
	MaxPathDepth        int
}

func DefaultLimits() Limits {
	return Limits{
		MaxEntries: 20000, MaxFileBytes: 1280 << 20, MaxTotalBytes: 1536 << 20,
		MaxManifestBytes: 8 << 20, MaxSignatureBytes: 64 << 10,
		MaxZIPBytes: 2 << 30, MaxZIPMetadataBytes: 16 << 20,
		MaxPathBytes: 1024, MaxPathDepth: 32,
	}
}

var (
	ErrLimit   = errors.New("derivedview: resource limit exceeded")
	ErrUnsafe  = errors.New("derivedview: unsafe package entry")
	ErrInvalid = errors.New("derivedview: invalid metadata")
)
