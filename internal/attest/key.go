package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// GenerateKey returns a fresh ed25519 keypair and its key id (a short hash of
// the public key), for tests and bootstrap.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, "", fmt.Errorf("attest: generate key: %w", err)
	}
	return pub, priv, KeyID(pub), nil
}

// KeyID is a stable short identifier for a public key (first 16 hex of its
// sha256), used to tag signatures so a verifier can select the right key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:16]
}

// LoadPublicKeyHex loads a hex-encoded ed25519 public key from path.
func LoadPublicKeyHex(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("attest: read public key: %w", err)
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("attest: decode public key hex: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("attest: public key must be %d bytes, got %d", ed25519.PublicKeySize, len(decoded))
	}
	return ed25519.PublicKey(decoded), nil
}

// LoadPrivateKeyHex loads a hex-encoded ed25519 private key (seed or full key)
// from path. A 32-byte value is treated as a seed; a 64-byte value as the full
// private key. This keeps the on-disk format trivial; a TPM/KMS-backed signer
// would implement the same Sign call without changing the wire format.
func LoadPrivateKeyHex(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("attest: read key: %w", err)
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("attest: decode key hex: %w", err)
	}
	switch len(decoded) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(decoded), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(decoded), nil
	default:
		return nil, fmt.Errorf("attest: key must be %d-byte seed or %d-byte private key, got %d", ed25519.SeedSize, ed25519.PrivateKeySize, len(decoded))
	}
}
