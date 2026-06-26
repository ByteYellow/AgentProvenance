package attest

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSignVerifyRoundtrip(t *testing.T) {
	pub, priv, keyID, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	digest := DigestSHA256([]byte("forensics-bundle-bytes"))
	stmt := NewStatement("forensics/run-1", digest, map[string]any{"run_id": "run-1", "kind": "forensics_bundle"})

	env, err := Sign(stmt, priv, keyID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(env, pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(got.Subject) != 1 || got.Subject[0].Digest["sha256"] != digest {
		t.Fatalf("subject digest not preserved: %+v", got.Subject)
	}
	if got.Type != StatementType {
		t.Fatalf("type = %q", got.Type)
	}
}

// TestVerifyDetectsPayloadTamper is the whole point: an attacker who rewrites
// the attested content (here, the subject digest) post-signing must fail
// verification.
func TestVerifyDetectsPayloadTamper(t *testing.T) {
	pub, priv, keyID, _ := GenerateKey()
	stmt := NewStatement("evidence/run-1", DigestSHA256([]byte("original")), nil)
	env, err := Sign(stmt, priv, keyID)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper: swap the payload for a statement over a different digest, keeping
	// the original signature.
	tampered := NewStatement("evidence/run-1", DigestSHA256([]byte("rewritten-by-attacker")), nil)
	raw, _ := json.Marshal(tampered)
	env.Payload = base64.StdEncoding.EncodeToString(raw)

	if _, err := Verify(env, pub); err == nil {
		t.Fatal("verify accepted a tampered payload - tamper-evidence broken")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	_, priv, keyID, _ := GenerateKey()
	otherPub, _, _, _ := GenerateKey()
	env, err := Sign(NewStatement("x", DigestSHA256([]byte("y")), nil), priv, keyID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(env, otherPub); err == nil {
		t.Fatal("verify accepted a signature from the wrong key")
	}
}

func TestLoadPrivateKeyHexSeedAndFull(t *testing.T) {
	pub, priv, _, _ := GenerateKey()
	dir := t.TempDir()

	seedPath := filepath.Join(dir, "seed.hex")
	if err := os.WriteFile(seedPath, []byte(hex.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPrivateKeyHex(seedPath)
	if err != nil {
		t.Fatalf("load seed: %v", err)
	}
	// A signature from the loaded key must verify against the original public key.
	env, _ := Sign(NewStatement("x", DigestSHA256([]byte("z")), nil), loaded, "")
	if _, err := Verify(env, pub); err != nil {
		t.Fatalf("loaded seed key did not round-trip: %v", err)
	}

	fullPath := filepath.Join(dir, "full.hex")
	if err := os.WriteFile(fullPath, []byte(hex.EncodeToString(priv)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKeyHex(fullPath); err != nil {
		t.Fatalf("load full key: %v", err)
	}

	badPath := filepath.Join(dir, "bad.hex")
	if err := os.WriteFile(badPath, []byte("abcd"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKeyHex(badPath); err == nil {
		t.Fatal("expected error for wrong-length key")
	}
}
