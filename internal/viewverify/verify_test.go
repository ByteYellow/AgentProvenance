package viewverify

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/derivedview"
)

func readerFixture(t *testing.T) (string, string, PolicyFile) {
	t.Helper()
	root, external := t.TempDir(), t.TempDir()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	html := []byte("<!doctype html><title>Recorded evidence</title><p>Read only</p>")
	m := derivedview.Manifest{
		Sources:    []derivedview.Source{{ID: "fixture", Kind: "saved_evidence", Digest: derivedview.Reference{SHA256: attest.DigestSHA256([]byte("source"))}}},
		Selection:  derivedview.Reference{SHA256: attest.DigestSHA256([]byte("selection"))},
		Projection: derivedview.Rules{Version: "fixture/v1", SHA256: attest.DigestSHA256([]byte("rules")), ImplementationSHA256: attest.DigestSHA256([]byte("implementation"))},
		Coverage:   derivedview.Coverage{State: derivedview.CoverageUnknown},
		Files:      []derivedview.File{{Path: "index.html", SHA256: attest.DigestSHA256(html), Bytes: int64(len(html))}},
		Exporter:   derivedview.Exporter{ID: "fixture-exporter"}, CreatedAt: "2026-11-16T00:00:00Z",
	}
	manifest, signature, err := derivedview.Sign(m, key)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{"index.html": html, derivedview.ManifestPath: manifest, derivedview.SignaturePath: signature} {
		if err := os.WriteFile(filepath.Join(root, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	policy := PolicyFile{SchemaVersion: PolicySchema, ID: "recipient-policy", Keys: []PolicyKey{{KeyID: attest.KeyID(pub), PublicKeyHex: hex.EncodeToString(pub), Roles: []string{"exporter"}}}}
	path := filepath.Join(external, "trust.json")
	writePolicy(t, path, policy)
	return root, path, policy
}

func writePolicy(t *testing.T, path string, policy PolicyFile) {
	t.Helper()
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func verifyResult(t *testing.T, path, policy string, want int) derivedview.Result {
	t.Helper()
	var out bytes.Buffer
	code, err := Verify(context.Background(), path, policy, &out)
	if code != want || (want == 0) != (err == nil) {
		t.Fatalf("code=%d err=%v want=%d", code, err, want)
	}
	var result derivedview.Result
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("invalid report: %v (%s)", err, out.Bytes())
	}
	return result
}

func TestRecipientTrustAndCoverageAreIndependent(t *testing.T) {
	root, path, policy := readerFixture(t)
	r := verifyResult(t, root, path, 0)
	if r.DeclaredCoverage.State != derivedview.CoverageUnknown || r.DerivedSignature.Status != derivedview.SignatureValid {
		t.Fatalf("signature changed capture coverage: %+v", r)
	}
	r = verifyResult(t, root, "", 2)
	if r.DerivedSignature.Status != derivedview.SignatureUnknownKey || r.DerivedSignature.Cryptographic != derivedview.IntegrityPassed {
		t.Fatalf("embedded key became trusted: %+v", r)
	}
	policy.Keys[0].Roles = []string{"producer"}
	writePolicy(t, path, policy)
	r = verifyResult(t, root, path, 2)
	if r.DerivedSignature.Status != derivedview.SignatureUntrustedRole {
		t.Fatalf("producer key became exporter authority: %+v", r)
	}
}

func TestVerifierDoesNotLoadPackagePolicy(t *testing.T) {
	root, _, policy := readerFixture(t)
	inside := filepath.Join(root, "policy.json")
	writePolicy(t, inside, policy)
	var out bytes.Buffer
	code, err := Verify(context.Background(), root, inside, &out)
	if code != 3 || err == nil || out.Len() != 0 {
		t.Fatalf("package policy accepted: code=%d err=%v", code, err)
	}
	r := verifyResult(t, root, "", 1)
	if r.DerivedSignature.Trusted || r.FileIntegrity != derivedview.IntegrityFailed {
		t.Fatalf("extra policy trusted or ignored: %+v", r)
	}
}

func TestVerifierZIPAndDirectoryAgreeAndDetectTampering(t *testing.T) {
	root, path, _ := readerFixture(t)
	archive := filepath.Join(t.TempDir(), "reader.zip")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for _, name := range []string{"index.html", derivedview.ManifestPath, derivedview.SignaturePath} {
		raw, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		entry, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	a := verifyResult(t, root, path, 0)
	b := verifyResult(t, archive, path, 0)
	if a.DerivedSignature != b.DerivedSignature || a.FileIntegrity != b.FileIntegrity {
		t.Fatalf("ZIP differs from directory: %+v %+v", a, b)
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	verifyResult(t, root, path, 1)
}

func TestVerifierHistoricalUnsignedAndInvalidPolicies(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("old reader"), 0600); err != nil {
		t.Fatal(err)
	}
	r := verifyResult(t, root, "", 2)
	if r.ManifestStatus != "missing" || r.DerivedSignature.Status != derivedview.SignatureUnsigned {
		t.Fatalf("historical reader upgraded: %+v", r)
	}
	_, path, policy := readerFixture(t)
	for _, test := range []string{"duplicate", "id", "role", "empty"} {
		t.Run(test, func(t *testing.T) {
			p := policy
			p.Keys = append([]PolicyKey(nil), policy.Keys...)
			switch test {
			case "duplicate":
				p.Keys = append(p.Keys, p.Keys[0])
			case "id":
				p.Keys[0].KeyID = "wrong"
			case "role":
				p.Keys[0].Roles = []string{"administrator"}
			case "empty":
				p.Keys[0].Roles = nil
			}
			writePolicy(t, path, p)
			if _, err := ReadPolicy(path); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
}
