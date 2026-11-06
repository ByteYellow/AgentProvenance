package cli

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"github.com/byteyellow/agentprovenance/internal/attest"
)

// writeForensicsImportBundle writes a minimal self-contained forensics bundle
// and, when priv is non-nil, a DSSE attestation next to it over the exact
// bundle bytes (the same <bundle>.dsse.json layout the export command uses).
func writeForensicsImportBundle(t *testing.T, dir string, priv ed25519.PrivateKey) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"run_id":         "t-import-run",
		"schema_version": "agentprovenance.forensics_export/v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if priv == nil {
		return bundlePath
	}
	stmt := attest.NewStatement("forensics/t-import-run", attest.DigestSHA256(raw), map[string]any{
		"run_id": "t-import-run",
		"kind":   "forensics_bundle",
	})
	env, err := attest.Sign(stmt, priv, attest.KeyID(priv.Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	envRaw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bundle.dsse.json"), envRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	return bundlePath
}

func writeForensicsPubKey(t *testing.T, dir string, pub ed25519.PublicKey) string {
	t.Helper()
	path := filepath.Join(dir, "pub.key")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(pub)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func runForensicsImport(t *testing.T, dataDir string, extraArgs ...string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	root := NewRootCommand()
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(append([]string{"--data-dir", dataDir, "forensics", "import"}, extraArgs...))
	err := root.Execute()
	return stdout.String(), stderr.String(), err
}

// M10: the default import path must fail closed — no key, no import.
func TestForensicsImportFailsClosedWithoutPubKey(t *testing.T) {
	dir := t.TempDir()
	bundle := writeForensicsImportBundle(t, dir, nil)
	stdout, stderr, err := runForensicsImport(t, filepath.Join(dir, "store"), bundle)
	if err == nil {
		t.Fatalf("import without --pub-key must be refused; stdout=%s", stdout)
	}
	msg := err.Error() + stderr
	for _, want := range []string{"refusing", "--pub-key", "--allow-unverified"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("refusal error missing %q: %v (%s)", want, err, stderr)
		}
	}
	if strings.Contains(stdout, "imported run=") {
		t.Fatalf("unverified bundle was imported anyway: %s", stdout)
	}
}

// M10: --allow-unverified is the explicit escape hatch: it imports, but loudly.
func TestForensicsImportAllowUnverifiedWarnsAndMarksUnverified(t *testing.T) {
	dir := t.TempDir()
	bundle := writeForensicsImportBundle(t, dir, nil)
	stdout, stderr, err := runForensicsImport(t, filepath.Join(dir, "store"), bundle, "--allow-unverified")
	if err != nil {
		t.Fatalf("explicit unverified import failed: %v (%s)", err, stderr)
	}
	if !strings.Contains(stdout, "imported run=t-import-run") || !strings.Contains(stdout, "attestation=unverified") {
		t.Fatalf("output must mark the import unverified: %s", stdout)
	}
	if !strings.Contains(stderr, "WARNING") || !strings.Contains(stderr, "WITHOUT signature verification") {
		t.Fatalf("missing loud unverified warning on stderr: %s", stderr)
	}

	// JSON mode carries the same attestation verdict.
	var out bytes.Buffer
	root := NewRootCommand()
	root.SetOut(&out)
	root.SetArgs([]string{"--data-dir", filepath.Join(dir, "store-json"), "forensics", "import", "--json", "--allow-unverified", bundle})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	var got struct {
		RunID               string `json:"run_id"`
		AttestationVerified bool   `json:"attestation_verified"`
		AttestationStatus   string `json:"attestation_status"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("invalid import JSON: %s (%v)", out.String(), err)
	}
	if got.RunID != "t-import-run" || got.AttestationVerified || got.AttestationStatus != "unverified" {
		t.Fatalf("JSON must mark import unverified: %+v", got)
	}
}

func TestForensicsImportDiagnosticLanguage(t *testing.T) {
	for _, locale := range []string{"en", "zh-CN"} {
		for _, jsonMode := range []bool{false, true} {
			for _, mode := range []string{"refused", "unverified", "wrong-key", "key-precedence"} {
				t.Run(fmt.Sprintf("%s/json=%t/%s", locale, jsonMode, mode), func(t *testing.T) {
					dir := t.TempDir()
					pub, priv, _, err := attest.GenerateKey()
					if err != nil {
						t.Fatal(err)
					}
					bundle := writeForensicsImportBundle(t, dir, priv)
					args := []string{"--data-dir", filepath.Join(dir, "store"), "--lang", locale, "forensics", "import", bundle}
					if jsonMode {
						args = append(args, "--json")
					}
					switch mode {
					case "unverified":
						args = append(args, "--allow-unverified")
					case "wrong-key", "key-precedence":
						if mode == "wrong-key" {
							pub, _, _, err = attest.GenerateKey()
							if err != nil {
								t.Fatal(err)
							}
						}
						args = append(args, "--pub-key", writeForensicsPubKey(t, dir, pub), "--allow-unverified")
					}
					root := NewRootCommand()
					var stdout, stderr bytes.Buffer
					root.SetOut(&stdout)
					root.SetErr(&stderr)
					root.SetArgs(args)
					err = root.Execute()
					failed := mode == "refused" || mode == "wrong-key"
					if (err != nil) != failed {
						t.Fatalf("mode=%s error=%v", mode, err)
					}
					if failed && stdout.Len() != 0 {
						t.Fatalf("refused import emitted stdout: %s", stdout.String())
					}
					diagnostic := stderr.String() + ErrorText(root, err)
					hasChinese := strings.ContainsFunc(diagnostic, func(r rune) bool { return unicode.Is(unicode.Han, r) })
					wantChinese := locale == "zh-CN" && !jsonMode
					if diagnostic == "" || hasChinese != wantChinese {
						t.Fatalf("diagnostic language: want Chinese=%t, got %q", wantChinese, diagnostic)
					}
					if strings.Contains(diagnostic, "Usage:") || strings.Contains(diagnostic, "用法：") {
						t.Fatalf("import failure printed usage: %q", diagnostic)
					}
					if jsonMode && !failed {
						var result forensicsImportResult
						if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
							t.Fatal(err)
						}
						verified := mode == "key-precedence"
						if result.AttestationVerified != verified || result.AttestationStatus != importAttestationStatus(verified) {
							t.Fatalf("verification status changed: %+v", result)
						}
					}
				})
			}
		}
	}
}

func TestForensicsImportHelpExplainsVerificationDefault(t *testing.T) {
	for _, tc := range []struct{ locale, want string }{
		{"en", "required unless --allow-unverified"},
		{"zh-CN", "除非显式使用 --allow-unverified"},
	} {
		t.Run(tc.locale, func(t *testing.T) {
			root := NewRootCommand()
			var output bytes.Buffer
			root.SetOut(&output)
			root.SetArgs([]string{"--lang", tc.locale, "forensics", "import", "--help"})
			if err := root.Execute(); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), tc.want) {
				t.Fatalf("help omits default verification: %s", output.String())
			}
		})
	}
}

// M10: with the correct key the existing verify-then-import path is unchanged
// and the success output states the bundle was verified.
func TestForensicsImportSignedWithCorrectKeyVerifies(t *testing.T) {
	dir := t.TempDir()
	_, priv, _, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	bundle := writeForensicsImportBundle(t, dir, priv)
	pubFile := writeForensicsPubKey(t, dir, priv.Public().(ed25519.PublicKey))
	stdout, stderr, err := runForensicsImport(t, filepath.Join(dir, "store"), bundle, "--pub-key", pubFile)
	if err != nil {
		t.Fatalf("verified import failed: %v (%s)", err, stderr)
	}
	if !strings.Contains(stdout, "attestation=verified") {
		t.Fatalf("output must mark the import verified: %s", stdout)
	}
	if strings.Contains(stderr, "WARNING") {
		t.Fatalf("verified import must not warn: %s", stderr)
	}

	var out bytes.Buffer
	root := NewRootCommand()
	root.SetOut(&out)
	root.SetArgs([]string{"--data-dir", filepath.Join(dir, "store-json"), "forensics", "import", "--json", "--pub-key", pubFile, bundle})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	var got struct {
		AttestationVerified bool   `json:"attestation_verified"`
		AttestationStatus   string `json:"attestation_status"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("invalid import JSON: %s (%v)", out.String(), err)
	}
	if !got.AttestationVerified || got.AttestationStatus != "verified" {
		t.Fatalf("JSON must mark import verified: %+v", got)
	}
}

// M10: wrong key is still rejected — the escape hatch must not weaken
// explicit verification.
func TestForensicsImportWrongKeyRejected(t *testing.T) {
	dir := t.TempDir()
	_, signPriv, _, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, _, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	bundle := writeForensicsImportBundle(t, dir, signPriv)
	wrongPub := writeForensicsPubKey(t, dir, otherPub)
	stdout, _, err := runForensicsImport(t, filepath.Join(dir, "store"), bundle, "--pub-key", wrongPub)
	if err == nil || !strings.Contains(err.Error(), "attestation verify failed") {
		t.Fatalf("wrong key must be rejected, got: %v", err)
	}
	if strings.Contains(stdout, "imported run=") {
		t.Fatalf("bundle imported despite failed verification: %s", stdout)
	}

	// Combining --allow-unverified with --pub-key must not bypass verification.
	if _, _, err := runForensicsImport(t, filepath.Join(dir, "store2"), bundle, "--pub-key", wrongPub, "--allow-unverified"); err == nil || !strings.Contains(err.Error(), "attestation verify failed") {
		t.Fatalf("--allow-unverified must not bypass --pub-key verification, got: %v", err)
	}
}

// M10: a bundle tampered after signing is rejected even with the correct key.
func TestForensicsImportTamperedBundleRejected(t *testing.T) {
	dir := t.TempDir()
	_, priv, _, err := attest.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	bundle := writeForensicsImportBundle(t, dir, priv)
	pubFile := writeForensicsPubKey(t, dir, priv.Public().(ed25519.PublicKey))
	tampered, err := json.Marshal(map[string]any{
		"run_id":         "t-import-run-TAMPERED",
		"schema_version": "agentprovenance.forensics_export/v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundle, tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runForensicsImport(t, filepath.Join(dir, "store"), bundle, "--pub-key", pubFile); err == nil || !strings.Contains(err.Error(), "attestation verify failed") {
		t.Fatalf("tampered bundle must be rejected, got: %v", err)
	}
}
