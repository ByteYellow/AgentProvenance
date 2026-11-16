// Package viewverify provides a database-free command path for exported readers.
package viewverify

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/derivedview"
)

const PolicySchema = "agentprovenance.reader_trust/v1"

type PolicyFile struct {
	SchemaVersion string      `json:"schema_version"`
	ID            string      `json:"id"`
	Keys          []PolicyKey `json:"keys"`
}

type PolicyKey struct {
	KeyID        string   `json:"key_id"`
	PublicKeyHex string   `json:"public_key_hex"`
	Roles        []string `json:"roles"`
}

// ReadPolicy reads only a path explicitly supplied by the recipient. No policy
// or key file is discovered from the package, user home, environment or network.
func ReadPolicy(path string) (derivedview.TrustPolicy, error) {
	p := derivedview.TrustPolicy{Keys: map[string]derivedview.TrustedKey{}}
	if path == "" {
		return p, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return p, err
	}
	defer f.Close()
	l := &io.LimitedReader{R: f, N: (64 << 10) + 1}
	d := json.NewDecoder(l)
	d.DisallowUnknownFields()
	var input PolicyFile
	if err := d.Decode(&input); err != nil {
		return p, fmt.Errorf("invalid recipient trust policy: %w", err)
	}
	if d.Decode(new(any)) != io.EOF || l.N == 0 {
		return p, fmt.Errorf("trust policy must be one JSON object within 64 KiB")
	}
	if input.SchemaVersion != PolicySchema || input.ID == "" || len(input.ID) > 256 || len(input.Keys) > 128 {
		return p, fmt.Errorf("invalid recipient trust policy schema, ID or key count")
	}
	p.ID = input.ID
	for _, key := range input.Keys {
		pub, err := hex.DecodeString(key.PublicKeyHex)
		if err != nil || len(pub) != ed25519.PublicKeySize || key.KeyID != attest.KeyID(pub) {
			return p, fmt.Errorf("trust policy key ID must match its Ed25519 public key")
		}
		if _, exists := p.Keys[key.KeyID]; exists {
			return p, fmt.Errorf("duplicate trust policy key ID")
		}
		if len(key.Roles) == 0 || len(key.Roles) > 2 {
			return p, fmt.Errorf("trust policy key requires explicit roles")
		}
		roles := map[string]bool{}
		for _, role := range key.Roles {
			if (role != "exporter" && role != "producer") || roles[role] {
				return p, fmt.Errorf("trust policy roles must be distinct exporter or producer values")
			}
			roles[role] = true
		}
		p.Keys[key.KeyID] = derivedview.TrustedKey{PublicKey: pub, Roles: key.Roles}
	}
	return p, nil
}

// Verify returns 0 for intact files with a trusted exporter signature, 1 for
// failed verification, 2 for unsigned/untrusted evidence and 3 for input errors.
// Coverage and original-source signatures remain separate report fields.
func Verify(ctx context.Context, path, policyPath string, out io.Writer) (int, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return 3, err
	}
	if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
		return 3, fmt.Errorf("verification input must be a regular ZIP file or a directory")
	}
	if info.IsDir() && policyPath != "" {
		root, err := filepath.EvalSymlinks(path)
		if err != nil {
			return 3, err
		}
		policy, err := filepath.EvalSymlinks(policyPath)
		if err != nil {
			return 3, err
		}
		root, err = filepath.Abs(root)
		if err != nil {
			return 3, err
		}
		policy, err = filepath.Abs(policy)
		if err != nil {
			return 3, err
		}
		rel, err := filepath.Rel(root, policy)
		if err != nil || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return 3, fmt.Errorf("recipient trust policy must be outside the evidence directory")
		}
	}
	policy, err := ReadPolicy(policyPath)
	if err != nil {
		return 3, err
	}
	var result derivedview.Result
	if info.IsDir() {
		result, err = derivedview.VerifyDirectory(ctx, path, policy, derivedview.Limits{})
	} else {
		var f *os.File
		f, err = os.Open(path)
		if err != nil {
			return 3, err
		}
		defer f.Close()
		result, err = derivedview.VerifyZIP(ctx, f, info.Size(), policy, derivedview.Limits{})
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	if writeErr := encoder.Encode(result); writeErr != nil {
		return 3, writeErr
	}
	if err != nil {
		return 1, err
	}
	if result.FileIntegrity == derivedview.IntegrityFailed || result.DerivedSignature.Status == derivedview.SignatureInvalid {
		return 1, fmt.Errorf("exported reader verification failed")
	}
	if result.FileIntegrity != derivedview.IntegrityPassed || !result.DerivedSignature.Trusted || result.DerivedSignature.Status != derivedview.SignatureValid {
		return 2, fmt.Errorf("exported reader is unsigned or its exporter is not trusted")
	}
	return 0, nil
}
