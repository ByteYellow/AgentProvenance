package derivedview_test

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"testing/fstest"

	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/derivedview"
)

func ExampleSign() {
	ctx := context.Background()
	frozen := fstest.MapFS{"index.html": {Data: []byte("<html>Frozen reader</html>")}}
	files, err := derivedview.InventoryFS(ctx, frozen, derivedview.Limits{})
	if err != nil {
		panic(err)
	}
	// Fixed seed for this executable example only; use the configured export key.
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	m := derivedview.Manifest{
		Sources:   []derivedview.Source{{ID: "run-1", Kind: "checkpoint", Digest: derivedview.Reference{SHA256: attest.DigestSHA256([]byte("frozen database"))}}},
		Selection: derivedview.Reference{SHA256: attest.DigestSHA256([]byte("private selection"))},
		Projection: derivedview.Rules{
			Version: "replay/v1", SHA256: attest.DigestSHA256([]byte("projection rules")),
			ImplementationSHA256: attest.DigestSHA256([]byte("implementation revision")),
		},
		Files: files, Coverage: derivedview.Coverage{State: derivedview.CoverageUnknown},
		Exporter:  derivedview.Exporter{ID: "exporter-1", KeyID: "recipient-pinned-key"},
		CreatedAt: "2026-11-16T10:00:00Z",
	}
	manifest, signature, err := derivedview.Sign(m, key)
	if err != nil {
		panic(err)
	}
	// The existing export writer persists these exact bytes alongside its payload.
	frozen[derivedview.ManifestPath] = &fstest.MapFile{Data: manifest}
	frozen[derivedview.SignaturePath] = &fstest.MapFile{Data: signature}
	policy := derivedview.TrustPolicy{Keys: map[string]derivedview.TrustedKey{
		"recipient-pinned-key": {PublicKey: key.Public().(ed25519.PublicKey), Roles: []string{derivedview.RoleExporter}},
	}}
	result, err := derivedview.VerifyFS(ctx, frozen, policy, derivedview.Limits{})
	if err != nil {
		panic(err)
	}
	fmt.Println(result.FileIntegrity, result.DerivedSignature.Status, result.DerivedSignature.Trusted)
	fmt.Println(result.Derivation, result.SourceSignatures[0].Status)
	// Output:
	// passed valid true
	// not_checked unsigned
}
