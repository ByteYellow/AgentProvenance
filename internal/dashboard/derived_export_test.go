package dashboard

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/derivedview"
)

func TestDerivedExportSignsFrozenSelectedPayload(t *testing.T) {
	paths, db, _ := artifactStore(t)
	ctx := context.Background()
	for _, session := range []string{"selected", "private"} {
		body := session + "-BODY"
		if _, err := (agentcontext.Service{DB: db, Paths: paths}).Save(ctx, "r",
			agentcontext.Source{Harness: "fixture", SessionID: session, ParserVersion: "fixture/v1", Binding: "explicit"},
			[]agentcontext.Record{{Key: "message", Kind: "message", Role: "user", Body: &body}}, agentcontext.Coverage{Status: agentcontext.OK}); err != nil {
			t.Fatal(err)
		}
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	inputs := []ReplaySelection{{RunID: "r", Scope: "session", Harness: "fixture", SessionID: "selected"}}
	p, err := (Server{DB: db}).PrepareSignedOfflineReplaySet(ctx, inputs, ReplaySigner{
		ExporterID: "reviewer", Key: key, ImplementationSHA256: attest.DigestSHA256([]byte("fixture-binary")),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	assertReplayDeliveryBanner(t, p, DeliveryDerived)
	if !p.Inventory.Signed || p.Inventory.Signature == nil || p.Inventory.Signature.Kind != "derived_view" {
		t.Fatalf("missing exporter signature identity: %+v", p.Inventory)
	}
	policy := derivedview.TrustPolicy{ID: "recipient", Keys: map[string]derivedview.TrustedKey{
		attest.KeyID(pub): {PublicKey: pub, Roles: []string{derivedview.RoleExporter}},
	}}
	verified, err := derivedview.VerifyDirectory(ctx, p.root, policy, derivedview.Limits{})
	if err != nil || verified.FileIntegrity != derivedview.IntegrityPassed || !verified.DerivedSignature.Trusted {
		t.Fatalf("signed frozen directory: %+v %v", verified, err)
	}
	if verified.DeclaredCoverage.State != derivedview.CoverageUnknown || len(verified.Manifest.Sources) != 1 || verified.Manifest.Sources[0].Digest.Path != "" {
		t.Fatalf("signature introduced capture certainty or included private source: %+v", verified.Manifest)
	}
	if verified.Manifest.Selection.SHA256 != p.Inventory.Selection.SHA256 || len(verified.Manifest.Files) != len(p.Inventory.Files)+1 {
		t.Fatal("manifest did not bind the existing selection and every reader asset")
	}
	if err := os.RemoveAll(paths.Provenance); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := p.WriteZIP(ctx, &out); err != nil {
		t.Fatal(err)
	}
	verified, err = derivedview.VerifyZIP(ctx, bytes.NewReader(out.Bytes()), int64(out.Len()), policy, derivedview.Limits{})
	if err != nil || verified.FileIntegrity != derivedview.IntegrityPassed || !verified.DerivedSignature.Trusted {
		t.Fatalf("signed exported ZIP: %+v %v", verified, err)
	}
	z, err := zip.NewReader(bytes.NewReader(out.Bytes()), int64(out.Len()))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range z.File {
		if file.Name == "snapshot.db" || file.Name == "original.bundle" || file.Name == "policy.json" {
			t.Fatalf("implicit source or trust policy included: %s", file.Name)
		}
		f, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(f)
		f.Close()
		if err != nil || bytes.Contains(raw, []byte("private-BODY")) {
			t.Fatalf("private content leaked: %s %v", file.Name, err)
		}
	}
	if err := os.WriteFile(filepath.Join(p.root, "assets", "offline.js"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := p.WriteZIP(ctx, io.Discard); err == nil {
		t.Fatal("prepared payload change was ignored")
	}
}

func TestDerivedExportDoesNotUseMutablePublicInventory(t *testing.T) {
	_, db, _ := artifactStore(t)
	if _, err := db.Exec(`INSERT INTO events (id,run_id,source,event_type,created_at,payload) VALUES ('e','r','fixture','exec','2026-11-16T00:00:00Z','{}')`); err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := (Server{DB: db}).PrepareOfflineReplay(context.Background(), "r")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.Inventory.Selection.Path = "private-original.json"
	p.Inventory.Files = nil
	if err := p.signDerived(context.Background(), attest.DigestSHA256([]byte("source")), ReplaySigner{
		ExporterID: "fixture", Key: key, ImplementationSHA256: attest.DigestSHA256([]byte("implementation")),
	}); err != nil {
		t.Fatal(err)
	}
	assertReplayDeliveryBanner(t, p, DeliveryDerived)
	var saved derivedview.Manifest
	raw, err := os.ReadFile(filepath.Join(p.root, derivedview.ManifestPath))
	if err != nil || json.Unmarshal(raw, &saved) != nil || saved.Selection.Path == "private-original.json" || len(saved.Files) < 2 {
		t.Fatalf("mutable public inventory used for signing: %+v %v", saved, err)
	}
}

func assertReplayDeliveryBanner(t *testing.T, p *PreparedReplay, mode string) {
	t.Helper()
	for _, locale := range []string{"en", "zh-CN"} {
		raw, err := os.ReadFile(filepath.Join(p.root, locale, "index.html"))
		if err != nil {
			t.Fatal(err)
		}
		page := string(raw)
		start := strings.Index(page, `<nav class="offline-replay-bar"`)
		if start < 0 {
			t.Fatalf("missing delivery banner in %s", locale)
		}
		page = page[start:]
		end := strings.Index(page, "</nav>")
		if end < 0 {
			t.Fatalf("invalid delivery banner in %s", locale)
		}
		page = page[:end]
		if !strings.Contains(page, `data-delivery-mode="`+mode+`"`) || !strings.Contains(page, `data-verification-state="not_checked"`) {
			t.Fatalf("missing delivery/verification state in %s", locale)
		}
		if mode != DeliveryReading && (strings.Contains(page, "unsigned sharing copy") || strings.Contains(page, "未签名的分享副本")) {
			t.Fatalf("signed payload still claims unsigned in %s", locale)
		}
		if mode != DeliveryReading {
			want := "recipient verification pending"
			if locale == "zh-CN" {
				want = "等待接收方验证"
			}
			if !strings.Contains(page, want) {
				t.Fatalf("exporter supplied a recipient verification claim in %s", locale)
			}
		}
	}
}

func TestDerivedExportHTTPPreviewUsesOperatorSigner(t *testing.T) {
	m, _ := previewFixture(t)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := Server{DB: m.server.DB, ReplaySigner: &ReplaySigner{ExporterID: "local-operator", Key: key,
		ImplementationSHA256: attest.DigestSHA256([]byte("fixture-binary"))}}
	exports := NewReplayExports(config)
	t.Cleanup(exports.Close)
	config.ReplayExports = exports
	h := config.Handler()
	if w := previewCall(h, "POST", "/api/replay/previews", `{"run":"preview-run","scope":"whole_run","sign_key":"attacker"}`); w.Code != 400 {
		t.Fatalf("request accepted a signing key: %d", w.Code)
	}
	p := preparedPreview(t, h)
	if !p.Inventory.Signed || p.Inventory.Signature == nil || p.Inventory.Signature.ExporterID != "local-operator" {
		t.Fatalf("configured signature missing: %+v", p.Inventory.Signature)
	}
	base := "/api/replay/previews/" + p.ID
	for _, file := range []string{derivedview.ManifestPath, derivedview.SignaturePath} {
		w := previewCall(h, "GET", base+"/files/"+file, "")
		if w.Code != 200 {
			t.Fatalf("signature not inspectable: %s %d", file, w.Code)
		}
	}
	w := previewCall(h, "GET", base+"/download?inventory="+p.InventorySHA256, "")
	if w.Code != 200 {
		t.Fatalf("signed download failed: %d", w.Code)
	}
	policy := derivedview.TrustPolicy{Keys: map[string]derivedview.TrustedKey{
		attest.KeyID(pub): {PublicKey: pub, Roles: []string{derivedview.RoleExporter}},
	}}
	result, err := derivedview.VerifyZIP(context.Background(), bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()), policy, derivedview.Limits{})
	if err != nil || result.FileIntegrity != derivedview.IntegrityPassed || !result.DerivedSignature.Trusted {
		t.Fatalf("downloaded signature: %+v %v", result, err)
	}
}
