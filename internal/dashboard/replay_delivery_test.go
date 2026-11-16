package dashboard

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/derivedview"
	"github.com/byteyellow/agentprovenance/internal/forensics"
)

func TestReplayOriginalDeliveryReadsExactBundleRevision(t *testing.T) {
	paths, db, _ := artifactStore(t)
	ctx := context.Background()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, run := range []string{"selected", "private"} {
		body := run + "-ORIGINAL-BODY"
		_, err := (agentcontext.Service{DB: db, Paths: paths}).Save(ctx, run,
			agentcontext.Source{Harness: "fixture", SessionID: "s", ParserVersion: "fixture/v1", Binding: "explicit"},
			[]agentcontext.Record{{Key: "m", Kind: "message", Body: &body}}, agentcontext.Coverage{Status: agentcontext.OK})
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO events(id,run_id,event_type,source,payload,created_at) VALUES('before','selected','file_read','fixture','{"note":"ORIGINAL-EVENT"}','2026-11-16T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key, SignKeyID: attest.KeyID(pub)}).ExportBundle("selected")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO events(id,run_id,event_type,source,payload,created_at) VALUES('after','selected','file_read','fixture','{"note":"LATER-EVENT"}','2026-11-16T00:00:01Z')`); err != nil {
		t.Fatal(err)
	}
	server := Server{DB: db, ReplaySigner: &ReplaySigner{ExporterID: "reviewer", Key: key, ImplementationSHA256: attest.DigestSHA256([]byte("fixture"))},
		ReplayDelivery: ReplayDelivery{Mode: DeliveryOriginals, OriginalBundleIDs: []string{bundle.ID}, ConfirmOriginalScope: true}}
	p, err := server.PrepareOfflineReplay(ctx, "selected")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	assertReplayDeliveryBanner(t, p, DeliveryOriginals)
	if p.Inventory.DeliveryMode != DeliveryOriginals || p.Inventory.Events != 1 || len(p.Inventory.Originals) != 1 {
		t.Fatalf("wrong revision: %+v", p.Inventory)
	}
	files, content := replayZIPData(t, p)
	if !strings.Contains(content, "ORIGINAL-EVENT") || strings.Contains(content, "LATER-EVENT") || strings.Contains(content, "private-ORIGINAL-BODY") {
		t.Fatal("original view mixed another run or a later database revision")
	}
	for original, ref := range map[string]ReplayFile{bundle.Path: p.Inventory.Originals[0].Bundle, bundle.AttestationPath: p.Inventory.Originals[0].Attestation} {
		raw, err := os.ReadFile(original)
		if err != nil || !bytes.Equal(raw, files[ref.Path]) {
			t.Fatalf("original bytes changed: %s %v", original, err)
		}
	}
	verified, err := derivedview.VerifyDirectory(ctx, p.root, derivedview.TrustPolicy{Keys: map[string]derivedview.TrustedKey{
		attest.KeyID(pub): {PublicKey: pub, Roles: []string{"producer", "exporter"}},
	}}, derivedview.Limits{})
	if err != nil || verified.FileIntegrity != derivedview.IntegrityPassed || !verified.DerivedSignature.Trusted || len(verified.SourceSignatures) != 2 {
		t.Fatalf("verification: %+v %v", verified, err)
	}
	// Original removal after preparation cannot invalidate a frozen delivery.
	if err := os.Remove(bundle.Path); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(bundle.AttestationPath); err != nil {
		t.Fatal(err)
	}
	_, _ = replayZIPData(t, p)
}

func TestReplayOriginalDeliveryRejectsScopeAndChangedFiles(t *testing.T) {
	paths, db, _ := artifactStore(t)
	if _, err := db.Exec(`INSERT INTO events(id,run_id,event_type,source,payload,created_at) VALUES('e','r','exec','fixture','{}','2026-11-16T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key}).ExportBundle("r")
	if err != nil {
		t.Fatal(err)
	}
	signer := &ReplaySigner{ExporterID: "reviewer", Key: key, ImplementationSHA256: attest.DigestSHA256([]byte("fixture"))}
	for _, tc := range []struct {
		name      string
		delivery  ReplayDelivery
		selection ReplaySelection
	}{
		{"not-confirmed", ReplayDelivery{Mode: DeliveryOriginals, OriginalBundleIDs: []string{bundle.ID}}, ReplaySelection{RunID: "r", Scope: "whole_run"}},
		{"session", ReplayDelivery{Mode: DeliveryOriginals, OriginalBundleIDs: []string{bundle.ID}, ConfirmOriginalScope: true}, ReplaySelection{RunID: "r", Scope: "session", Harness: "fixture", SessionID: "s"}},
		{"exclusion", ReplayDelivery{Mode: DeliveryOriginals, OriginalBundleIDs: []string{bundle.ID}, ConfirmOriginalScope: true}, ReplaySelection{RunID: "r", Scope: "whole_run", ExcludeCategories: []string{"runtime"}}},
		{"foreign-run", ReplayDelivery{Mode: DeliveryOriginals, OriginalBundleIDs: []string{bundle.ID}, ConfirmOriginalScope: true}, ReplaySelection{RunID: "other", Scope: "whole_run"}},
		{"implicit-original", ReplayDelivery{Mode: DeliveryDerived, OriginalBundleIDs: []string{bundle.ID}}, ReplaySelection{RunID: "r", Scope: "whole_run"}},
		{"duplicate-original", ReplayDelivery{Mode: DeliveryOriginals, OriginalBundleIDs: []string{bundle.ID, bundle.ID}, ConfirmOriginalScope: true}, ReplaySelection{RunID: "r", Scope: "whole_run"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := (Server{DB: db, ReplaySigner: signer, ReplayDelivery: tc.delivery}).PrepareSelectedOfflineReplay(context.Background(), tc.selection)
			if err == nil {
				p.Close()
				t.Fatal("invalid original selection accepted")
			}
		})
	}
	server := Server{DB: db, ReplaySigner: signer, ReplayDelivery: ReplayDelivery{Mode: DeliveryOriginals, OriginalBundleIDs: []string{bundle.ID}, ConfirmOriginalScope: true}}
	raw, err := os.ReadFile(bundle.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundle.Path, append(raw, ' '), 0600); err != nil {
		t.Fatal(err)
	}
	if p, err := server.PrepareOfflineReplay(context.Background(), "r"); err == nil {
		p.Close()
		t.Fatal("changed registered original accepted")
	}
	if err := os.WriteFile(bundle.Path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(bundle.AttestationPath); err != nil {
		t.Fatal(err)
	}
	if p, err := server.PrepareOfflineReplay(context.Background(), "r"); err == nil {
		p.Close()
		t.Fatal("unsigned original accepted")
	}
	// Derived delivery never discovers original files as implicit dependencies.
	server.ReplayDelivery = ReplayDelivery{Mode: DeliveryDerived}
	p, err := server.PrepareOfflineReplay(context.Background(), "r")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	files, _ := replayZIPData(t, p)
	for name := range files {
		if strings.HasPrefix(name, "originals/") || filepath.Ext(name) == ".db" {
			t.Fatalf("implicit original: %s", name)
		}
	}
}

func TestReplayDeliveryExplicitReadingOverridesServerSigning(t *testing.T) {
	m, _ := previewFixture(t)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := Server{DB: m.server.DB, ReplaySigner: &ReplaySigner{ExporterID: "operator", Key: key, ImplementationSHA256: attest.DigestSHA256([]byte("fixture"))}}
	exports := NewReplayExports(config)
	defer exports.Close()
	config.ReplayExports = exports
	w := previewCall(config.Handler(), "POST", "/api/replay/previews", `{"run":"preview-run","scope":"whole_run","delivery":{"mode":"reading"}}`)
	if w.Code != 201 || !strings.Contains(w.Body.String(), `"signed":false`) || !strings.Contains(w.Body.String(), `"delivery_mode":"reading"`) {
		t.Fatalf("explicit reading mode: %d %s", w.Code, w.Body.String())
	}
}
