package handoff

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func anchorDelivery(t *testing.T, f deliveryFixture) string {
	t.Helper()
	a := f.report.Attempt
	ref, err := f.receiver.RecordAdmission(context.Background(), a.Request, a)
	if err != nil {
		t.Fatal(err)
	}
	f.receiver.SourceAdmissionRef = ref
	return ref
}

func oneExecutionLink(t *testing.T, db *sql.DB, run, direction string) ExecutionLink {
	t.Helper()
	page, err := (EvidenceService{DB: db}).Links(context.Background(), ExecutionLinksOptions{RunID: run, Direction: direction})
	if err != nil || len(page.Links) != 1 || page.HasMore {
		t.Fatalf("execution links: %+v %v", page, err)
	}
	return page.Links[0]
}

func TestExecutionLinksBidirectionalAndLateDelivery(t *testing.T) {
	f := testDelivery(t)
	ref := anchorDelivery(t, f)
	a := f.report.Attempt
	before := oneExecutionLink(t, f.receiver.DB, a.Request.Source.RunID, "outgoing")
	if before.Identity != IdentityOf(a) || before.AdmissionRef != ref || before.Basis != "authenticated_admission" ||
		before.Manifest != nil || before.Checkpoint != nil || !strings.Contains(strings.Join(before.Issues, ","), "delivery_evidence_not_recorded") {
		t.Fatalf("undelivered admission invented result: %+v", before)
	}
	d := f.prepare(t, "first")
	receipt := f.receive(t, d)
	forward := oneExecutionLink(t, f.receiver.DB, a.Request.Source.RunID, "outgoing")
	back := oneExecutionLink(t, f.receiver.DB, a.LocalRunID, "incoming")
	left, _ := json.Marshal(forward)
	right, _ := json.Marshal(back)
	if !bytes.Equal(left, right) || forward.Basis != "authenticated_delivery" || forward.Checkpoint.Result.ExitCode != 0 || forward.Receipt.Status != "persisted" {
		t.Fatalf("two directions disagree: %s %s", left, right)
	}
	if forward.Manifest.State.Delivery == Acknowledged {
		t.Fatal("receipt invented sender acknowledgment")
	}
	if got := f.receive(t, d); !bytes.Equal(got, receipt) {
		t.Fatal("receipt replay changed")
	}
	if _, err := f.sender.Acknowledge(context.Background(), f.principal, d.Manifest.ID, receipt); err != nil {
		t.Fatal(err)
	}
	later := f.prepare(t, "second")
	f.receive(t, later)
	for _, scope := range []struct{ run, direction string }{{a.Request.Source.RunID, "outgoing"}, {a.LocalRunID, "incoming"}} {
		link := oneExecutionLink(t, f.receiver.DB, scope.run, scope.direction)
		if link.Manifest.PackageVersion != 2 || link.AdmissionRef != ref || link.Manifest.ID == forward.Manifest.ID || link.Identity != forward.Identity {
			t.Fatalf("late package lost identity or ordering: %+v", link)
		}
	}
	var count int
	if err := f.receiver.DB.QueryRow(`SELECT COUNT(*) FROM provenance_objects WHERE object_type='execution_delivery_evidence'`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("delivery history changed: %d %v", count, err)
	}
}

func TestExecutionLinksSignedRoundTripAndMissingSource(t *testing.T) {
	f := testDelivery(t)
	anchorDelivery(t, f)
	a := f.report.Attempt
	f.receive(t, f.prepare(t, "export"))
	expected := oneExecutionLink(t, f.receiver.DB, a.Request.Source.RunID, "outgoing")
	exporter := forensics.Service{DB: f.receiver.DB, Paths: f.receiver.Paths, SignKey: f.receiver.SignKey}
	var bundles []forensics.BundleInfo
	// Export the execution first so an independent reader initially lacks the caller.
	for _, run := range []string{a.LocalRunID, a.Request.Source.RunID} {
		b, err := exporter.ExportBundle(run)
		if err != nil {
			t.Fatal(err)
		}
		if err := forensics.VerifyBundleAttestation(b.Path, b.AttestationPath, f.receiver.SignKey.Public().(ed25519.PublicKey)); err != nil {
			t.Fatal(err)
		}
		bundles = append(bundles, b)
	}
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	receiver := forensics.Service{DB: db, Paths: paths}
	if _, err := receiver.ImportBundleStrict(context.Background(), bundles[0].Path, a.LocalRunID); err != nil {
		t.Fatal(err)
	}
	partial := oneExecutionLink(t, db, a.LocalRunID, "incoming")
	if partial.Admission != nil || partial.Basis != "unanchored_delivery" || len(partial.Issues) != 1 || partial.Issues[0] != "source_admission_not_included" {
		t.Fatalf("execution-only import invented source availability: %+v", partial)
	}
	if _, err := receiver.ImportBundleStrict(context.Background(), bundles[1].Path, a.Request.Source.RunID); err != nil {
		t.Fatal(err)
	}
	if root := os.Getenv("AGENTPROV_TEST_LINKS_DIR"); root != "" {
		if err := os.MkdirAll(root, 0700); err != nil {
			t.Fatal(err)
		}
		for i, b := range bundles {
			for ext, path := range map[string]string{"bundle.json": b.Path, "attestation.json": b.AttestationPath} {
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, []string{"execution-", "source-"}[i]+ext), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
		}
		page, err := (EvidenceService{DB: db}).Links(context.Background(), ExecutionLinksOptions{RunID: a.Request.Source.RunID})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(page)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "links.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
		var proof DeliveryEvidence
		if err := provenance.ReadObjectPayload(f.receiver.DB, a.LocalRunID, expected.DeliveryRef, &proof); err != nil {
			t.Fatal(err)
		}
		raw, err = json.Marshal(proof)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "proof.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Rename(f.receiver.Paths.Provenance, f.receiver.Paths.Provenance+"-unavailable"); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []struct{ run, direction string }{{a.Request.Source.RunID, "outgoing"}, {a.LocalRunID, "incoming"}} {
		got := oneExecutionLink(t, db, scope.run, scope.direction)
		left, _ := json.Marshal(expected)
		right, _ := json.Marshal(got)
		if !bytes.Equal(left, right) {
			t.Fatalf("imported cross-run link changed: %s %s", left, right)
		}
	}
}

func TestExecutionLinksAtomicFailureAndLegacyBackfill(t *testing.T) {
	f := testDelivery(t)
	ref := anchorDelivery(t, f)
	d := f.prepare(t, "atomic")
	if _, err := f.receiver.DB.Exec(`CREATE TRIGGER fail_delivery_link BEFORE INSERT ON provenance_objects
		WHEN NEW.object_type='execution_delivery_evidence' BEGIN SELECT RAISE(ABORT,'link write failure'); END`); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(d.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.receiver.Receive(context.Background(), IdentityOf(f.report.Attempt), d.Envelope, file)
	file.Close()
	if err == nil || rowCount(t, f.receiver.DB, "execution_delivery_receipts") != 0 || rowCount(t, f.receiver.DB, "events") != 0 || rowCount(t, f.receiver.DB, "provenance_objects") != 1 {
		t.Fatalf("link failure leaked committed delivery: %v", err)
	}
	if _, err := f.receiver.DB.Exec(`DROP TRIGGER fail_delivery_link`); err != nil {
		t.Fatal(err)
	}
	// Existing callers without a source anchor keep their receiving behavior.
	f.receiver.SourceAdmissionRef = ""
	receipt := f.receive(t, d)
	f.receiver.SourceAdmissionRef = ref
	again, err := f.receiver.Receive(context.Background(), IdentityOf(f.report.Attempt), d.Envelope, strings.NewReader(""))
	if err != nil || !bytes.Equal(receipt, again) {
		t.Fatalf("saved receipt backfill: %v", err)
	}
	if got := oneExecutionLink(t, f.receiver.DB, f.report.Attempt.LocalRunID, "incoming"); got.Basis != "authenticated_delivery" {
		t.Fatalf("backfill lost source: %+v", got)
	}
	f.receiver.SourceAdmissionRef = "sha256:" + strings.Repeat("0", 64)
	if _, err := f.receiver.Receive(context.Background(), IdentityOf(f.report.Attempt), d.Envelope, strings.NewReader("")); err == nil {
		t.Fatal("missing configured anchor accepted")
	}
}

func TestExecutionLinksQualifiedIdentityPagingAndTamper(t *testing.T) {
	f := testDelivery(t)
	anchorDelivery(t, f)
	a := f.report.Attempt
	request := a.Request
	request.Source.ProducerID, request.Source.Namespace = "other-producer", "other-namespace"
	principal := f.principal
	principal.ID, principal.ProducerID, principal.Namespace = "other-principal", request.Source.ProducerID, request.Source.Namespace
	next, _, err := f.sender.Ledger.Admit(context.Background(), principal, request)
	if err != nil {
		t.Fatal(err)
	}
	other := &DeliveryReceiver{DB: f.receiver.DB, Paths: f.receiver.Paths, ID: f.receiver.ID, SignKey: f.receiver.SignKey,
		Target: f.receiver.Target, TargetKey: f.receiver.TargetKey, Caller: principal}
	if _, err := other.RecordAdmission(context.Background(), request, next); err != nil {
		t.Fatal(err)
	}
	service := EvidenceService{DB: f.receiver.DB}
	opts := ExecutionLinksOptions{RunID: a.Request.Source.RunID, Limit: 1}
	first, err := service.Links(context.Background(), opts)
	if err != nil || len(first.Links) != 1 || !first.HasMore {
		t.Fatalf("first page: %+v %v", first, err)
	}
	opts.Cursor = first.NextCursor
	last, err := service.Links(context.Background(), opts)
	if err != nil || len(last.Links) != 1 || last.HasMore || last.Links[0].Identity.Source.ProducerID == first.Links[0].Identity.Source.ProducerID {
		t.Fatalf("qualified identity lost: %+v %v", last, err)
	}
	opts.RunID = "different-run"
	if _, err := service.Links(context.Background(), opts); !errors.Is(err, ErrInvalid) {
		t.Fatalf("foreign cursor accepted: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.Links(ctx, ExecutionLinksOptions{RunID: a.Request.Source.RunID}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	d := f.prepare(t, "tamper")
	f.receive(t, d)
	link := oneExecutionLink(t, f.receiver.DB, a.LocalRunID, "incoming")
	var path string
	if err := f.receiver.DB.QueryRow(`SELECT path FROM provenance_objects WHERE hash=?`, link.DeliveryRef).Scan(&path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Links(context.Background(), ExecutionLinksOptions{RunID: a.LocalRunID, Direction: "incoming"}); err == nil {
		t.Fatal("corrupt delivery proof was silently omitted")
	}
}

func TestExecutionLinksReadHandler(t *testing.T) {
	f := testDelivery(t)
	anchorDelivery(t, f)
	h := (EvidenceService{DB: f.receiver.DB}).ReadHandler()
	for _, tc := range []struct {
		method, query string
		status        int
	}{{"GET", "?run=source-run", 200}, {"GET", "?run=source-run&limit=0", 400},
		{"GET", "?run=source-run&direction=sideways", 400}, {"GET", "", 400}, {"POST", "?run=source-run", 405}} {
		r := httptest.NewRequest(tc.method, "http://localhost/api/execution-links"+tc.query, nil)
		r.Header.Set("Accept-Language", "zh-CN")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status || !json.Valid(w.Body.Bytes()) || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s %s: %d %s", tc.method, tc.query, w.Code, w.Body)
		}
		if tc.status != http.StatusOK && !strings.Contains(w.Body.String(), `"error"`) {
			t.Fatal("missing typed error")
		}
	}
}

func TestExecutionLinksRejectValidButUnpinnedSignatures(t *testing.T) {
	f := testDelivery(t)
	anchorDelivery(t, f)
	d := f.prepare(t, "pinned")
	f.receive(t, d)
	link := oneExecutionLink(t, f.receiver.DB, f.report.Attempt.LocalRunID, "incoming")
	var proof DeliveryEvidence
	if err := provenance.ReadObjectPayload(f.receiver.DB, link.Identity.LocalRunID, link.DeliveryRef, &proof); err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proof.Manifest, err = signDelivery(deliveryPredicate, d.Manifest.ID, d.Manifest.BundleSHA256, d.Manifest, key)
	if err != nil {
		t.Fatal(err)
	}
	proof.TargetVerifier = hex.EncodeToString(pub)
	receipt := *link.Receipt
	receipt.ManifestSHA256 = attest.DigestSHA256(proof.Manifest)
	proof.Receipt, err = signDelivery(receiptPredicate, d.Manifest.ID, receipt.ManifestSHA256, receipt, f.receiver.SignKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := proof.verify(); err != nil {
		t.Fatalf("replacement signatures should be valid: %v", err)
	}
	if _, err := f.receiver.DB.Exec(`DELETE FROM provenance_objects WHERE hash=?`, link.DeliveryRef); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(proof)
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if _, err := (provenance.ObjectStore{DB: f.receiver.DB, Paths: f.receiver.Paths}).PutExternalObject(provenance.ExternalObjectInput{
		Type: deliveryEvidenceType, RunID: link.Identity.LocalRunID, SourceID: deliveryEvidenceID(proof.AdmissionRef, d.Manifest.PackageVersion), Payload: payload,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := (EvidenceService{DB: f.receiver.DB}).Links(context.Background(), ExecutionLinksOptions{RunID: link.Identity.LocalRunID, Direction: "incoming"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("self-supplied verifier replaced the configured key: %v", err)
	}
}
