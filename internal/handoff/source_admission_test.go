package handoff

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestSourceAdmissionReplayAndSignedBundle(t *testing.T) {
	f := testDelivery(t)
	ctx := context.Background()
	var id, parent, unused int
	var plan string
	if err := f.receiver.DB.QueryRow(`EXPLAIN QUERY PLAN SELECT COUNT(*),COALESCE(MIN(hash),''),COALESCE(MIN(run_id),'')
		FROM provenance_objects WHERE object_type='execution_source_admission' AND source_id=?`, "lookup").Scan(&id, &parent, &unused, &plan); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan, "idx_execution_source_admission_lookup") {
		t.Fatalf("source admission lookup scans unrelated evidence: %s", plan)
	}
	a := f.report.Attempt
	ref, err := f.receiver.RecordAdmission(ctx, a.Request, a)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			repeated := a
			repeated.State.Delivery = Acknowledged
			repeated.Revision++
			if got, err := f.receiver.RecordAdmission(ctx, a.Request, repeated); err != nil || got != ref {
				t.Errorf("concurrent replay changed source anchor: %s %v", got, err)
			}
		}()
	}
	wg.Wait()
	if rowCount(t, f.receiver.DB, "provenance_objects") != 1 {
		t.Fatal("replay duplicated source evidence")
	}
	var before SourceAdmission
	if err := provenance.ReadObjectPayload(f.receiver.DB, a.Request.Source.RunID, ref, &before); err != nil {
		t.Fatal(err)
	}
	if before.Identity != IdentityOf(a) || before.TargetKeySHA256 != attest.DigestSHA256(f.receiver.TargetKey) ||
		before.ReceiverKeySHA256 != attest.DigestSHA256(f.receiver.SignKey.Public().(ed25519.PublicKey)) {
		t.Fatalf("source anchor lost identity or configured key IDs: %+v", before)
	}
	var path string
	if err := f.receiver.DB.QueryRow(`SELECT path FROM provenance_objects WHERE hash=?`, ref).Scan(&path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"argv"`) || strings.Contains(string(raw), a.Request.Command.Workdir) || strings.Contains(string(raw), a.Request.Command.Argv[1]) {
		t.Fatal("source anchor retained a command body or workdir")
	}
	bundle, err := (forensics.Service{DB: f.receiver.DB, Paths: f.receiver.Paths, SignKey: f.receiver.SignKey}).ExportBundle(a.Request.Source.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, f.receiver.SignKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if root := os.Getenv("AGENTPROV_TEST_ADMISSION_DIR"); root != "" {
		if err := os.MkdirAll(root, 0700); err != nil {
			t.Fatal(err)
		}
		payload, err := json.Marshal(before)
		if err != nil {
			t.Fatal(err)
		}
		files := map[string][]byte{"source-admission.json": payload, "source-object.json": raw,
			"signer-public.hex": []byte(hex.EncodeToString(f.receiver.SignKey.Public().(ed25519.PublicKey)))}
		for name, source := range map[string]string{"bundle.json": bundle.Path, "attestation.json": bundle.AttestationPath} {
			files[name], err = os.ReadFile(source)
			if err != nil {
				t.Fatal(err)
			}
		}
		for name, data := range files {
			if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
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
	if _, err := (forensics.Service{DB: db, Paths: paths}).ImportBundleStrict(ctx, bundle.Path, a.Request.Source.RunID); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(f.receiver.Paths.Provenance, f.receiver.Paths.Provenance+"-unavailable"); err != nil {
		t.Fatal(err)
	}
	var after SourceAdmission
	if err := provenance.ReadObjectPayload(db, a.Request.Source.RunID, ref, &after); err != nil || before != after {
		t.Fatalf("signed source evidence did not survive independent import: %+v %v", after, err)
	}
}

func TestSourceAdmissionConflictAndRecovery(t *testing.T) {
	f := testDelivery(t)
	a := f.report.Attempt
	ctx := context.Background()
	if _, err := f.receiver.DB.Exec(`CREATE TRIGGER source_admission_failure BEFORE INSERT ON provenance_objects
		WHEN NEW.object_type='execution_source_admission' BEGIN SELECT RAISE(ABORT,'admission write failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.receiver.RecordAdmission(ctx, a.Request, a); err == nil || rowCount(t, f.receiver.DB, "provenance_objects") != 0 {
		t.Fatal("failed evidence write was reported as persisted")
	}
	if _, err := f.receiver.DB.Exec(`DROP TRIGGER source_admission_failure`); err != nil {
		t.Fatal(err)
	}
	ref, err := f.receiver.RecordAdmission(ctx, a.Request, a)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"target_key", "receiver_key", "receiver_id", "principal", "attempt", "run", "number", "request", "source", "target"} {
		t.Run(field, func(t *testing.T) {
			s := &DeliveryReceiver{DB: f.receiver.DB, Paths: f.receiver.Paths, ID: f.receiver.ID, SignKey: f.receiver.SignKey,
				Target: f.receiver.Target, TargetKey: f.receiver.TargetKey, Caller: f.receiver.Caller}
			b := a
			b.Request, _, _, _ = a.Request.Canonical()
			expected := ErrConflict
			switch field {
			case "target_key":
				s.TargetKey, _, _ = ed25519.GenerateKey(rand.Reader)
			case "receiver_key":
				_, s.SignKey, _ = ed25519.GenerateKey(rand.Reader)
			case "receiver_id":
				s.ID = "other-receiver"
			case "principal":
				s.Caller.ID = "other-router"
			case "attempt":
				b.ID = "another-attempt"
			case "run":
				b.LocalRunID = "another-run"
			case "number":
				b.Number++
			case "request":
				b.Request.Command.Argv[0] = "different-command"
			case "source":
				s.Caller.Namespace = "other-source"
				expected = ErrForbidden
			case "target":
				s.Target.Generation = "cloned-generation"
				expected = ErrForbidden
			}
			if _, err := s.RecordAdmission(ctx, a.Request, b); !errors.Is(err, expected) {
				t.Fatalf("changed %s accepted: %v", field, err)
			}
		})
	}
	if rowCount(t, f.receiver.DB, "provenance_objects") != 1 {
		t.Fatal("conflict overwrote or added source evidence")
	}
	if err := f.receiver.DB.Close(); err != nil {
		t.Fatal(err)
	}
	f.receiver.DB, err = store.Open(f.receiver.Paths)
	if err != nil {
		t.Fatal(err)
	}
	defer f.receiver.DB.Close()
	if got, err := f.receiver.RecordAdmission(ctx, a.Request, a); err != nil || got != ref {
		t.Fatalf("reopen could not recover the source admission: %s %v", got, err)
	}
	retry := a.Request
	retry.OperationID, retry.PreviousAttemptID = "explicit-retry", a.ID
	next, _, err := f.sender.Ledger.Admit(ctx, f.principal, retry)
	if err != nil {
		t.Fatal(err)
	}
	nextRef, err := f.receiver.RecordAdmission(ctx, retry, next)
	if err != nil || nextRef == ref || rowCount(t, f.receiver.DB, "provenance_objects") != 2 {
		t.Fatalf("explicit retry did not get its own source admission: %s %v", nextRef, err)
	}
	var nextSource SourceAdmission
	if err := provenance.ReadObjectPayload(f.receiver.DB, a.Request.Source.RunID, nextRef, &nextSource); err != nil || nextSource.PreviousAttemptID != a.ID || nextSource.AttemptNumber != 2 {
		t.Fatalf("retry lineage lost: %+v %v", nextSource, err)
	}
}

func TestSourceAdmissionCancellationAndIdentityRedaction(t *testing.T) {
	f := testDelivery(t)
	a := f.report.Attempt
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.receiver.RecordAdmission(ctx, a.Request, a); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled persistence: %v", err)
	}
	a.Request.Source.ToolCallID = "sk-fakeidentity01234567890123456789"
	_, _, a.RequestHash, _ = a.Request.Canonical()
	if _, err := f.receiver.RecordAdmission(context.Background(), a.Request, a); !errors.Is(err, ErrConflict) {
		t.Fatalf("redacted identity became a source anchor: %v", err)
	}
	if rowCount(t, f.receiver.DB, "provenance_objects") != 0 {
		t.Fatal("cancelled or changed identity was indexed")
	}
}
