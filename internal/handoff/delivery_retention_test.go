package handoff

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
)

func TestDeliveryRetentionRealCommandAndReceiptSurviveCleanup(t *testing.T) {
	f := testDelivery(t)
	ctx := context.Background()
	now := f.sender.Ledger.now()
	f.sender.Ledger.Now = func() time.Time { return now }
	f.sender.Retention = 2 * time.Hour
	d := f.prepare(t, "transfer")
	raw := f.receive(t, d)
	ack, err := f.sender.Acknowledge(ctx, f.principal, d.Manifest.ID, raw)
	if err != nil || ack.Storage == nil || !ack.Storage.RetainUntil.Equal(now.Add(2*time.Hour)) {
		t.Fatalf("retention from local ACK: %+v %v", ack.Storage, err)
	}
	pending := f.prepare(t, "not-yet-received")
	now = now.Add(time.Hour)
	if result, err := f.sender.PruneAcknowledged(ctx, 10); err != nil || result.Purged != 0 {
		t.Fatalf("early cleanup: %+v %v", result, err)
	}
	_, reader, err := f.sender.OpenBundle(ctx, f.principal, d.Manifest.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	now = ack.Storage.RetainUntil
	result, err := f.sender.PruneAcknowledged(ctx, 10)
	if err != nil || result.Purged != 1 || result.Retired != 1 || result.ReclaimedBytes < d.Manifest.BundleBytes {
		t.Fatalf("cleanup: %+v %v", result, err)
	}
	if _, err := os.Stat(filepath.Dir(d.BundlePath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("sender package still present: %v", err)
	}
	if _, err := os.Stat(pending.BundlePath); err != nil {
		t.Fatalf("unacknowledged package removed: %v", err)
	}
	if n, err := io.Copy(io.Discard, reader); err != nil || n != d.Manifest.BundleBytes {
		t.Fatalf("in-flight descriptor broken: %d %v", n, err)
	}
	if err := f.sender.Ledger.DB.Close(); err != nil {
		t.Fatal(err)
	}
	f.sender.Ledger.DB, err = store.Open(f.sender.Paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.sender.Ledger.DB.Close() })
	got, err := f.sender.Get(ctx, f.principal, d.Manifest.ID)
	if err != nil || !got.retired() || got.Storage.PurgedAt == nil || !bytes.Equal(got.Envelope, d.Envelope) || !bytes.Equal(got.Receipt, raw) {
		t.Fatalf("reopened metadata: %+v %v", got.Storage, err)
	}
	if _, reused, err := f.sender.Prepare(ctx, f.principal, f.report.Attempt.ID, "transfer"); !errors.Is(err, ErrDeliveryRetired) || reused {
		t.Fatalf("retired operation republished: %t %v", reused, err)
	}
	if _, _, err := f.sender.OpenBundle(ctx, f.principal, d.Manifest.ID); !errors.Is(err, ErrDeliveryRetired) {
		t.Fatalf("retired download: %v", err)
	}
	if got, err := f.sender.Acknowledge(ctx, f.principal, d.Manifest.ID, raw); err != nil || !bytes.Equal(got.Receipt, raw) {
		t.Fatalf("receipt replay: %v", err)
	}
	if _, _, err := f.sender.Ledger.Admit(ctx, f.principal, f.report.Attempt.Request); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired command replay: %v", err)
	}
	if rowCount(t, f.sender.Ledger.DB, "execution_attempts") != 1 || rowCount(t, f.sender.Ledger.DB, "tool_calls") != 1 {
		t.Fatal("cleanup/replay changed execution history")
	}
	if err := os.RemoveAll(f.workdir); err != nil {
		t.Fatal(err)
	}
	page, err := provenance.ReadTextContentPage(f.receiver.DB, f.report.Attempt.LocalRunID, f.report.Checkpoint.Stdout.Ref, 0, 1024)
	if err != nil || page.Content != "total,42\n" {
		t.Fatalf("independent received evidence: %+v %v", page, err)
	}
	if receipt, err := f.receiver.Receive(ctx, IdentityOf(f.report.Attempt), d.Envelope, strings.NewReader("")); err != nil || !bytes.Equal(receipt, raw) {
		t.Fatalf("receiver lost durable receipt: %v", err)
	}
	files := f.report.Checkpoint.Result.ArtifactCapture.Files
	if len(files) != 1 || files[0].Path != "result.csv" {
		t.Fatalf("missing artifact: %+v", files)
	}
	artifact, err := provenance.ReadTextContentPage(f.receiver.DB, f.report.Attempt.LocalRunID, files[0].ContentRef, 0, 1024)
	if err != nil || artifact.Content != "total,42\n" {
		t.Fatalf("received artifact after cleanup: %+v %v", artifact, err)
	}
	if err := provenance.VerifyRun(f.receiver.DB, f.report.Attempt.LocalRunID, io.Discard); err != nil {
		t.Fatal(err)
	}
	if again, err := f.sender.PruneAcknowledged(ctx, 10); err != nil || again.Purged != 0 {
		t.Fatalf("repeated cleanup: %+v %v", again, err)
	}
	third := f.prepare(t, "explicit-new-transfer")
	if third.Manifest.PackageVersion != 3 || third.Manifest.PreviousManifestSHA256 != pending.ManifestSHA256 {
		t.Fatal("new package lost immutable version chain")
	}
	if root := os.Getenv("AGENTPROV_TEST_RETENTION_REPORT_DIR"); root != "" {
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
		var path string
		if err := f.receiver.DB.QueryRow(`SELECT bundle_path FROM execution_delivery_receipts WHERE manifest_sha256=?`, d.ManifestSHA256).Scan(&path); err != nil {
			t.Fatal(err)
		}
		bundle, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		metadata, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		for name, body := range map[string][]byte{
			"delivery.json": metadata, "manifest.dsse.json": d.Envelope, "receipt.dsse.json": raw, "bundle.json": bundle,
			"sender.pub":   []byte(hex.EncodeToString(f.sender.SignKey.Public().(ed25519.PublicKey))),
			"receiver.pub": []byte(hex.EncodeToString(f.receiver.SignKey.Public().(ed25519.PublicKey))),
		} {
			if err := os.WriteFile(filepath.Join(root, name), body, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Logf("signed command output survived cleanup: version=%d bytes=%d storage=%s", d.Manifest.PackageVersion, result.ReclaimedBytes, got.Storage.State)
}

func TestDeliveryRetentionDisabledLegacyAndValidRequest(t *testing.T) {
	f := testDelivery(t)
	ctx := context.Background()
	now := f.sender.Ledger.now()
	f.sender.Ledger.Now = func() time.Time { return now }
	d := f.prepare(t, "legacy")
	raw := f.receive(t, d)
	if _, err := f.sender.Acknowledge(ctx, f.principal, d.Manifest.ID, raw); err != nil {
		t.Fatal(err)
	}
	if r, err := f.sender.PruneAcknowledged(ctx, 10); err != nil || r != (DeliveryCleanup{}) {
		t.Fatalf("default changed: %+v %v", r, err)
	}
	f.sender.Retention = time.Minute
	if r, err := f.sender.PruneAcknowledged(ctx, 1); err != nil || r.Scheduled != 1 || r.Purged != 0 {
		t.Fatalf("legacy scheduling: %+v %v", r, err)
	}
	got, err := f.sender.Get(ctx, f.principal, d.Manifest.ID)
	if err != nil || !got.Storage.RetainUntil.Equal(f.report.Attempt.Request.ValidUntil) {
		t.Fatalf("request validity not protected: %+v %v", got.Storage, err)
	}
	now = now.Add(2 * time.Minute)
	if r, err := f.sender.PruneAcknowledged(ctx, 1); err != nil || r.Purged != 0 {
		t.Fatalf("valid request removed: %+v %v", r, err)
	}
	if _, err := f.sender.Acknowledge(ctx, f.principal, d.Manifest.ID, raw); err != nil {
		t.Fatal(err)
	}
	unchanged, _ := f.sender.Get(ctx, f.principal, d.Manifest.ID)
	if !unchanged.Storage.RetainUntil.Equal(got.Storage.RetainUntil) {
		t.Fatal("receipt replay reset retention")
	}
	now = f.report.Attempt.Request.ValidUntil
	f.sender.Retention = 0
	if r, err := f.sender.PruneAcknowledged(ctx, 1); err != nil || r.Purged != 0 {
		t.Fatalf("disabled cleanup: %+v %v", r, err)
	}
	f.sender.Retention = time.Minute
	if r, err := f.sender.PruneAcknowledged(ctx, 1); err != nil || r.Purged != 1 {
		t.Fatalf("expired request: %+v %v", r, err)
	}
}

func TestDeliveryRetentionInterruptedUnlinkAndBoundedRetry(t *testing.T) {
	f := testDelivery(t)
	ctx := context.Background()
	now := f.sender.Ledger.now()
	f.sender.Ledger.Now = func() time.Time { return now }
	f.sender.Retention = time.Hour
	var deliveries []Delivery
	for _, op := range []string{"first", "second"} {
		d := f.prepare(t, op)
		if _, err := f.sender.Acknowledge(ctx, f.principal, d.Manifest.ID, f.receive(t, d)); err != nil {
			t.Fatal(err)
		}
		deliveries = append(deliveries, d)
		now = now.Add(time.Second)
	}
	now = now.Add(2 * time.Hour)
	first := deliveries[0]
	unknown := filepath.Join(filepath.Dir(first.BundlePath), "operator-note.txt")
	if err := os.WriteFile(unknown, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r, err := f.sender.PruneAcknowledged(ctx, 1); err == nil || r.Retired != 1 || r.Failed != 1 || r.Purged != 0 {
		t.Fatalf("unexpected file failure hidden: %+v %v", r, err)
	}
	if got, err := f.sender.Get(ctx, f.principal, first.Manifest.ID); err != nil || !got.retired() || got.Storage.PurgedAt != nil {
		t.Fatalf("retirement not durable: %+v %v", got.Storage, err)
	}
	if r, err := f.sender.PruneAcknowledged(ctx, 1); err != nil || r.Purged != 1 {
		t.Fatalf("failed package starved next package: %+v %v", r, err)
	}
	if err := os.Remove(unknown); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(first.BundlePath); err != nil {
		t.Fatal(err)
	}
	if err := f.sender.Ledger.DB.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.sender.Ledger.DB, err = store.Open(f.sender.Paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.sender.Ledger.DB.Close() })
	if r, err := f.sender.PruneAcknowledged(ctx, 1); err != nil || r.Purged != 1 || r.Retired != 0 {
		t.Fatalf("restart after partial unlink: %+v %v", r, err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := f.sender.PruneAcknowledged(cancelled, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled cleanup: %v", err)
	}
}

func TestDeliveryRetentionConcurrentWorkers(t *testing.T) {
	f := testDelivery(t)
	ctx := context.Background()
	now := f.sender.Ledger.now()
	f.sender.Retention = time.Hour
	d := f.prepare(t, "concurrent")
	if _, err := f.sender.Acknowledge(ctx, f.principal, d.Manifest.ID, f.receive(t, d)); err != nil {
		t.Fatal(err)
	}
	f.sender.Ledger.Now = func() time.Time { return now.Add(2 * time.Hour) }
	other := &DeliveryService{Ledger: f.sender.Ledger, Paths: f.sender.Paths, SignKey: f.sender.SignKey,
		ReceiverID: f.sender.ReceiverID, ReceiverKey: f.sender.ReceiverKey, Retention: time.Hour}
	var wg sync.WaitGroup
	for _, sender := range []*DeliveryService{f.sender, other} {
		wg.Add(1)
		go func(s *DeliveryService) {
			defer wg.Done()
			if _, err := s.PruneAcknowledged(ctx, 1); err != nil {
				t.Error(err)
			}
		}(sender)
	}
	wg.Wait()
	got, err := f.sender.Get(ctx, f.principal, d.Manifest.ID)
	if err != nil || got.Storage.PurgedAt == nil {
		t.Fatalf("concurrent cleanup: %+v %v", got.Storage, err)
	}
}

func TestDeliveryRetentionTransactionFailures(t *testing.T) {
	for _, stage := range []string{"retire", "purge"} {
		t.Run(stage, func(t *testing.T) {
			f := testDelivery(t)
			ctx := context.Background()
			now := f.sender.Ledger.now()
			f.sender.Retention = time.Hour
			d := f.prepare(t, "transaction")
			if _, err := f.sender.Acknowledge(ctx, f.principal, d.Manifest.ID, f.receive(t, d)); err != nil {
				t.Fatal(err)
			}
			f.sender.Ledger.Now = func() time.Time { return now.Add(2 * time.Hour) }
			condition := "NEW.retired_at_ns>0"
			if stage == "purge" {
				condition = "NEW.purged_at_ns>0"
			}
			if _, err := f.sender.Ledger.DB.Exec(`CREATE TRIGGER fail_retention BEFORE UPDATE ON execution_delivery_retention WHEN ` + condition + ` BEGIN SELECT RAISE(ABORT,'injected storage failure'); END`); err != nil {
				t.Fatal(err)
			}
			if r, err := f.sender.PruneAcknowledged(ctx, 1); err == nil || r.Failed != 1 || r.Purged != 0 {
				t.Fatalf("storage failure hidden: %+v %v", r, err)
			}
			got, err := f.sender.Get(ctx, f.principal, d.Manifest.ID)
			if err != nil || got.retired() != (stage == "purge") || got.Storage.PurgedAt != nil {
				t.Fatalf("storage state: %+v %v", got.Storage, err)
			}
			if _, err := os.Stat(d.BundlePath); (stage == "retire" && err != nil) || (stage == "purge" && !errors.Is(err, os.ErrNotExist)) {
				t.Fatalf("wrong filesystem result: %v", err)
			}
			if _, err := f.sender.Ledger.DB.Exec(`DROP TRIGGER fail_retention`); err != nil {
				t.Fatal(err)
			}
			if r, err := f.sender.PruneAcknowledged(ctx, 1); err != nil || r.Purged != 1 {
				t.Fatalf("retry did not settle: %+v %v", r, err)
			}
		})
	}
}

func TestDeliveryRetentionUpgradeAndTargetIsolation(t *testing.T) {
	f := testDelivery(t)
	ctx := context.Background()
	d := f.prepare(t, "upgrade")
	raw := f.receive(t, d)
	if _, err := f.sender.Acknowledge(ctx, f.principal, d.Manifest.ID, raw); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{`DROP TABLE execution_delivery_retention`, `DELETE FROM schema_versions WHERE version>25`, `INSERT OR IGNORE INTO schema_versions VALUES(25,'previous version','2026-11-14')`} {
		if _, err := f.sender.Ledger.DB.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := store.EnsureSchema(f.sender.Ledger.DB); err != nil {
			t.Fatal(err)
		}
	}
	got, err := f.sender.Get(ctx, f.principal, d.Manifest.ID)
	if err != nil || got.Storage != nil || !bytes.Equal(got.Envelope, d.Envelope) || !bytes.Equal(got.Receipt, raw) {
		t.Fatalf("upgrade changed original evidence: %+v %v", got.Storage, err)
	}
	f.sender.Retention = time.Hour
	now := f.report.Attempt.Request.ValidUntil.Add(24 * time.Hour)
	f.sender.Ledger.Now = func() time.Time { return now }
	for _, change := range []string{"receiver", "generation", "producer", "instance"} {
		other := &DeliveryService{Ledger: f.sender.Ledger, Paths: f.sender.Paths, SignKey: f.sender.SignKey,
			ReceiverID: f.sender.ReceiverID, ReceiverKey: f.sender.ReceiverKey, Retention: time.Hour}
		switch change {
		case "receiver":
			other.ReceiverID = "other"
		case "generation":
			other.Ledger.Target.Generation = "other"
		case "producer":
			other.Ledger.Target.ProducerID = "other"
		case "instance":
			other.Ledger.Target.InstanceID = "other"
		}
		if r, err := other.PruneAcknowledged(ctx, 1); err != nil || r != (DeliveryCleanup{}) {
			t.Fatalf("foreign %s scheduled/deleted: %+v %v", change, r, err)
		}
	}
	if r, err := f.sender.PruneAcknowledged(ctx, 1); err != nil || r.Scheduled != 1 || r.Purged != 0 {
		t.Fatalf("old receipt retroactively expired: %+v %v", r, err)
	}
	got, err = f.sender.Get(ctx, f.principal, d.Manifest.ID)
	if err != nil || !got.Storage.RetainUntil.Equal(now.Add(time.Hour)) {
		t.Fatalf("legacy window: %+v %v", got.Storage, err)
	}
}

func TestDeliveryRetentionRejectsUnownedPaths(t *testing.T) {
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(paths.Artifacts, "execution-deliveries")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	foreign := t.TempDir()
	secret := filepath.Join(foreign, "bundle.json")
	if err := os.WriteFile(secret, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(foreign, filepath.Join(root, "package-link")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{secret, filepath.Join(root, ".prepare-work", "bundle.json"), filepath.Join(root, "package-link", "bundle.json"), filepath.Join(root, "package-x", "unexpected.json")} {
		if _, err := removeDeliveryPackage(context.Background(), paths, path); err == nil {
			t.Fatalf("accepted unowned path %s", path)
		}
	}
	if body, err := os.ReadFile(secret); err != nil || string(body) != "preserve" {
		t.Fatalf("followed package symlink: %q %v", body, err)
	}
}
