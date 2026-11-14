package handoff

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
)

type deliveryFixture struct {
	sender    *DeliveryService
	receiver  *DeliveryReceiver
	principal Principal
	report    Report
	workdir   string
}

func testDelivery(t *testing.T) deliveryFixture {
	t.Helper()
	e, p, r := testExecutor(t)
	work := t.TempDir()
	e.Options.WorkspaceRoot = work
	if err := os.WriteFile(filepath.Join(work, "input.csv"), []byte("value\n20\n22\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.Command.Workdir, r.Command.DisableSnapshot = work, false
	r.Command.Argv = []string{"awk", `NR>1 {sum+=$1} END {printf "total,%d\n",sum > "result.csv"; printf "total,%d\n",sum}`, "input.csv"}
	a, _, err := e.Ledger.Admit(context.Background(), p, r)
	if err != nil {
		t.Fatal(err)
	}
	stop := startExecutor(t, e)
	report := waitExecution(t, e, p, a.ID, Succeeded)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	return deliveryFromReport(t, e, p, report, work)
}

func deliveryFromReport(t *testing.T, e *Executor, p Principal, report Report, work string) deliveryFixture {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recvPub, recvKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s := &DeliveryService{Ledger: e.Ledger, Paths: e.Paths, SignKey: key, ReceiverID: "investigator", ReceiverKey: recvPub}
	receiver := &DeliveryReceiver{DB: db, Paths: paths, ID: s.ReceiverID, SignKey: recvKey, Target: report.Attempt.Request.Target, TargetKey: pub, Caller: p}
	return deliveryFixture{s, receiver, p, report, work}
}

func (f deliveryFixture) prepare(t *testing.T, operation string) Delivery {
	t.Helper()
	d, _, err := f.sender.Prepare(context.Background(), f.principal, f.report.Attempt.ID, operation)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func (f deliveryFixture) receive(t *testing.T, d Delivery) []byte {
	t.Helper()
	file, err := os.Open(d.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	raw, err := f.receiver.Receive(context.Background(), IdentityOf(f.report.Attempt), d.Envelope, file)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDeliveryRealCommandSurvivesLostReceiptAndReopen(t *testing.T) {
	f := testDelivery(t)
	ctx := context.Background()
	d := f.prepare(t, "initial")
	if d.Manifest.State.Capture != Draining || d.Manifest.PackageVersion != 1 || d.Manifest.CheckpointRef != f.report.CheckpointRef {
		t.Fatalf("manifest: %+v", d.Manifest)
	}
	raw := f.receive(t, d)
	before, err := f.sender.Ledger.Get(ctx, f.principal, f.report.Attempt.ID)
	if err != nil || before.State.Delivery != Transferring {
		t.Fatalf("receipt not returned, sender state: %+v %v", before, err)
	}
	if err := f.receiver.DB.Close(); err != nil {
		t.Fatal(err)
	}
	f.receiver.DB, err = store.Open(f.receiver.Paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.receiver.DB.Close() })
	// A retry returns the stored receipt without requiring the body again.
	again, err := f.receiver.Receive(ctx, IdentityOf(f.report.Attempt), d.Envelope, strings.NewReader(""))
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatalf("receipt retry: %v", err)
	}
	got, err := f.sender.Acknowledge(ctx, f.principal, d.Manifest.ID, again)
	if err != nil || !bytes.Equal(got.Receipt, raw) {
		t.Fatalf("ack: %v", err)
	}
	after, err := f.sender.Ledger.Get(ctx, f.principal, f.report.Attempt.ID)
	if err != nil || after.State.Delivery != Acknowledged || after.State.Capture != Draining || after.State.Execution != Succeeded {
		t.Fatalf("ack changed capture/execution: %+v %v", after.State, err)
	}
	if err := f.sender.Ledger.DB.Close(); err != nil {
		t.Fatal(err)
	}
	f.sender.Ledger.DB, err = store.Open(f.sender.Paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.sender.Ledger.DB.Close() })
	replayed, reused, err := f.sender.Prepare(ctx, f.principal, f.report.Attempt.ID, "initial")
	if err != nil || !reused || !bytes.Equal(replayed.Envelope, d.Envelope) || !bytes.Equal(replayed.Receipt, raw) {
		t.Fatalf("reopened outbox: %v %t", err, reused)
	}
	if _, err := f.sender.Acknowledge(ctx, f.principal, d.Manifest.ID, raw); err != nil {
		t.Fatal(err)
	}
	stable, _ := f.sender.Ledger.Get(ctx, f.principal, f.report.Attempt.ID)
	if stable.Revision != after.Revision || rowCount(t, f.receiver.DB, "execution_delivery_receipts") != 1 {
		t.Fatal("replay changed revision or duplicated receipt")
	}
	for _, path := range []string{f.workdir, f.sender.Paths.Provenance, f.sender.Paths.Snapshots} {
		if err := os.RemoveAll(path); err != nil {
			t.Fatal(err)
		}
	}
	page, err := provenance.ReadTextContentPage(f.receiver.DB, f.report.Attempt.LocalRunID, f.report.Checkpoint.Stdout.Ref, 0, 1024)
	if err != nil || page.Content != "total,42\n" {
		t.Fatalf("received command output: %+v %v", page, err)
	}
	files := f.report.Checkpoint.Result.ArtifactCapture.Files
	if len(files) != 1 || files[0].Path != "result.csv" {
		t.Fatalf("missing result artifact: %+v", files)
	}
	artifact, err := provenance.ReadTextContentPage(f.receiver.DB, f.report.Attempt.LocalRunID, files[0].ContentRef, 0, 1024)
	if err != nil || artifact.Content != "total,42\n" || artifact.HasMore {
		t.Fatalf("received artifact: %+v %v", artifact, err)
	}
	if err := provenance.VerifyRun(f.receiver.DB, f.report.Attempt.LocalRunID, io.Discard); err != nil {
		t.Fatal(err)
	}
}

func TestDeliveryPreservesStopReport(t *testing.T) {
	f := testDelivery(t)
	r := f.report.Attempt.Request
	r.DispatchID, r.OperationID, r.Source.ToolCallID = "stop-dispatch", "stop-operation", "stop-call"
	r.Command = Command{Argv: []string{"sleep", "60"}, DisableSnapshot: true, PostRootGraceMS: 1}
	a, _, err := f.sender.Ledger.Admit(context.Background(), f.principal, r)
	if err != nil {
		t.Fatal(err)
	}
	e := &Executor{Ledger: f.sender.Ledger, Paths: f.sender.Paths, PollInterval: 5 * time.Millisecond}
	stop := startExecutor(t, e)
	waitExecution(t, e, f.principal, a.ID, Running)
	if _, err := e.Ledger.RequestStop(context.Background(), f.principal, a.ID, "stop"); err != nil {
		t.Fatal(err)
	}
	f.report = waitExecution(t, e, f.principal, a.ID, Cancelled)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if f.report.Checkpoint.Result.Stop == nil {
		t.Fatal("stop report missing from execution checkpoint")
	}
	d := f.prepare(t, "stopped-evidence")
	f.receive(t, d)
	var raw string
	if err := f.receiver.DB.QueryRow(`SELECT json_extract(payload,'$.stop_report') FROM events WHERE id=?`,
		f.report.Checkpoint.Result.EndEventID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var got, want map[string]any
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(f.report.Checkpoint.Result.Stop)
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}
	gotJSON, _ := json.Marshal(got)
	wantJSON, _ := json.Marshal(want)
	if !bytes.Equal(gotJSON, wantJSON) {
		t.Fatalf("signed delivery changed stop evidence: %s != %s", gotJSON, wantJSON)
	}
	if err := provenance.VerifyRun(f.receiver.DB, a.LocalRunID, io.Discard); err != nil {
		t.Fatal(err)
	}
}

func TestDeliveryRejectsWrongScopeSignatureAndBytes(t *testing.T) {
	f := testDelivery(t)
	d := f.prepare(t, "initial")
	body, err := os.ReadFile(d.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"signature", "receiver", "attempt", "generation", "subject", "checkpoint", "bytes", "extra_bytes", "truncated", "expected_source"} {
		t.Run(name, func(t *testing.T) {
			m, expected := d.Manifest, IdentityOf(f.report.Attempt)
			data := append([]byte(nil), body...)
			key := f.sender.SignKey
			switch name {
			case "signature":
				_, key, err = ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
			case "receiver":
				m.ReceiverID = "other"
			case "attempt":
				m.Identity.AttemptID = "other"
			case "generation":
				m.Identity.Target.Generation = "restored"
			case "checkpoint":
				m.CheckpointRef = "sha256:" + strings.Repeat("0", 64)
			case "bytes":
				data[len(data)-1] ^= 1
			case "extra_bytes":
				data = append(data, '\n')
			case "truncated":
				data = data[:len(data)-1]
			case "expected_source":
				expected.Source.ToolCallID = "other"
			}
			id := m.ID
			if name == "subject" {
				id = strings.Repeat("1", 64)
			}
			env, err := signDelivery(deliveryPredicate, id, m.BundleSHA256, m, key)
			if err != nil {
				t.Fatal(err)
			}
			if receipt, err := f.receiver.Receive(context.Background(), expected, env, bytes.NewReader(data)); err == nil || len(receipt) != 0 {
				t.Fatalf("accepted %s", name)
			}
			if rowCount(t, f.receiver.DB, "events") != 0 || rowCount(t, f.receiver.DB, "execution_delivery_receipts") != 0 {
				t.Fatal("rejection changed receiving store")
			}
		})
	}
	f.receive(t, d)
}

func TestDeliveryReceiptAndEvidenceCommitAtomically(t *testing.T) {
	f := testDelivery(t)
	d := f.prepare(t, "initial")
	if _, err := f.receiver.DB.Exec(`CREATE TRIGGER fail_receipt BEFORE INSERT ON execution_delivery_receipts BEGIN SELECT RAISE(ABORT,'receipt disk failure'); END`); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(d.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	raw, err := f.receiver.Receive(context.Background(), IdentityOf(f.report.Attempt), d.Envelope, file)
	if err == nil || len(raw) != 0 || rowCount(t, f.receiver.DB, "events") != 0 || rowCount(t, f.receiver.DB, "provenance_objects") != 0 {
		t.Fatalf("receipt failure committed evidence: %v", err)
	}
	if _, err := f.receiver.DB.Exec("DROP TRIGGER fail_receipt"); err != nil {
		t.Fatal(err)
	}
	raw = f.receive(t, d)
	if _, err := f.sender.Ledger.DB.Exec(`CREATE TRIGGER fail_ack BEFORE UPDATE ON execution_attempts WHEN NEW.delivery_state='acknowledged' BEGIN SELECT RAISE(ABORT,'ack disk failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.sender.Acknowledge(context.Background(), f.principal, d.Manifest.ID, raw); err == nil {
		t.Fatal("failed sender update acknowledged")
	}
	saved, err := f.sender.Get(context.Background(), f.principal, d.Manifest.ID)
	if err != nil || len(saved.Receipt) != 0 {
		t.Fatalf("partial sender ack: %v", err)
	}
	if _, err := f.sender.Ledger.DB.Exec("DROP TRIGGER fail_ack"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.sender.Acknowledge(context.Background(), f.principal, d.Manifest.ID, raw); err != nil {
		t.Fatal(err)
	}
}

func TestDeliveryLateEvidenceExtendsSignedRange(t *testing.T) {
	f := testDelivery(t)
	ctx := context.Background()
	objects := provenance.ObjectStore{DB: f.sender.Ledger.DB, Paths: f.sender.Paths}
	if _, err := objects.MaterializeRun(f.report.Attempt.LocalRunID); err != nil {
		t.Fatal(err)
	}
	first := f.prepare(t, "first")
	receipt1 := f.receive(t, first)
	if _, err := f.sender.Acknowledge(ctx, f.principal, first.Manifest.ID, receipt1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.sender.Ledger.DB.Exec(`INSERT INTO events(id,run_id,source,event_type,payload,created_at) VALUES('late-record',?,'test','annotation','{"late":true}','2026-11-14T00:00:00Z')`, f.report.Attempt.LocalRunID); err != nil {
		t.Fatal(err)
	}
	if _, err := objects.MaterializeRun(f.report.Attempt.LocalRunID); err != nil {
		t.Fatal(err)
	}
	second := f.prepare(t, "second")
	if second.Manifest.PackageVersion != 2 || second.Manifest.PreviousManifestSHA256 != first.ManifestSHA256 || second.Manifest.BundleSHA256 == first.Manifest.BundleSHA256 {
		t.Fatal("late package did not extend chain")
	}
	current, _ := f.sender.Ledger.Get(ctx, f.principal, f.report.Attempt.ID)
	if current.State.Delivery != Transferring {
		t.Fatal("new package inherited old ack")
	}
	if _, err := f.sender.Acknowledge(ctx, f.principal, second.Manifest.ID, receipt1); !errors.Is(err, ErrConflict) {
		t.Fatalf("old receipt acknowledged new range: %v", err)
	}
	receipt2 := f.receive(t, second)
	if _, err := f.sender.Acknowledge(ctx, f.principal, second.Manifest.ID, receipt2); err != nil {
		t.Fatal(err)
	}
	if rowCount(t, f.receiver.DB, "execution_delivery_receipts") != 2 {
		t.Fatal("late package replaced receipt")
	}
	var count int
	if err := f.receiver.DB.QueryRow("SELECT COUNT(*) FROM events WHERE id='late-record'").Scan(&count); err != nil || count != 1 {
		t.Fatalf("late record not retained: %v", err)
	}
	// Earlier receipt and package remain independently readable after extension.
	if err := checkDeliveryFile(ctx, first.BundlePath, first.Manifest); err != nil {
		t.Fatal(err)
	}
	if raw := f.receive(t, first); !bytes.Equal(raw, receipt1) {
		t.Fatal("old receipt was rewritten")
	}
}

func TestDeliveryConcurrentReplayAndOutOfOrder(t *testing.T) {
	f := testDelivery(t)
	ctx := context.Background()
	const n = 4
	var wg sync.WaitGroup
	errs := make(chan error, n)
	ids := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, _, err := f.sender.Prepare(ctx, f.principal, f.report.Attempt.ID, "same")
			errs <- err
			ids <- d.Manifest.ID
		}()
	}
	wg.Wait()
	close(errs)
	close(ids)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	id := ""
	for got := range ids {
		if id != "" && id != got {
			t.Fatal("concurrent duplicate delivery")
		}
		id = got
	}
	first := f.prepare(t, "same")
	second := f.prepare(t, "next")
	file, err := os.Open(second.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := f.receiver.Receive(ctx, IdentityOf(f.report.Attempt), second.Envelope, file); !errors.Is(err, ErrConflict) {
		t.Fatalf("missing predecessor accepted: %v", err)
	}
	if rowCount(t, f.receiver.DB, "events") != 0 {
		t.Fatal("out of order import changed store")
	}
	r1 := f.receive(t, first)
	r2 := f.receive(t, second)
	if _, err := f.sender.Acknowledge(ctx, f.principal, second.Manifest.ID, r2); err != nil {
		t.Fatal(err)
	}
	state, _ := f.sender.Ledger.Get(ctx, f.principal, f.report.Attempt.ID)
	if state.State.Delivery != Transferring {
		t.Fatal("one receipt acknowledged other unconfirmed range")
	}
	if _, err := f.sender.Acknowledge(ctx, f.principal, first.Manifest.ID, r1); err != nil {
		t.Fatal(err)
	}
	state, _ = f.sender.Ledger.Get(ctx, f.principal, f.report.Attempt.ID)
	if state.State.Delivery != Acknowledged {
		t.Fatal("complete receipts not acknowledged")
	}
}

func TestDeliveryStoredConflictAndCancellation(t *testing.T) {
	f := testDelivery(t)
	ctx := context.Background()
	foreign := f.principal
	foreign.ID = "other"
	if _, _, err := f.sender.Prepare(ctx, foreign, f.report.Attempt.ID, "first"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("foreign prepare: %v", err)
	}
	d := f.prepare(t, "first")
	if _, err := f.sender.Get(ctx, foreign, d.Manifest.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("foreign get: %v", err)
	}
	f.receive(t, d)
	changed := d.Manifest
	changed.SnapshotAt = changed.SnapshotAt.Add(1)
	raw, err := signDelivery(deliveryPredicate, changed.ID, changed.BundleSHA256, changed, f.sender.SignKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.receiver.Receive(ctx, IdentityOf(f.report.Attempt), raw, strings.NewReader("")); !errors.Is(err, ErrConflict) {
		t.Fatalf("same package ID changed: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := f.sender.Prepare(cancelled, f.principal, f.report.Attempt.ID, "new"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled export: %v", err)
	}
	if _, err := f.receiver.Receive(cancelled, IdentityOf(f.report.Attempt), d.Envelope, strings.NewReader("")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled receive: %v", err)
	}
	if err := os.WriteFile(d.BundlePath, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.sender.Prepare(ctx, f.principal, f.report.Attempt.ID, "first"); err == nil {
		t.Fatal("retry accepted corrupted outbox")
	}
}

func TestDeliveryProtocolPreservesInt64AndRejectsWrongType(t *testing.T) {
	f := testDelivery(t)
	d := f.prepare(t, "first")
	m := d.Manifest
	m.AttemptRevision = 9007199254740993
	raw, err := signDelivery(deliveryPredicate, m.ID, m.BundleSHA256, m, f.sender.SignKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := verifyManifest(raw, f.receiver.TargetKey)
	if err != nil || got.AttemptRevision != m.AttemptRevision {
		t.Fatalf("revision lost precision: %d %v", got.AttemptRevision, err)
	}
	wrong, err := signDelivery(receiptPredicate, m.ID, m.BundleSHA256, m, f.sender.SignKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyManifest(wrong, f.receiver.TargetKey); err == nil {
		t.Fatal("wrong predicate accepted")
	}
	var env attest.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	env.PayloadType = "text/plain"
	wrong, err = json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyManifest(wrong, f.receiver.TargetKey); err == nil {
		t.Fatal("wrong payload type accepted")
	}
	if _, err := verifyManifest(append(raw, []byte("{}")...), f.receiver.TargetKey); err == nil {
		t.Fatal("trailing JSON accepted")
	}
}

type mutatingDeliveryReader struct {
	io.Reader
	mutate func()
}

func (r *mutatingDeliveryReader) Read(b []byte) (int, error) {
	if r.mutate != nil {
		r.mutate()
		r.mutate = nil
	}
	return r.Reader.Read(b)
}

func TestDeliveryOwnsAuthenticatedManifestBytes(t *testing.T) {
	f := testDelivery(t)
	d := f.prepare(t, "first")
	original := append([]byte(nil), d.Envelope...)
	file, err := os.Open(d.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	r := &mutatingDeliveryReader{Reader: file, mutate: func() { d.Envelope[len(d.Envelope)-1] ^= 1 }}
	if _, err := f.receiver.Receive(context.Background(), IdentityOf(f.report.Attempt), d.Envelope, r); err != nil {
		t.Fatal(err)
	}
	var stored []byte
	if err := f.receiver.DB.QueryRow("SELECT manifest_json FROM execution_delivery_receipts").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, original) {
		t.Fatal("caller changed manifest after authentication")
	}
}

func TestDeliveryRejectsForeignReceiptSigner(t *testing.T) {
	f := testDelivery(t)
	d := f.prepare(t, "first")
	raw := f.receive(t, d)
	var r DeliveryReceipt
	if _, err := verifyDelivery(raw, f.sender.ReceiverKey, receiptPredicate, &r); err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := signDelivery(receiptPredicate, d.Manifest.ID, d.ManifestSHA256, r, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.sender.Acknowledge(context.Background(), f.principal, d.Manifest.ID, forged); !errors.Is(err, ErrForbidden) {
		t.Fatalf("foreign receipt key: %v", err)
	}
	saved, err := f.sender.Get(context.Background(), f.principal, d.Manifest.ID)
	if err != nil || len(saved.Receipt) != 0 {
		t.Fatalf("foreign signer changed outbox: %v", err)
	}
}
