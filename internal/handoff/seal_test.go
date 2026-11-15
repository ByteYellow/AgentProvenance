package handoff

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func assertSealReceipts(t *testing.T, summary SealSummary, verified, pending int, complete bool) {
	t.Helper()
	raw, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["receipts_verified"] != float64(verified) || fields["receipts_pending"] != float64(pending) || fields["delivery_complete"] != complete {
		t.Fatalf("receipt summary: %s; want verified=%d pending=%d complete=%t", raw, verified, pending, complete)
	}
}

func TestSealStoppedChecksReceiptCompletion(t *testing.T) {
	f := testDelivery(t)
	ctx := context.Background()
	var item SealResult
	summary, err := f.sender.SealStopped(ctx, f.principal, "receipt-check", func(result SealResult) error { item = result; return nil })
	if err != nil || !summary.Complete || item.Delivery == nil {
		t.Fatalf("prepare: %+v %v", summary, err)
	}
	assertSealReceipts(t, summary, 0, 1, false)
	receipt := f.receive(t, *item.Delivery)
	if _, err := f.sender.Acknowledge(ctx, f.principal, item.Delivery.Manifest.ID, receipt); err != nil {
		t.Fatal(err)
	}
	before, err := f.sender.Ledger.Get(ctx, f.principal, item.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	summary, err = f.sender.SealStopped(ctx, f.principal, "receipt-check", nil)
	if err != nil || !summary.Complete || summary.Reused != 1 {
		t.Fatalf("receipt check: %+v %v", summary, err)
	}
	assertSealReceipts(t, summary, 1, 0, true)
	after, err := f.sender.Ledger.Get(ctx, f.principal, item.AttemptID)
	if err != nil || before.Revision != after.Revision || before.State != after.State {
		t.Fatalf("receipt check changed execution: %+v %v", after, err)
	}
}

func TestSealStoppedRequiresEveryReceiptInTheOperation(t *testing.T) {
	f := testDelivery(t)
	ctx := context.Background()
	r := f.report.Attempt.Request
	r.DispatchID, r.OperationID, r.Source.ToolCallID = "failed-call", "failed-command", "failed-call"
	r.Command = Command{Argv: []string{"sh", "-c", "printf 'expected failure' >&2; exit 7"}, DisableSnapshot: true, PostRootGraceMS: 1}
	a, _, err := f.sender.Ledger.Admit(ctx, f.principal, r)
	if err != nil {
		t.Fatal(err)
	}
	e := &Executor{Ledger: f.sender.Ledger, Paths: f.sender.Paths, PollInterval: 5 * time.Millisecond}
	stop := startExecutor(t, e)
	failed := waitExecution(t, e, f.principal, a.ID, Failed)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	var items []SealResult
	summary, err := f.sender.SealStopped(ctx, f.principal, "batch-stop", func(item SealResult) error { items = append(items, item); return nil })
	if err != nil || !summary.Complete || len(items) != 2 {
		t.Fatalf("batch prepare: %+v %v", summary, err)
	}
	assertSealReceipts(t, summary, 0, 2, false)
	for i, item := range items {
		original, err := f.sender.Ledger.Get(ctx, f.principal, item.AttemptID)
		if err != nil {
			t.Fatal(err)
		}
		copy := f
		copy.report.Attempt = original
		receipt := copy.receive(t, *item.Delivery)
		if _, err := f.sender.Acknowledge(ctx, f.principal, item.Delivery.Manifest.ID, receipt); err != nil {
			t.Fatal(err)
		}
		summary, err = f.sender.SealStopped(ctx, f.principal, "batch-stop", nil)
		if err != nil || !summary.Complete || summary.Reused != 2 {
			t.Fatalf("batch check: %+v %v", summary, err)
		}
		assertSealReceipts(t, summary, i+1, 1-i, i == 1)
	}
	actual, err := f.sender.Ledger.Get(ctx, f.principal, a.ID)
	if err != nil || actual.State.Execution != Failed || actual.State.Capture != failed.Attempt.State.Capture {
		t.Fatalf("receipt changed failed execution: %+v %v", actual, err)
	}
	// A new sealing pass has new immutable packages and needs its own receipts.
	summary, err = f.sender.SealStopped(ctx, f.principal, "later-stop", nil)
	if err != nil || !summary.Complete || summary.Prepared != 2 {
		t.Fatalf("later batch: %+v %v", summary, err)
	}
	assertSealReceipts(t, summary, 0, 2, false)
}

func TestSealStoppedRejectsInvalidSavedReceipt(t *testing.T) {
	for _, problem := range []string{"malformed", "wrong_signer", "wrong_receiver", "wrong_package", "wrong_generation", "wrong_subject", "current_pin_changed"} {
		t.Run(problem, func(t *testing.T) {
			f := testDelivery(t)
			ctx := context.Background()
			d := f.prepare(t, "receipt-check")
			raw := f.receive(t, d)
			if _, err := f.sender.Acknowledge(ctx, f.principal, d.Manifest.ID, raw); err != nil {
				t.Fatal(err)
			}
			var receipt DeliveryReceipt
			if _, err := verifyDelivery(raw, f.sender.ReceiverKey, receiptPredicate, &receipt); err != nil {
				t.Fatal(err)
			}
			key, subject := f.receiver.SignKey, d.Manifest.ID
			switch problem {
			case "wrong_signer":
				key = f.sender.SignKey
			case "wrong_receiver":
				receipt.ReceiverID = "another-receiver"
			case "wrong_package":
				receipt.PackageVersion++
			case "wrong_generation":
				receipt.Identity.Target.Generation = "another-generation"
			case "wrong_subject":
				subject = "another-delivery"
			case "current_pin_changed":
				f.sender.ReceiverKey = f.receiver.TargetKey
			}
			bad, err := signDelivery(receiptPredicate, subject, d.ManifestSHA256, receipt, key)
			if err != nil {
				t.Fatal(err)
			}
			if problem == "malformed" {
				bad = []byte(`{}`)
			}
			if _, err := f.sender.Ledger.DB.Exec("UPDATE execution_deliveries SET receipt_json=? WHERE id=?", bad, d.Manifest.ID); err != nil {
				t.Fatal(err)
			}
			var item SealResult
			summary, err := f.sender.SealStopped(ctx, f.principal, "receipt-check", func(result SealResult) error { item = result; return nil })
			if err == nil || summary.Complete || summary.Failed != 1 || item.Status != "failed" || item.Error == "" {
				t.Fatalf("invalid saved receipt accepted: %+v %v", summary, err)
			}
			assertSealReceipts(t, summary, 0, 0, false)
			if _, err := f.sender.Acknowledge(ctx, f.principal, d.Manifest.ID, raw); err == nil {
				t.Fatal("acknowledgment retry accepted a damaged saved receipt")
			}
		})
	}
}

func TestSealStoppedRealCommandAndIdempotentRetry(t *testing.T) {
	f := testDelivery(t)
	f.sender.Ledger.DB.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var first SealResult
	summary, err := f.sender.SealStopped(ctx, f.principal, "guest-stop", func(item SealResult) error { first = item; return nil })
	if err != nil || !summary.Complete || summary.Attempts != 1 || summary.Prepared != 1 || first.Status != "prepared" || first.Delivery == nil {
		t.Fatalf("seal: %+v %+v %v", summary, first, err)
	}
	if first.Delivery.Manifest.State.Capture != f.report.Attempt.State.Capture || first.Delivery.Manifest.State.Execution != Succeeded {
		t.Fatal("sealing changed execution or capture evidence")
	}
	var replay SealResult
	again, err := f.sender.SealStopped(ctx, f.principal, "guest-stop", func(item SealResult) error { replay = item; return nil })
	if err != nil || !again.Complete || again.Prepared != 0 || again.Reused != 1 || replay.Status != "reused" ||
		!bytes.Equal(first.Delivery.Envelope, replay.Delivery.Envelope) || first.BundlePath != replay.BundlePath {
		t.Fatalf("retry: %+v %+v %v", again, replay, err)
	}
	a, err := f.sender.Ledger.Get(ctx, f.principal, first.AttemptID)
	if err != nil || a.State.Delivery != Transferring {
		t.Fatalf("local preparation must not acknowledge delivery: %+v %v", a.State, err)
	}
	receipt := f.receive(t, *first.Delivery)
	if _, err := f.sender.Acknowledge(ctx, f.principal, first.Delivery.Manifest.ID, receipt); err != nil {
		t.Fatal(err)
	}
	acknowledged, err := f.sender.SealStopped(ctx, f.principal, "guest-stop", func(item SealResult) error {
		if item.Delivery == nil || !bytes.Equal(item.Delivery.Receipt, receipt) {
			t.Fatal("acknowledged package lost its receipt")
		}
		return nil
	})
	if err != nil || !acknowledged.Complete || acknowledged.Reused != 1 {
		t.Fatalf("acknowledged retry: %+v %v", acknowledged, err)
	}
}

func TestSealStoppedReportsAllProblemsWithoutStartingCommands(t *testing.T) {
	f := testDelivery(t)
	ctx := context.Background()
	r := f.report.Attempt.Request
	r.OperationID, r.DispatchID, r.Source.ToolCallID = "pending", "pending", "pending"
	a, _, err := f.sender.Ledger.Admit(ctx, f.principal, r)
	if err != nil {
		t.Fatal(err)
	}
	r.OperationID, r.DispatchID, r.Source.ToolCallID = "no-checkpoint", "no-checkpoint", "no-checkpoint"
	missing, _, err := f.sender.Ledger.Admit(ctx, f.principal, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.sender.Ledger.AdvanceExecution(ctx, missing.ID, missing.Revision, Failed, "fixture_failure", []string{"fixture/no-checkpoint"}); err != nil {
		t.Fatal(err)
	}
	seen := map[string]SealResult{}
	summary, err := f.sender.SealStopped(ctx, f.principal, "partial-stop", func(item SealResult) error { seen[item.AttemptID] = item; return nil })
	if err == nil || summary.Complete || summary.Attempts != 3 || summary.Prepared != 1 || summary.Unfinished != 1 || summary.Failed != 1 {
		t.Fatalf("partial seal: %+v %v", summary, err)
	}
	if seen[a.ID].Status != "unfinished" || seen[missing.ID].Status != "failed" || seen[missing.ID].Error == "" {
		t.Fatalf("missing failure reasons: %+v", seen)
	}
	unchanged, err := f.sender.Ledger.Get(ctx, f.principal, a.ID)
	if err != nil || unchanged.State.Execution != Accepted || unchanged.Revision != a.Revision {
		t.Fatalf("pending task changed: %+v %v", unchanged, err)
	}
}

func TestSealStoppedScopesTargetGenerationAndCaller(t *testing.T) {
	f := testDelivery(t)
	ctx := context.Background()
	for _, dimension := range []string{"target_producer", "instance", "generation", "principal", "source_producer", "namespace"} {
		r, p, ledger := f.report.Attempt.Request, f.principal, f.sender.Ledger
		r.OperationID, r.DispatchID = dimension, dimension
		switch dimension {
		case "target_producer":
			r.Target.ProducerID = "other"
		case "instance":
			r.Target.InstanceID = "other"
		case "generation":
			r.Target.Generation = "other"
		case "principal":
			p.ID = "other"
		case "source_producer":
			r.Source.ProducerID, p.ProducerID = "other", "other"
		case "namespace":
			r.Source.Namespace, p.Namespace = "other", "other"
		}
		ledger.Target, p.AllowedTargets = r.Target, []Target{r.Target}
		if _, _, err := ledger.Admit(ctx, p, r); err != nil {
			t.Fatal(err)
		}
	}
	var items []SealResult
	summary, err := f.sender.SealStopped(ctx, f.principal, "own-only", func(item SealResult) error { items = append(items, item); return nil })
	if err != nil || !summary.Complete || summary.Attempts != 1 || len(items) != 1 || items[0].AttemptID != f.report.Attempt.ID {
		t.Fatalf("scope: %+v %+v %v", summary, items, err)
	}
	wrong := f.principal
	wrong.AllowedTargets = nil
	if _, err := f.sender.SealStopped(ctx, wrong, "forbidden", nil); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unauthorized seal: %v", err)
	}
}

func TestSealStoppedPaginatesUnfinishedAttempts(t *testing.T) {
	f := testDelivery(t)
	ctx := context.Background()
	for i := 0; i < 205; i++ {
		r := f.report.Attempt.Request
		r.DispatchID, r.OperationID, r.Source.ToolCallID = fmt.Sprintf("seal-pending-%d", i), fmt.Sprintf("seal-operation-%d", i), fmt.Sprintf("seal-call-%d", i)
		if _, _, err := f.sender.Ledger.Admit(ctx, f.principal, r); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	summary, err := f.sender.SealStopped(ctx, f.principal, "all-pages", func(item SealResult) error {
		if seen[item.AttemptID] {
			t.Fatal("duplicate attempt across pages")
		}
		seen[item.AttemptID] = true
		return nil
	})
	if !errors.Is(err, ErrConflict) || summary.Complete || summary.Attempts != 206 || summary.Unfinished != 205 || summary.Prepared != 1 || len(seen) != 206 {
		t.Fatalf("page enumeration: %+v count=%d %v", summary, len(seen), err)
	}
}

func TestSealStoppedRequiresExclusiveExecutor(t *testing.T) {
	f := testDelivery(t)
	e := &Executor{Ledger: f.sender.Ledger, Paths: f.sender.Paths}
	stop := startExecutor(t, e)
	defer stop()
	summary, err := f.sender.SealStopped(context.Background(), f.principal, "active", nil)
	if err == nil || !strings.Contains(err.Error(), "requires a stopped executor") || summary.Complete || summary.Attempts != 0 {
		t.Fatalf("active executor: %+v %v", summary, err)
	}
}

func TestSealStoppedCancellationAndOutputFailure(t *testing.T) {
	f := testDelivery(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if summary, err := f.sender.SealStopped(ctx, f.principal, "cancelled", nil); !errors.Is(err, context.Canceled) || summary.Attempts != 0 || summary.Complete {
		t.Fatalf("cancelled: %+v %v", summary, err)
	}
	failure := errors.New("output unavailable")
	summary, err := f.sender.SealStopped(context.Background(), f.principal, "broken-output", func(SealResult) error { return failure })
	if !errors.Is(err, failure) || summary.Complete || summary.Prepared != 1 {
		t.Fatalf("output failure: %+v %v", summary, err)
	}
	retry, err := f.sender.SealStopped(context.Background(), f.principal, "broken-output", nil)
	if err != nil || !retry.Complete || retry.Prepared != 0 || retry.Reused != 1 {
		t.Fatalf("output retry duplicated package: %+v %v", retry, err)
	}
}

func TestSealStoppedSurfacesCorruptExistingPackageAndDatabaseFailure(t *testing.T) {
	f := testDelivery(t)
	delivery := f.prepare(t, "shutdown")
	if err := os.WriteFile(delivery.BundlePath, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	summary, err := f.sender.SealStopped(context.Background(), f.principal, "shutdown", nil)
	if err == nil || summary.Complete || summary.Failed != 1 || summary.Reused != 0 {
		t.Fatalf("corrupt package: %+v %v", summary, err)
	}
	if err := f.sender.Ledger.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if summary, err := f.sender.SealStopped(context.Background(), f.principal, "closed-db", nil); err == nil || summary.Complete {
		t.Fatalf("unreadable database reported complete: %+v %v", summary, err)
	}
}
