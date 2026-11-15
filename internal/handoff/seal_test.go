package handoff

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

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
