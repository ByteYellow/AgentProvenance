package handoff

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/store"
)

func testLedger(t *testing.T) (Ledger, Principal, Request, store.Paths) {
	t.Helper()
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	r := fixtureRequest()
	l := Ledger{DB: db, Target: r.Target, Now: func() time.Time { return r.ValidUntil.Add(-time.Hour) }}
	return l, fixturePrincipal(r), r, paths
}

func rowCount(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestAdmissionSurvivesReopen(t *testing.T) {
	l, p, r, paths := testLedger(t)
	a, reused, err := l.Admit(context.Background(), p, r)
	if err != nil || reused || a.State != InitialState() || a.Number != 1 {
		t.Fatalf("admission: %+v %t %v", a, reused, err)
	}
	if err := l.DB.Close(); err != nil {
		t.Fatal(err)
	}
	l.DB, err = store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer l.DB.Close()
	got, reused, err := l.Admit(context.Background(), p, r)
	if err != nil || !reused || got.ID != a.ID || got.LocalRunID != a.LocalRunID || got.RequestHash != a.RequestHash {
		t.Fatalf("reopened admission duplicated: %+v %t %v", got, reused, err)
	}
	if rowCount(t, l.DB, "execution_attempts") != 1 || rowCount(t, l.DB, "execution_attempt_history") != 1 {
		t.Fatal("network retry duplicated ledger/history")
	}
	if rowCount(t, l.DB, "tool_calls") != 0 {
		t.Fatal("admission started recording a command")
	}
}

func TestConcurrentAdmissionAndClaim(t *testing.T) {
	l, p, r, _ := testLedger(t)
	const n = 32
	var wg sync.WaitGroup
	type result struct {
		a     Attempt
		reuse bool
		err   error
	}
	results := make(chan result, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, reuse, err := l.Admit(context.Background(), p, r)
			results <- result{a, reuse, err}
		}()
	}
	wg.Wait()
	close(results)
	var admitted Attempt
	newCount := 0
	for got := range results {
		if got.err != nil {
			t.Fatal(got.err)
		}
		if admitted.ID != "" && got.a.ID != admitted.ID {
			t.Fatal("same operation created different attempts")
		}
		admitted = got.a
		if !got.reuse {
			newCount++
		}
	}
	if newCount != 1 {
		t.Fatalf("new admissions = %d", newCount)
	}
	claims := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := l.AdvanceExecution(context.Background(), admitted.ID, 1, Starting, "executor_claim", nil)
			claims <- err
		}()
	}
	wg.Wait()
	close(claims)
	winners := 0
	for err := range claims {
		if err == nil {
			winners++
		} else if !errors.Is(err, ErrStale) {
			t.Fatal(err)
		}
	}
	if winners != 1 || rowCount(t, l.DB, "execution_attempt_history") != 2 {
		t.Fatalf("claim winners=%d", winners)
	}
}

func TestConflictsAndIsolation(t *testing.T) {
	l, p, r, _ := testLedger(t)
	ctx := context.Background()
	a, _, err := l.Admit(ctx, p, r)
	if err != nil {
		t.Fatal(err)
	}
	changed := r
	changed.Command.Argv = []string{"python3", "different.py"}
	if _, _, err := l.Admit(ctx, p, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed request = %v", err)
	}
	changed = r
	changed.OperationID = "different-operation"
	if _, _, err := l.Admit(ctx, p, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("silent reexecution = %v", err)
	}
	changed.Source.SessionID = "another-session"
	if _, _, err := l.Admit(ctx, p, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("dispatch reassigned to another session: %v", err)
	}
	changed = r
	changed.Source.ProducerID = "other-producer"
	if _, _, err := l.Admit(ctx, p, changed); !errors.Is(err, ErrForbidden) {
		t.Fatalf("producer spoof = %v", err)
	}
	other := fixturePrincipal(changed)
	b, _, err := l.Admit(ctx, other, changed)
	if err != nil || a.ID == b.ID || a.LocalRunID == b.LocalRunID {
		t.Fatalf("valid producers were not isolated: %+v %v", b, err)
	}
	if _, err := l.Get(ctx, other, a.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("cross-source query = %v", err)
	}
	changed = r
	changed.Target.Generation = "cloned-generation"
	other = fixturePrincipal(changed)
	if _, _, err := l.Admit(ctx, other, changed); !errors.Is(err, ErrForbidden) {
		t.Fatalf("wrong executor generation = %v", err)
	}
	other = p
	other.ID = "different-principal"
	if _, _, err := l.Admit(ctx, other, r); !errors.Is(err, ErrForbidden) {
		t.Fatalf("principal changed on retry = %v", err)
	}
}

func TestExplicitReexecutionIsItselfIdempotent(t *testing.T) {
	l, p, r, _ := testLedger(t)
	ctx := context.Background()
	a, _, err := l.Admit(ctx, p, r)
	if err != nil {
		t.Fatal(err)
	}
	a, err = l.AdvanceExecution(ctx, a.ID, a.Revision, Starting, "claim", nil)
	if err != nil {
		t.Fatal(err)
	}
	a, err = l.AdvanceExecution(ctx, a.ID, a.Revision, Unknown, "executor_restarted", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.AdvanceExecution(ctx, a.ID, a.Revision, Accepted, "auto_retry", nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("unknown attempt automatically requeued: %v", err)
	}
	retry := r
	retry.OperationID, retry.PreviousAttemptID = "explicit-reexecute-1", a.ID
	b, reused, err := l.Admit(ctx, p, retry)
	if err != nil || reused || b.Number != 2 || b.LocalRunID == a.LocalRunID {
		t.Fatalf("explicit retry: %+v %t %v", b, reused, err)
	}
	for i := 0; i < 4; i++ {
		got, reused, err := l.Admit(ctx, p, retry)
		if err != nil || !reused || got.ID != b.ID {
			t.Fatalf("reexecution network retry duplicated: %+v %v", got, err)
		}
	}
	retry.OperationID = "explicit-reexecute-2"
	if _, _, err := l.Admit(ctx, p, retry); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale previous attempt accepted: %v", err)
	}
	retry.PreviousAttemptID = b.ID
	if _, _, err := l.Admit(ctx, p, retry); !errors.Is(err, ErrConflict) {
		t.Fatalf("active attempt reexecuted: %v", err)
	}
	if rowCount(t, l.DB, "execution_attempts") != 2 {
		t.Fatal("wrong attempt count")
	}
}

func TestExpiryRejectsOldRequestsEvenWithoutDedupRows(t *testing.T) {
	l, p, r, _ := testLedger(t)
	ctx := context.Background()
	a, _, err := l.Admit(ctx, p, r)
	if err != nil {
		t.Fatal(err)
	}
	l.Now = func() time.Time { return r.ValidUntil }
	if _, _, err := l.Admit(ctx, p, r); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired retry = %v", err)
	}
	if _, err := l.Get(ctx, p, a.ID); err != nil {
		t.Fatalf("expiry hid historical result: %v", err)
	}
	for _, table := range []string{"execution_attempt_history", "execution_attempts", "execution_dispatches"} {
		if _, err := l.DB.Exec("DELETE FROM " + table); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := l.Admit(ctx, p, r); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired request became a new execution: %v", err)
	}
	l.Now = func() time.Time { return r.ValidUntil.Add(-48 * time.Hour) }
	if _, _, err := l.Admit(ctx, p, r); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unbounded replay validity = %v", err)
	}
}

func TestHistoryFailureRollsBackAdmissionAndTransition(t *testing.T) {
	l, p, r, _ := testLedger(t)
	ctx := context.Background()
	install := func() {
		t.Helper()
		if _, err := l.DB.Exec(`CREATE TRIGGER fail_history BEFORE INSERT ON execution_attempt_history BEGIN SELECT RAISE(ABORT,'test history failure'); END`); err != nil {
			t.Fatal(err)
		}
	}
	install()
	if _, _, err := l.Admit(ctx, p, r); err == nil {
		t.Fatal("history failure swallowed")
	}
	if rowCount(t, l.DB, "execution_dispatches") != 0 || rowCount(t, l.DB, "execution_attempts") != 0 {
		t.Fatal("partial admission committed")
	}
	if _, err := l.DB.Exec(`DROP TRIGGER fail_history`); err != nil {
		t.Fatal(err)
	}
	a, _, err := l.Admit(ctx, p, r)
	if err != nil {
		t.Fatal(err)
	}
	install()
	if _, err := l.AdvanceExecution(ctx, a.ID, a.Revision, Starting, "claim", nil); err == nil {
		t.Fatal("transition history failure swallowed")
	}
	got, err := l.Get(ctx, p, a.ID)
	if err != nil || got.Revision != 1 || got.State != InitialState() {
		t.Fatalf("partial transition committed: %+v %v", got, err)
	}
}

func TestExecutionEvidenceAndBoundedQuery(t *testing.T) {
	l, p, r, _ := testLedger(t)
	ctx := context.Background()
	a, _, err := l.Admit(ctx, p, r)
	if err != nil {
		t.Fatal(err)
	}
	a, err = l.AdvanceExecution(ctx, a.ID, a.Revision, Starting, "claim", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.AdvanceExecution(ctx, a.ID, a.Revision, Running, "started", nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("running without evidence = %v", err)
	}
	a, err = l.AdvanceExecution(ctx, a.ID, a.Revision, Running, "started", []string{"binding:1", "event:exec_start"})
	if err != nil {
		t.Fatal(err)
	}
	a, err = l.AdvanceExecution(ctx, a.ID, a.Revision, Succeeded, "exited", []string{"event:exec_end"})
	if err != nil || a.State.Capture != NotReady || a.State.Delivery != Pending {
		t.Fatalf("execution manufactured collection/delivery: %+v %v", a.State, err)
	}
	for i := 2; i < 8; i++ {
		next := r
		next.DispatchID, next.OperationID = fmt.Sprintf("dispatch-%d", i), fmt.Sprintf("operation-%d", i)
		if _, _, err := l.Admit(ctx, p, next); err != nil {
			t.Fatal(err)
		}
	}
	var after int64
	seen := map[string]bool{}
	for {
		page, err := l.List(ctx, p, r.Source, after, 2)
		if err != nil || len(page.Attempts) > 2 {
			t.Fatalf("page: %+v %v", page, err)
		}
		for _, item := range page.Attempts {
			if seen[item.ID] {
				t.Fatalf("duplicate page item %s", item.ID)
			}
			seen[item.ID] = true
		}
		if page.NextAfter == 0 {
			break
		}
		after = page.NextAfter
	}
	if len(seen) != 7 {
		t.Fatalf("pagination lost attempts: %d", len(seen))
	}
	other := r.Source
	other.Harness = "claude"
	page, err := l.List(ctx, p, other, 0, 100)
	if err != nil || len(page.Attempts) != 0 {
		t.Fatalf("same native IDs leaked across harness: %+v %v", page, err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := l.List(cancelled, p, r.Source, 0, 10); !errors.Is(err, context.Canceled) {
		t.Fatalf("query cancellation = %v", err)
	}
	got, err := l.Get(ctx, p, a.ID)
	if err != nil || got.State.Execution != Succeeded {
		t.Fatalf("query cancellation altered execution: %+v %v", got, err)
	}
	if _, err := l.List(ctx, p, r.Source, 0, 101); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unbounded page = %v", err)
	}
}

func TestDatabaseErrorsRemainErrors(t *testing.T) {
	l, p, r, _ := testLedger(t)
	if err := l.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.Admit(context.Background(), p, r); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("database failure became missing record: %v", err)
	}
}
