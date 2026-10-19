package agentcontext

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func TestSessionEnumerationPagesDeduplicateAndVerifyLatest(t *testing.T) {
	s, ctx := testService(t), context.Background()
	for i := 0; i < 405; i++ {
		src := testSource()
		src.SessionID = fmt.Sprintf("session-%03d", i)
		for _, channel := range []string{"transcript", "hooks"} {
			src.Channel = channel
			if _, err := s.Save(ctx, "run", src, nil, Coverage{Status: OK}); err != nil {
				t.Fatal(err)
			}
		}
	}
	src := testSource()
	src.Harness, src.SessionID = "claude", "session-404"
	if _, err := s.Save(ctx, "run", src, nil, Coverage{Status: OK}); err != nil {
		t.Fatal(err)
	}
	// Multiple reports for one source still enumerate one latest identity.
	if _, err := s.Save(ctx, "run", src, nil, Coverage{Status: Partial}); err != nil {
		t.Fatal(err)
	}
	for _, channel := range []string{"processing", "discovery", "runtime_correlation"} {
		src := testSource()
		src.Channel = channel
		if _, err := s.Save(ctx, "run", src, nil, Coverage{Status: Partial}); err != nil {
			t.Fatal(err)
		}
	}
	for _, harness := range []string{"unknown", "launch"} {
		src := testSource()
		src.Harness = harness
		if _, err := s.Save(ctx, "run", src, nil, Coverage{Status: Partial}); err != nil {
			t.Fatal(err)
		}
	}
	src = testSource()
	src.SessionID = ""
	if _, err := s.Save(ctx, "run", src, nil, Coverage{Status: Partial}); err != nil {
		t.Fatal(err)
	}
	want := []SessionIdentity{{Harness: "claude", SessionID: "session-404"}}
	for i := 0; i < 405; i++ {
		want = append(want, SessionIdentity{"codex", fmt.Sprintf("session-%03d", i)})
	}
	for i := 0; i < 2; i++ {
		got, err := s.EnumerateSessions(ctx, SessionEnumerationOptions{RunID: "run", MaxSources: 817, MaxSessions: 406})
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("complete deduplicated catalog: got=%d want=%d err=%v", len(got), len(want), err)
		}
	}
	// Cancel during verification, after enumeration has already started, rather
	// than relying on timing a goroutine against a small SQLite fixture.
	base, cancel := context.WithCancel(ctx)
	defer cancel()
	canceled := &enumerationCancelContext{Context: base, cancel: cancel}
	canceled.remaining.Store(50)
	if got, err := s.EnumerateSessions(canceled, SessionEnumerationOptions{RunID: "run"}); !errors.Is(err, context.Canceled) || got != nil {
		t.Fatalf("mid-enumeration cancellation returned partial catalog: %d %v", len(got), err)
	}
	for _, opts := range []SessionEnumerationOptions{{RunID: "run", MaxSources: 816}, {RunID: "run", MaxSessions: 405}} {
		got, err := s.EnumerateSessions(ctx, opts)
		if !errors.Is(err, ErrSessionEnumerationLimit) || got != nil {
			t.Fatalf("budget returned partial success: %d %v", len(got), err)
		}
	}
	got, err := s.EnumerateSessions(ctx, SessionEnumerationOptions{RunID: "other-run"})
	if err != nil || len(got) != 0 {
		t.Fatalf("cross-run leak: %v %v", got, err)
	}
	// Corruption beyond the first page must fail the complete operation.
	if _, err := s.DB.Exec(`UPDATE agent_context_reports SET harness='forged' WHERE source_id=(SELECT MAX(source_id) FROM agent_context_reports WHERE run_id='run')`); err != nil {
		t.Fatal(err)
	}
	got, err = s.EnumerateSessions(ctx, SessionEnumerationOptions{RunID: "run"})
	if err == nil || !strings.Contains(err.Error(), "identity mismatch") || got != nil {
		t.Fatalf("tail corruption hidden: %d %v", len(got), err)
	}
}

type enumerationCancelContext struct {
	context.Context
	cancel    context.CancelFunc
	remaining atomic.Int32
}

func (c *enumerationCancelContext) Err() error {
	if c.remaining.Add(-1) <= 0 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestSessionEnumerationInvalidCanceledAndStoreFailures(t *testing.T) {
	s := testService(t)
	for _, opts := range []SessionEnumerationOptions{{}, {RunID: strings.Repeat("r", 513)}, {RunID: "run", MaxSources: -1}, {RunID: "run", MaxSources: sessionEnumerationMaxSources + 1}, {RunID: "run", MaxSessions: -1}, {RunID: "run", MaxSessions: sessionEnumerationMaxSessions + 1}} {
		if _, err := s.EnumerateSessions(context.Background(), opts); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("invalid arguments accepted: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := s.EnumerateSessions(ctx, SessionEnumerationOptions{RunID: "run"}); !errors.Is(err, context.Canceled) || got != nil {
		t.Fatalf("cancellation hidden: %v %v", got, err)
	}
	if _, err := s.DB.Exec(`DROP TABLE agent_context_reports`); err != nil {
		t.Fatal(err)
	}
	if got, err := s.EnumerateSessions(context.Background(), SessionEnumerationOptions{RunID: "run"}); err == nil || got != nil {
		t.Fatalf("store failure hidden: %v %v", got, err)
	}
}

func TestSessionEnumerationUsesIndexRangeAndRejectsEmptySource(t *testing.T) {
	s := testService(t)
	rows, err := s.DB.Query("EXPLAIN QUERY PLAN "+sessionEnumerationPageSQL, "run", "source-after-first-page", sessionEnumerationPageSize)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if strings.Contains(detail, "SEARCH r ") && strings.Contains(detail, "source_id>?") {
			found = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil || !found {
		t.Fatalf("pagination must seek rather than rescan the run: found=%v err=%v", found, err)
	}
	if _, err := s.Save(context.Background(), "run", testSource(), nil, Coverage{Status: OK}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE agent_context_reports SET source_id='' WHERE run_id='run'`); err != nil {
		t.Fatal(err)
	}
	got, err := s.EnumerateSessions(context.Background(), SessionEnumerationOptions{RunID: "run"})
	if err == nil || got != nil || !strings.Contains(err.Error(), "source count mismatch") {
		t.Fatalf("empty source vanished silently: %v %v", got, err)
	}
}
