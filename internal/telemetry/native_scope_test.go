package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func scopeSnapshot(t *testing.T, n *NativeStream) NativePrefix {
	t.Helper()
	p, err := n.SnapshotPrefix(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func scopeRange(t *testing.T, n *NativeStream, start, end NativePrefix, group string) NativeScopePrefix {
	t.Helper()
	p, err := n.SnapshotScopePrefix(context.Background(), start, end, group)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNativeScopeObservedAccessState(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{Ingest: JSONLIngestOptions{DropUncorrelated: true}, PendingTTL: time.Hour})
	nativeBind(t, db, "5", "run-owned")
	start := scopeSnapshot(t, n)
	for _, group := range []string{"5", "6"} {
		state := strings.ReplaceAll(stateFixture, `"cgroup_id":"5"`, `"cgroup_id":"`+group+`"`)
		state = strings.ReplaceAll(state, "2026-10-19", "2026-09-19")
		line := `{"source":"procfs_access_control","event_type":"access_control_state","cgroup_id":"` + group + `","timestamp":"2026-09-19T00:00:00.01Z","state":` + state + "}\n"
		if _, err := n.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	end := scopeSnapshot(t, n)
	p := scopeRange(t, n, start, end, "5")
	if len(p.Batches) != 1 || p.Batches[0].Matched != 1 || p.Batches[0].Unscoped != 0 {
		t.Fatalf("observed procfs membership lost: %+v", p)
	}
	r, err := n.DrainScopePrefix(context.Background(), p)
	if err != nil || r.Ingested != 1 || r.Pending != 0 || r.State != "settled" {
		t.Fatalf("owned procfs state did not settle: %+v %v", r, err)
	}
	shared, err := ReadNativePrefix(context.Background(), db, end)
	if err != nil || shared.Pending != 1 {
		t.Fatalf("unrelated procfs state was removed: %+v %v", shared, err)
	}
	var process, tool string
	if err := db.QueryRow(`SELECT process_id,tool_call_id FROM events WHERE run_id='run-owned'`).Scan(&process, &tool); err != nil || process != "" || tool != "" {
		t.Fatalf("accounting changed procfs attribution: process=%s tool=%s %v", process, tool, err)
	}
}

func TestNativeScopeConcurrentIntervals(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{Ingest: JSONLIngestOptions{DropUncorrelated: true}, PendingTTL: time.Hour})
	nativeBind(t, db, "a", "run-a")
	nativeBind(t, db, "b", "run-b")
	aStart := scopeSnapshot(t, n)
	nativeWrite(t, n, "a", "/tmp/a1")
	bStart := scopeSnapshot(t, n)
	nativeWrite(t, n, "a", "/tmp/a2")
	nativeWrite(t, n, "b", "/tmp/b1")
	nativeWrite(t, n, "other", "/tmp/other")
	aEnd := scopeSnapshot(t, n)
	nativeWrite(t, n, "b", "/tmp/b2")
	bEnd := scopeSnapshot(t, n)
	for group, interval := range map[string][2]NativePrefix{"a": {aStart, aEnd}, "b": {bStart, bEnd}} {
		p := scopeRange(t, n, interval[0], interval[1], group)
		r, err := n.DrainScopePrefix(context.Background(), p)
		if err != nil || r.Events != 2 || r.Ingested != 2 || r.Pending != 0 || r.Dropped != 0 || r.State != "settled" {
			t.Fatalf("concurrent %s: %+v %v", group, r, err)
		}
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id=?`, "run-"+group).Scan(&count); err != nil || count != 2 {
			t.Fatalf("scope %s borrowed events: %d %v", group, count, err)
		}
	}
	shared, err := ReadNativePrefix(context.Background(), db, bEnd)
	if err != nil || shared.Pending != 1 || shared.Ingested != 4 {
		t.Fatalf("concurrent drain changed unrelated backlog: %+v %v", shared, err)
	}
}

func TestNativeScopeLegacyQueuedReplay(t *testing.T) {
	db, paths := nativeTestStore(t)
	opts := NativeStreamOptions{Ingest: JSONLIngestOptions{DropUncorrelated: true}, PendingTTL: time.Hour}
	n := nativeTestStream(t, db, paths, opts)
	nativeBind(t, db, "ready", "run-ready")
	nativeWrite(t, n, "ready", "/tmp/ready")
	nativeWrite(t, n, "late", "/tmp/late")
	p := scopeSnapshot(t, n)
	if err := n.processBatch(p.Batches[0].ID); err != nil {
		t.Fatal(err)
	}
	// Schema-23 queued batches have row receipts, but no scope metadata.
	for _, stmt := range []string{`UPDATE telemetry_spool_batches SET native_collector_id='',native_first_sequence=0`, `DELETE FROM telemetry_native_scope_counts`} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	nativeBind(t, db, "late", "run-late")
	restarted := nativeTestStream(t, db, paths, opts)
	if _, err := restarted.DrainPrefix(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("legacy replay lost or duplicated events: %d %v", count, err)
	}
	progress, err := ReadNativePrefix(context.Background(), db, p)
	if err != nil || progress.Ingested != 2 || progress.State != "settled" {
		t.Fatalf("legacy prefix did not finish: %+v %v", progress, err)
	}
}

func TestNativeScopePrefixIntervalAndUnrelatedRows(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{Ingest: JSONLIngestOptions{DropUncorrelated: true}, PendingTTL: time.Hour})
	nativeBind(t, db, "owned", "run-owned")
	nativeWrite(t, n, "owned", "/tmp/before")
	start := scopeSnapshot(t, n)
	nativeWrite(t, n, "owned", "/tmp/current")
	nativeWrite(t, n, "other", "/tmp/unrelated")
	end := scopeSnapshot(t, n)
	nativeWrite(t, n, "owned", "/tmp/after")
	p := scopeRange(t, n, start, end, "owned")
	if len(p.Batches) != 1 || p.Batches[0].Matched != 1 || p.Batches[0].Unscoped != 0 || p.After != 1 || p.Through != 3 {
		t.Fatalf("wrong scope interval: %+v", p)
	}
	progress, err := n.DrainScopePrefix(context.Background(), p)
	if err != nil || progress.State != "settled" || progress.Ingested != 1 || progress.Events != 1 || progress.Pending != 0 {
		t.Fatalf("owned progress: %+v %v", progress, err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("consumed before/after boundary: %d %v", count, err)
	}
	shared, err := ReadNativePrefix(context.Background(), db, end)
	if err != nil || shared.Pending != 2 {
		t.Fatalf("unrelated backlog lost: %+v %v", shared, err)
	}
	// Only the unrelated row in this batch expires. Its loss must remain in
	// shared statistics without changing the already committed owned outcome.
	if _, err := db.Exec(`UPDATE telemetry_spool_batches SET expires_at=0 WHERE id=?`, p.Batches[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := n.processBatch(p.Batches[0].ID); err != nil {
		t.Fatal(err)
	}
	progress, err = ReadNativeScopePrefix(context.Background(), db, p)
	if err != nil || progress.State != "settled" || progress.Ingested != 1 || progress.Dropped != 0 {
		t.Fatalf("unrelated expiry changed owned outcome: %+v %v", progress, err)
	}
	var payload string
	if err := db.QueryRow(`SELECT spool_path FROM telemetry_spool_batches WHERE id=?`, p.Batches[0].ID).Scan(&payload); err != nil || payload != "" {
		t.Fatalf("processed payload not removed: %q %v", payload, err)
	}
	serialized, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	next := nativeTestStream(t, db, paths, NativeStreamOptions{Ingest: JSONLIngestOptions{DropUncorrelated: true}})
	var saved NativeScopePrefix
	if err := json.Unmarshal(serialized, &saved); err != nil {
		t.Fatal(err)
	}
	progress, err = ReadNativeScopePrefix(context.Background(), db, saved)
	if err != nil || progress.Ingested != 1 || progress.Dropped != 0 {
		t.Fatalf("restart lost scope outcome: %+v %v", progress, err)
	}
	restartStart := scopeSnapshot(t, next)
	nativeWrite(t, next, "owned", "/tmp/new-epoch")
	restartEnd := scopeSnapshot(t, next)
	restarted := scopeRange(t, next, restartStart, restartEnd, "owned")
	if restarted.CollectorID == p.CollectorID || restarted.After != 0 || restarted.Through != 1 || len(restarted.Batches) != 1 {
		t.Fatalf("reused cgroup borrowed previous epoch: %+v", restarted)
	}
	if _, err := next.SnapshotScopePrefix(context.Background(), start, restartEnd, "owned"); err == nil {
		t.Fatal("mixed collector epochs accepted")
	}
}

func TestNativeScopePrefixLateAndUnscopedEvidence(t *testing.T) {
	for _, group := range []string{"owned", ""} {
		t.Run("group="+group, func(t *testing.T) {
			db, paths := nativeTestStore(t)
			n := nativeTestStream(t, db, paths, NativeStreamOptions{Ingest: JSONLIngestOptions{DropUncorrelated: true}, PendingTTL: time.Hour})
			start := scopeSnapshot(t, n)
			nativeWrite(t, n, group, "/tmp/late")
			end := scopeSnapshot(t, n)
			p := scopeRange(t, n, start, end, "owned")
			var expires int64
			if err := db.QueryRow(`SELECT expires_at FROM telemetry_spool_batches WHERE id=?`, p.Batches[0].ID).Scan(&expires); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
			defer cancel()
			progress, err := n.DrainScopePrefix(ctx, p)
			if !errors.Is(err, context.DeadlineExceeded) || progress.State != "pending" || progress.Pending != 1 {
				t.Fatalf("pending evidence was hidden: %+v %v", progress, err)
			}
			var after int64
			if err := db.QueryRow(`SELECT expires_at FROM telemetry_spool_batches WHERE id=?`, p.Batches[0].ID).Scan(&after); err != nil || after != expires {
				t.Fatalf("deadline changed retention: %d %d %v", expires, after, err)
			}
			if group != "" {
				nativeBind(t, db, group, "run-late")
				progress, err = n.DrainScopePrefix(context.Background(), p)
				if err != nil || progress.Ingested != 1 || progress.Dropped != 0 || progress.State != "settled" {
					t.Fatalf("late binding not recovered: %+v %v", progress, err)
				}
			} else {
				if p.Batches[0].Unscoped != 1 || p.Batches[0].Matched != 0 {
					t.Fatalf("unknown cgroup labeled owned: %+v", p)
				}
			}
		})
	}
}

func TestNativeScopePrefixRetainsAlreadyProcessedLoss(t *testing.T) {
	for _, group := range []string{"owned", "other", ""} {
		t.Run("group="+group, func(t *testing.T) {
			db, paths := nativeTestStore(t)
			n := nativeTestStream(t, db, paths, NativeStreamOptions{BatchEvents: 1, Ingest: JSONLIngestOptions{DropUncorrelated: true}})
			start := scopeSnapshot(t, n)
			nativeWrite(t, n, group, "/tmp/expired")
			if _, err := db.Exec(`UPDATE telemetry_spool_batches SET expires_at=0`); err != nil {
				t.Fatal(err)
			}
			if err := n.Process(32); err != nil {
				t.Fatal(err)
			}
			end := scopeSnapshot(t, n)
			if len(end.Batches) != 0 {
				t.Fatal("fixture batch was not cleaned")
			}
			p := scopeRange(t, n, start, end, "owned")
			progress, err := ReadNativeScopePrefix(context.Background(), db, p)
			want := int64(1)
			if group == "other" {
				want = 0
			}
			if err != nil || progress.State != "settled" || progress.Dropped != want || len(p.Batches) != 1 {
				t.Fatalf("processed loss misclassified: %+v %v", progress, err)
			}
		})
	}
}

func TestNativeScopePrefixMetadataAndAtomicOutcomes(t *testing.T) {
	for _, mutation := range []string{
		`DELETE FROM telemetry_native_scope_counts`,
		`UPDATE telemetry_native_scope_counts SET event_count=2`,
		`UPDATE telemetry_native_scope_counts SET ingested_count=-1`,
		`UPDATE telemetry_native_scope_counts SET ingested_count=1`,
		`UPDATE telemetry_spool_batches SET native_first_sequence=7`,
		`UPDATE telemetry_spool_batches SET native_collector_id='different'`,
		`DELETE FROM telemetry_spool_batches`,
	} {
		t.Run(mutation, func(t *testing.T) {
			db, paths := nativeTestStore(t)
			n := nativeTestStream(t, db, paths, NativeStreamOptions{})
			start := scopeSnapshot(t, n)
			nativeWrite(t, n, "owned", "/tmp/value")
			end := scopeSnapshot(t, n)
			p := scopeRange(t, n, start, end, "owned")
			if _, err := db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			progress, err := ReadNativeScopePrefix(context.Background(), db, p)
			if err == nil || progress.State == "settled" {
				t.Fatalf("corrupt metadata reported settled: %+v %v", progress, err)
			}
		})
	}
	t.Run("outcome_failure", func(t *testing.T) {
		db, paths := nativeTestStore(t)
		n := nativeTestStream(t, db, paths, NativeStreamOptions{})
		nativeBind(t, db, "owned", "run-owned")
		start := scopeSnapshot(t, n)
		nativeWrite(t, n, "owned", "/tmp/value")
		end := scopeSnapshot(t, n)
		p := scopeRange(t, n, start, end, "owned")
		if _, err := db.Exec(`CREATE TRIGGER fail_scope_outcome BEFORE UPDATE ON telemetry_native_scope_counts BEGIN SELECT RAISE(ABORT,'scope outcome failure'); END`); err != nil {
			t.Fatal(err)
		}
		if _, err := n.DrainScopePrefix(context.Background(), p); err == nil {
			t.Fatal("outcome persistence failure ignored")
		}
		for _, table := range []string{"events", "telemetry_native_rows"} {
			var count int
			if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil || count != 0 {
				t.Fatalf("partial commit in %s: %d %v", table, count, err)
			}
		}
		if _, err := db.Exec(`DROP TRIGGER fail_scope_outcome`); err != nil {
			t.Fatal(err)
		}
		progress, err := n.DrainScopePrefix(context.Background(), p)
		if err != nil || progress.Ingested != 1 || progress.Pending != 0 {
			t.Fatalf("outcome retry: %+v %v", progress, err)
		}
	})
}
