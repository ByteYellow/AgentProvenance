package telemetry

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNativePrefixDoesNotConsumeLaterBatches(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{BatchEvents: 1})
	nativeBind(t, db, "first", "run-first")
	nativeBind(t, db, "later", "run-later")
	nativeWrite(t, n, "first", "/tmp/first")
	prefix, err := n.SnapshotPrefix(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	nativeWrite(t, n, "later", "/tmp/later")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	progress, err := n.DrainPrefix(ctx, prefix)
	if err != nil {
		t.Fatal(err)
	}
	if progress.State != "settled" || progress.Events != 1 || progress.Ingested != 1 || progress.Pending != 0 {
		t.Fatalf("progress=%+v", progress)
	}
	var first, later int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id='run-first'`).Scan(&first); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id='run-later'`).Scan(&later); err != nil {
		t.Fatal(err)
	}
	if first != 1 || later != 0 {
		t.Fatalf("fixed-prefix drain consumed later work: first=%d later=%d", first, later)
	}
}

func TestNativePrefixPartialInputAndOwnedSnapshot(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{})
	if _, err := n.Write([]byte(`{"event_type":"file_write",`)); err != nil {
		t.Fatal(err)
	}
	if _, err := n.SnapshotPrefix(context.Background()); err == nil {
		t.Fatal("checkpoint accepted a partial input line")
	}
	if _, err := n.Write([]byte(`"path":"/tmp/first"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	p, err := n.SnapshotPrefix(context.Background())
	if err != nil || p.Sequence != 1 || len(p.Batches) != 1 || p.Counters["captured"] != 1 {
		t.Fatalf("prefix=%+v error=%v", p, err)
	}
	nativeWrite(t, n, "later", "/tmp/later")
	next, err := n.SnapshotPrefix(context.Background())
	if err != nil || next.Sequence != 2 || next.Counters["captured"] != 2 || len(next.Batches) != 2 {
		t.Fatalf("next=%+v error=%v", next, err)
	}
	if p.Sequence != 1 || p.Counters["captured"] != 1 || len(p.Batches) != 1 {
		t.Fatal("later capture changed the saved prefix")
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := n.SnapshotPrefix(context.Background()); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed checkpoint: %v", err)
	}
	if _, err := n.DrainPrefix(context.Background(), p); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed collector processed backlog: %v", err)
	}
}

func TestNativePrefixDeadlineRetainsLateBinding(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{Ingest: JSONLIngestOptions{DropUncorrelated: true}, PendingTTL: time.Hour})
	nativeWrite(t, n, "late", "/tmp/late")
	p, err := n.SnapshotPrefix(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var expires int64
	if err := db.QueryRow(`SELECT expires_at FROM telemetry_spool_batches WHERE id=?`, p.Batches[0].ID).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	progress, err := n.DrainPrefix(ctx, p)
	if !errors.Is(err, context.DeadlineExceeded) || progress.State != "pending" || progress.Pending != 1 || progress.Dropped != 0 {
		t.Fatalf("progress=%+v error=%v", progress, err)
	}
	var unchanged int64
	var path string
	if err := db.QueryRow(`SELECT expires_at,spool_path FROM telemetry_spool_batches WHERE id=?`, p.Batches[0].ID).Scan(&unchanged, &path); err != nil {
		t.Fatal(err)
	}
	if unchanged != expires {
		t.Fatal("drain changed the pending binding deadline")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	nativeBind(t, db, "late", "run-late")
	progress, err = n.DrainPrefix(context.Background(), p)
	if err != nil || progress.State != "settled" || progress.Ingested != 1 || progress.Dropped != 0 {
		t.Fatalf("late progress=%+v error=%v", progress, err)
	}
}

func TestNativePrefixPreservesLossOutcomes(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{BatchEvents: 1, MaxQueuedBatches: 1, Ingest: JSONLIngestOptions{DropUncorrelated: true}})
	nativeWrite(t, n, "unknown", "/tmp/accepted")
	nativeWrite(t, n, "unknown", "/tmp/queue-rejected")
	if _, err := n.Write([]byte("invalid-json\n")); err != nil {
		t.Fatal(err)
	}
	p, err := n.SnapshotPrefix(context.Background())
	if err != nil || p.Sequence != 1 || p.Counters["dropped_queue_full"] != 1 || p.Counters["invalid"] != 1 {
		t.Fatalf("prefix=%+v error=%v", p, err)
	}
	if _, err := db.Exec(`UPDATE telemetry_spool_batches SET expires_at=0 WHERE id=?`, p.Batches[0].ID); err != nil {
		t.Fatal(err)
	}
	progress, err := n.DrainPrefix(context.Background(), p)
	if err != nil || progress.State != "settled" || progress.Dropped != 1 || progress.Ingested != 0 || progress.Pending != 0 {
		t.Fatalf("loss was hidden: %+v error=%v", progress, err)
	}
}

func TestNativePrefixRestartAndCleanup(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{})
	nativeBind(t, db, "first", "run-first")
	nativeWrite(t, n, "first", "/tmp/first")
	p, err := n.SnapshotPrefix(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	next := nativeTestStream(t, db, paths, NativeStreamOptions{})
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	if next.producerID == p.CollectorID {
		t.Fatal("restart reused the accepting process epoch")
	}
	progress, err := next.DrainPrefix(context.Background(), p)
	if err != nil || progress.State != "settled" || progress.Ingested != 1 {
		t.Fatalf("progress=%+v error=%v", progress, err)
	}
	var path string
	if err := db.QueryRow(`SELECT spool_path FROM telemetry_spool_batches WHERE id=?`, p.Batches[0].ID).Scan(&path); err != nil || path != "" {
		t.Fatalf("payload retained: %q %v", path, err)
	}
	progress, err = ReadNativePrefix(context.Background(), db, p)
	if err != nil || progress.State != "settled" || progress.Ingested != 1 {
		t.Fatalf("cleanup lost prefix outcomes: %+v %v", progress, err)
	}
	current, err := next.SnapshotPrefix(context.Background())
	if err != nil || current.Sequence != 0 || current.Counters["captured"] != 1 || len(current.Batches) != 0 {
		t.Fatalf("restart snapshot=%+v error=%v", current, err)
	}
}

func TestNativePrefixRejectsChangedMetadata(t *testing.T) {
	for _, mutation := range []string{
		`DELETE FROM telemetry_spool_batches`,
		`UPDATE telemetry_spool_batches SET file_sha256='changed'`,
		`UPDATE telemetry_spool_batches SET event_count=0`,
		`UPDATE telemetry_spool_batches SET format='falco'`,
		`UPDATE telemetry_spool_batches SET status='dropped'`,
		`UPDATE telemetry_spool_batches SET status='processed'`,
		`UPDATE telemetry_spool_batches SET ingested_count=-1`,
		`UPDATE telemetry_spool_batches SET dropped_count=2`,
	} {
		t.Run(mutation, func(t *testing.T) {
			db, paths := nativeTestStore(t)
			n := nativeTestStream(t, db, paths, NativeStreamOptions{})
			nativeWrite(t, n, "first", "/tmp/first")
			p, err := n.SnapshotPrefix(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			progress, err := ReadNativePrefix(context.Background(), db, p)
			if err == nil || progress.State == "settled" {
				t.Fatalf("invalid metadata became a settled prefix: %+v %v", progress, err)
			}
		})
	}
}

func TestNativePrefixFailureRequeuesOnlyClaimedBatch(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{})
	nativeWrite(t, n, "first", "/tmp/first")
	p, err := n.SnapshotPrefix(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER fail_event BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'prefix event failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := n.DrainPrefix(context.Background(), p); err == nil || !strings.Contains(err.Error(), "prefix event failure") {
		t.Fatalf("injected failure: %v", err)
	}
	var state, problem string
	if err := db.QueryRow(`SELECT status,error FROM telemetry_spool_batches WHERE id=?`, p.Batches[0].ID).Scan(&state, &problem); err != nil {
		t.Fatal(err)
	}
	if state != "queued" || !strings.Contains(problem, "prefix event failure") {
		t.Fatalf("failed batch was stranded: state=%s error=%s", state, problem)
	}
	if _, err := db.Exec(`DROP TRIGGER fail_event`); err != nil {
		t.Fatal(err)
	}
	progress, err := n.DrainPrefix(context.Background(), p)
	if err != nil || progress.Ingested != 1 || progress.State != "settled" {
		t.Fatalf("retry: %+v %v", progress, err)
	}
}

func TestNativePrefixCleanupFailureRemainsVisible(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{})
	nativeWrite(t, n, "first", "/tmp/first")
	p, err := n.SnapshotPrefix(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	n.removeFile = func(string) error { return fmt.Errorf("prefix cleanup failure") }
	if _, err := n.DrainPrefix(context.Background(), p); err == nil {
		t.Fatal("cleanup failure was swallowed")
	}
	progress, err := ReadNativePrefix(context.Background(), db, p)
	if err != nil || progress.State != "settled" || progress.CleanupPending != 1 || progress.Ingested != 1 || !strings.Contains(progress.LastError, "prefix cleanup failure") {
		t.Fatalf("cleanup status=%+v error=%v", progress, err)
	}
}

func TestNativePrefixConcurrentDrainsAndCapture(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{BatchEvents: 1, FlushInterval: time.Millisecond})
	for i := 0; i < 8; i++ {
		nativeWrite(t, n, "known", fmt.Sprintf("/tmp/first-%d", i))
	}
	p, err := n.SnapshotPrefix(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- n.Run(ctx, nil) }()
	var work sync.WaitGroup
	errors := make(chan error, 3)
	for range 2 {
		work.Add(1)
		go func() {
			defer work.Done()
			progress, err := n.DrainPrefix(ctx, p)
			if err == nil && (progress.State != "settled" || progress.Ingested != 8) {
				err = fmt.Errorf("unexpected prefix progress: %+v", progress)
			}
			errors <- err
		}()
	}
	work.Add(1)
	go func() {
		defer work.Done()
		for i := 0; i < 24; i++ {
			if _, err := n.Write([]byte(fmt.Sprintf(`{"event_type":"file_write","path":"/tmp/later-%d"}`+"\n", i))); err != nil {
				errors <- err
				return
			}
		}
		errors <- nil
	}()
	work.Wait()
	cancel()
	if err := <-runDone; err != nil {
		t.Fatal(err)
	}
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := n.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&count); err != nil || count != 32 {
		t.Fatalf("concurrent replay duplicated evidence: %d %v", count, err)
	}
}

func TestNativePrefixPagesAndBounds(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{BatchEvents: 1})
	nativeWrite(t, n, "first", "/tmp/first")
	p, err := n.SnapshotPrefix(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	batch := p.Batches[0]
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < 260; i++ {
		id := fmt.Sprintf("native-page-%04d", i)
		if _, err := tx.Exec(`INSERT INTO telemetry_spool_batches(id,format,spool_path,file_sha256,event_count,status,ingested_count,created_at,updated_at)
			VALUES (?,'native','',?,1,'processed',1,'now','now')`, id, batch.SHA256); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		p.Batches = append(p.Batches, NativePrefixBatch{ID: id, SHA256: batch.SHA256, EventCount: 1})
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	progress, err := n.DrainPrefix(context.Background(), p)
	if err != nil || progress.Batches != 260 || progress.Ingested != 260 || progress.State != "settled" {
		t.Fatalf("paged progress=%+v error=%v", progress, err)
	}
	p.Batches = append(p.Batches, batch)
	if _, err := ReadNativePrefix(context.Background(), db, p); err == nil {
		t.Fatal("duplicate checkpoint batch accepted")
	}
	p.Batches = make([]NativePrefixBatch, maxNativePrefixBatches+1)
	if _, err := ReadNativePrefix(context.Background(), db, p); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("checkpoint overflow: %v", err)
	}
}

func TestNativePrefixSnapshotDoesNotTruncate(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{})
	_, err := db.Exec(`WITH RECURSIVE batches(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM batches WHERE n<=?)
		INSERT INTO telemetry_spool_batches(id,format,spool_path,file_sha256,event_count,status,created_at,updated_at)
		SELECT 'native-limit-'||n,'native','pending',?,0,'queued','now','now' FROM batches`,
		maxNativePrefixBatches, strings.Repeat("0", 64))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.SnapshotPrefix(context.Background()); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized checkpoint silently truncated: %v", err)
	}
}

func TestNativePrefixReportsCommittedChunkOnFailure(t *testing.T) {
	nativeReportsCommittedChunkOnFailure(t, false)
}

func TestNativeScopeReportsCommittedChunkOnFailure(t *testing.T) {
	nativeReportsCommittedChunkOnFailure(t, true)
}

func nativeReportsCommittedChunkOnFailure(t *testing.T, scoped bool) {
	t.Helper()
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{BatchEvents: 32})
	start := scopeSnapshot(t, n)
	for i := 0; i < 20; i++ {
		nativeWrite(t, n, "first", fmt.Sprintf("/tmp/chunk-%d", i))
	}
	p, err := n.SnapshotPrefix(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	drain := func() (NativePrefixProgress, error) { return n.DrainPrefix(context.Background(), p) }
	if scoped {
		rangePrefix := scopeRange(t, n, start, p, "first")
		drain = func() (NativePrefixProgress, error) { return n.DrainScopePrefix(context.Background(), rangePrefix) }
	}
	// The time budget may commit fewer than 16 rows. Fail only after the first
	// transaction updates its durable count, independent of scheduling speed.
	if _, err := db.Exec(`CREATE TRIGGER fail_later_chunk BEFORE INSERT ON events
		WHEN (SELECT SUM(ingested_count) FROM telemetry_spool_batches)>0
		BEGIN SELECT RAISE(ABORT,'later chunk failure'); END`); err != nil {
		t.Fatal(err)
	}
	progress, err := drain()
	var committed, receipts, counted int64
	if readErr := db.QueryRow(`SELECT (SELECT COUNT(*) FROM events),
		(SELECT COUNT(*) FROM telemetry_native_rows),
		(SELECT SUM(ingested_count) FROM telemetry_native_scope_counts)`).Scan(&committed, &receipts, &counted); readErr != nil {
		t.Fatal(readErr)
	}
	if committed < 1 || committed > maxNativeTransactionRows || receipts != committed || counted != committed {
		t.Fatalf("partial transaction receipts diverged: events=%d receipts=%d scope=%d", committed, receipts, counted)
	}
	if err == nil || !strings.Contains(err.Error(), "later chunk failure") || progress.Ingested != committed ||
		progress.Pending != 20-committed || progress.State != "pending" || progress.Events != 20 || progress.Failed != 0 || progress.Dropped != 0 {
		t.Fatalf("partial committed=%d progress=%+v error=%v", committed, progress, err)
	}
	if _, err := db.Exec(`DROP TRIGGER fail_later_chunk`); err != nil {
		t.Fatal(err)
	}
	progress, err = drain()
	if err != nil || progress.Ingested != 20 || progress.State != "settled" {
		t.Fatalf("retry progress=%+v error=%v", progress, err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&count); err != nil || count != 20 {
		t.Fatalf("committed chunk was duplicated: %d %v", count, err)
	}
}

func TestNativePrefixCancelledSnapshotAndExplicitEventID(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{})
	if _, err := n.Write([]byte(`{"event_id":"provided-id","event_type":"file_write","path":"/tmp/provided"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := n.SnapshotPrefix(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled checkpoint: %v", err)
	}
	p, err := n.SnapshotPrefix(context.Background())
	if err != nil || p.Sequence != 1 || len(p.Batches) != 1 {
		t.Fatalf("explicit ID was absent from the accepted sequence: %+v %v", p, err)
	}
	if _, err := n.DrainPrefix(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	var id string
	if err := db.QueryRow(`SELECT raw_event_id FROM events`).Scan(&id); err != nil || id != "provided-id" {
		t.Fatalf("explicit identity changed: %q %v", id, err)
	}
}

// An autocommit can finish before the driver reports cancellation. Exercise
// that exact boundary instead of depending on a scheduler race at a deadline.
type nativeClaimFaultConnector struct {
	driver driver.Driver
	dsn    string
	fired  atomic.Bool
	rows   bool
	reset  atomic.Bool
	block  func()
}

func (c *nativeClaimFaultConnector) Driver() driver.Driver { return c.driver }
func (c *nativeClaimFaultConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := c.driver.Open(c.dsn)
	if err != nil {
		return nil, err
	}
	return &nativeClaimFaultConn{Conn: conn, fault: c}, nil
}

type nativeClaimFaultConn struct {
	driver.Conn
	fault *nativeClaimFaultConnector
}

func (c *nativeClaimFaultConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
}

func (c *nativeClaimFaultConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
}

func (c *nativeClaimFaultConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if strings.Contains(query, "status=CASE WHEN status='processing'") && c.fault.reset.CompareAndSwap(true, false) {
		return nil, errors.New("claim reset storage failure")
	}
	result, err := c.Conn.(driver.ExecerContext).ExecContext(ctx, query, args)
	if err == nil && strings.HasPrefix(query, "UPDATE telemetry_spool_batches SET status='processing'") && c.fault.fired.CompareAndSwap(false, true) {
		if c.fault.block != nil {
			c.fault.block()
		}
		if c.fault.rows {
			return nativeClaimFaultResult{Result: result}, nil
		}
		return nil, context.DeadlineExceeded
	}
	return result, err
}

func TestNativePrefixUnacknowledgedClaimKeepsWorkerOwnership(t *testing.T) {
	db, paths := nativeTestStore(t)
	n := nativeTestStream(t, db, paths, NativeStreamOptions{})
	nativeBind(t, db, "claim", "run-claim")
	nativeWrite(t, n, "claim", "/tmp/claim")
	prefix, err := n.SnapshotPrefix(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	claimed, release := make(chan struct{}), make(chan struct{})
	fault := &nativeClaimFaultConnector{driver: db.Driver(), dsn: paths.DB,
		block: func() { close(claimed); <-release }}
	fault.reset.Store(true)
	faultDB := sql.OpenDB(fault)
	n.service.DB = faultDB
	t.Cleanup(func() { n.service.DB = db; faultDB.Close() })
	done := make(chan error, 1)
	go func() { done <- n.processBatchContext(context.Background(), prefix.Batches[0].ID) }()
	<-claimed
	var secondErr error
	func() {
		defer close(release)
		secondErr = n.processBatchContext(context.Background(), prefix.Batches[0].ID)
		var attempts int
		if err := db.QueryRow(`SELECT attempts FROM telemetry_spool_batches WHERE id=?`, prefix.Batches[0].ID).Scan(&attempts); err != nil || attempts != 1 {
			t.Errorf("second worker stole an unacknowledged claim: attempts=%d error=%v", attempts, err)
		}
	}()
	firstErr := <-done
	if secondErr != nil || !errors.Is(firstErr, context.DeadlineExceeded) || !strings.Contains(firstErr.Error(), "claim reset storage failure") {
		t.Fatalf("first=%v second=%v", firstErr, secondErr)
	}
	var state string
	if err := db.QueryRow(`SELECT status FROM telemetry_spool_batches WHERE id=?`, prefix.Batches[0].ID).Scan(&state); err != nil || state != "processing" {
		t.Fatalf("failed-reset fixture state=%s error=%v", state, err)
	}
	progress, err := n.DrainPrefix(context.Background(), prefix)
	if err != nil || progress.State != "settled" || progress.Ingested != 1 {
		t.Fatalf("ownerless claim recovery=%+v error=%v", progress, err)
	}
}

type nativeClaimFaultResult struct{ driver.Result }

func (nativeClaimFaultResult) RowsAffected() (int64, error) { return 0, context.DeadlineExceeded }

func TestNativePrefixClaimResultFailureRemainsRetryable(t *testing.T) {
	for _, rows := range []bool{false, true} {
		t.Run(fmt.Sprintf("rows_result=%t", rows), func(t *testing.T) {
			db, paths := nativeTestStore(t)
			n := nativeTestStream(t, db, paths, NativeStreamOptions{})
			nativeBind(t, db, "claim", "run-claim")
			nativeWrite(t, n, "claim", "/tmp/claim")
			prefix, err := n.SnapshotPrefix(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			fault := &nativeClaimFaultConnector{driver: db.Driver(), dsn: paths.DB, rows: rows}
			faultDB := sql.OpenDB(fault)
			n.service.DB = faultDB
			t.Cleanup(func() { n.service.DB = db; faultDB.Close() })
			progress, err := n.DrainPrefix(context.Background(), prefix)
			if !fault.fired.Load() || !errors.Is(err, context.DeadlineExceeded) || progress.Pending != 1 {
				t.Fatalf("claim fault was not observed: %+v %v", progress, err)
			}
			var state string
			if err := db.QueryRow(`SELECT status FROM telemetry_spool_batches WHERE id=?`, prefix.Batches[0].ID).Scan(&state); err != nil || state != "queued" {
				t.Fatalf("unacknowledged claim stranded the batch: %q %v", state, err)
			}
			progress, err = n.DrainPrefix(context.Background(), prefix)
			if err != nil || progress.State != "settled" || progress.Ingested != 1 {
				t.Fatalf("claim recovery=%+v error=%v", progress, err)
			}
		})
	}
}
