package telemetry

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/byteyellow/agentprovenance/internal/correlation"
	"github.com/byteyellow/agentprovenance/internal/i18n"
	"github.com/byteyellow/agentprovenance/internal/ids"
	"github.com/byteyellow/agentprovenance/internal/redact"
	"github.com/byteyellow/agentprovenance/internal/store"
)

// NativeStreamOptions bounds both resident memory and the on-disk backlog.
// PendingTTL starts at capture, not at replay, so restarts cannot renew it.
type NativeStreamOptions struct {
	Ingest           JSONLIngestOptions
	BatchEvents      int
	BatchBytes       int64
	FlushInterval    time.Duration
	PendingTTL       time.Duration
	MaxQueuedBytes   int64
	MaxQueuedBatches int
	PolicyEnabled    bool
}

func (o NativeStreamOptions) defaults() NativeStreamOptions {
	if o.BatchEvents == 0 {
		o.BatchEvents = 256
	}
	if o.BatchBytes == 0 {
		o.BatchBytes = 1 << 20
	}
	if o.FlushInterval == 0 {
		o.FlushInterval = time.Second
	}
	if o.PendingTTL == 0 {
		o.PendingTTL = 2 * time.Minute
	}
	if o.MaxQueuedBytes == 0 {
		o.MaxQueuedBytes = 256 << 20
	}
	if o.MaxQueuedBatches == 0 {
		o.MaxQueuedBatches = 4096
	}
	o.Ingest.Format = "native"
	return o
}

type NativeStreamStatus struct {
	Counters              map[string]int64 `json:"counters"`
	QueuedBatches         int              `json:"queued_batches"`
	QueuedBytes           int64            `json:"queued_bytes"`
	PendingEvents         int64            `json:"pending_events"`
	CleanupPendingBatches int              `json:"cleanup_pending_batches"`
	LastError             string           `json:"last_error,omitempty"`
}

// NativeStreamRunning tests the process-held collector lock; persisted probe
// reports alone are historical snapshots and cannot establish liveness.
func NativeStreamRunning(paths store.Paths) (bool, error) {
	return nativeStreamRunning(filepath.Join(paths.Spool, "native.lock"))
}

func ReadNativeStreamStatus(db *sql.DB) (NativeStreamStatus, error) {
	return ReadNativeStreamStatusContext(context.Background(), db)
}

func ReadNativeStreamStatusContext(ctx context.Context, db *sql.DB) (NativeStreamStatus, error) {
	out := NativeStreamStatus{Counters: map[string]int64{}}
	rows, err := db.QueryContext(ctx, `SELECT name, value FROM telemetry_native_counters`)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var key string
		var value int64
		if err := rows.Scan(&key, &value); err != nil {
			rows.Close()
			return out, err
		}
		out.Counters[key] = value
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	err = db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(size_bytes),0), COALESCE(SUM(event_count-ingested_count-dropped_count-failed_count),0), COALESCE(SUM(CASE WHEN status='processed' THEN 1 ELSE 0 END),0) FROM telemetry_spool_batches WHERE format='native' AND (status IN ('initializing','capturing','queued','processing') OR (status='processed' AND spool_path!=''))`).Scan(&out.QueuedBatches, &out.QueuedBytes, &out.PendingEvents, &out.CleanupPendingBatches)
	if err != nil {
		return out, err
	}
	var captured int64
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(SUM(event_count),0) FROM telemetry_spool_batches WHERE format='native'`).Scan(&captured); err != nil {
		return out, err
	}
	out.Counters["captured"] = captured
	err = db.QueryRowContext(ctx, `SELECT error FROM telemetry_spool_batches WHERE format='native' AND error!='' AND (status IN ('initializing','capturing','queued','processing') OR (status='processed' AND spool_path!='')) ORDER BY updated_at DESC LIMIT 1`).Scan(&out.LastError)
	if err != nil && err != sql.ErrNoRows {
		return out, err
	}
	return out, nil
}

// NativeStream accepts JSONL writes from the sensor, normalizes/redacts them
// before persistence, fsyncs accepted rows, and seals bounded spool batches.
// Only counters and one partial JSON line are retained in memory. A store lock
// prevents two collectors from reclaiming each other's in-flight batches.
type NativeStream struct {
	service    SpoolService
	opts       NativeStreamOptions
	mu         sync.Mutex
	file       *os.File
	id         string
	size       int64
	count      int
	partial    []byte
	counters   map[string]int64
	lock       *os.File
	closed     bool
	producerID string
	sequence   uint64
	removeFile func(string) error
}

func NewNativeStream(db *sql.DB, paths store.Paths, options NativeStreamOptions) (*NativeStream, error) {
	opts := options.defaults()
	if opts.BatchEvents < 1 || opts.BatchEvents > 4096 || opts.BatchBytes < 1024 || opts.BatchBytes > 16<<20 || opts.PendingTTL < time.Millisecond || opts.FlushInterval < time.Millisecond || opts.MaxQueuedBytes < opts.BatchBytes || opts.MaxQueuedBatches < 1 {
		return nil, i18n.Errorf("invalid native spool limits: batch events 1..4096, batch bytes 1 KiB..16 MiB, positive intervals, queue >= batch")
	}
	if err := os.MkdirAll(paths.Spool, 0o700); err != nil {
		return nil, err
	}
	lock, err := lockNativeStream(filepath.Join(paths.Spool, "native.lock"))
	if err != nil {
		return nil, err
	}
	n := &NativeStream{service: SpoolService{DB: db, Paths: paths}, opts: opts, counters: map[string]int64{}, lock: lock, producerID: ids.New("sensor")}
	if err := n.recover(); err != nil {
		n.lock.Close()
		return nil, err
	}
	return n, nil
}

func incrementNative(db sqlStore, name string, value int64) error {
	if value == 0 {
		return nil
	}
	_, err := db.Exec(`INSERT INTO telemetry_native_counters(name,value) VALUES (?,?) ON CONFLICT(name) DO UPDATE SET value=value+excluded.value`, name, value)
	return err
}

func (n *NativeStream) flushCounters() error {
	for name, value := range n.counters {
		if err := incrementNative(n.service.DB, name, value); err != nil {
			return err
		}
		delete(n.counters, name)
	}
	return nil
}

func (n *NativeStream) openBatch() error {
	// Reserve a whole batch: queue limits remain conservative even if the
	// process dies between a file write and updating its durable row count.
	// Successfully committed evidence does not free disk capacity until its
	// payload has actually been removed. Count cleanup failures as backlog too.
	var queued int
	var queuedBytes int64
	if err := n.service.DB.QueryRow(`SELECT COUNT(*),COALESCE(SUM(size_bytes),0) FROM telemetry_spool_batches WHERE status IN ('initializing','capturing','queued','processing') OR (format='native' AND status='processed' AND spool_path!='')`).Scan(&queued, &queuedBytes); err != nil {
		return err
	}
	if queued >= n.opts.MaxQueuedBatches || queuedBytes+n.opts.BatchBytes > n.opts.MaxQueuedBytes {
		return SpoolBackpressureError{Queued: queued, QueuedBytes: queuedBytes, IncomingBytes: n.opts.BatchBytes, MaxQueued: n.opts.MaxQueuedBatches, MaxQueuedBytes: n.opts.MaxQueuedBytes, MaxBatchBytes: n.opts.BatchBytes, Reason: "telemetry_native_spool_capacity_full"}
	}
	id := ids.New("native")
	path := filepath.Join(n.service.Paths.Spool, id+".jsonl")
	options, err := json.Marshal(n.opts)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	policy := 0
	if n.opts.PolicyEnabled {
		policy = 1
	}
	_, err = n.service.DB.Exec(`INSERT INTO telemetry_spool_batches (id,format,source_path,spool_path,status,size_bytes,native_options,expires_at,policy_enabled,created_at,updated_at) VALUES (?,'native','sensor:stream',?,'initializing',?,?,?,?,?,?)`, id, path, n.opts.BatchBytes, string(options), now.Add(n.opts.PendingTTL).UnixMilli(), policy, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := syncNativeDirectory(n.service.Paths.Spool); err != nil {
		f.Close()
		return err
	}
	if _, err := n.service.DB.Exec(`UPDATE telemetry_spool_batches SET status='capturing' WHERE id=? AND status='initializing'`, id); err != nil {
		f.Close()
		return err
	}
	n.file, n.id, n.size, n.count = f, id, 0, 0
	return nil
}

func (n *NativeStream) Write(p []byte) (int, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return 0, os.ErrClosed
	}
	// JSON encoders emit complete lines, but tolerate arbitrary io.Writer
	// splits without allowing a corrupt producer to grow memory without bound.
	for _, b := range p {
		if len(n.partial) >= 1<<20 {
			n.partial = nil
			if err := incrementNative(n.service.DB, "dropped_oversize", 1); err != nil {
				return 0, err
			}
			return 0, i18n.Errorf("native sensor JSON line exceeds 1 MiB")
		}
		if b != '\n' {
			n.partial = append(n.partial, b)
			continue
		}
		line := n.partial
		n.partial = nil
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if err := n.appendLine(line); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (n *NativeStream) appendLine(line []byte) error {
	n.counters["read"]++
	var raw map[string]any
	if err := json.Unmarshal(line, &raw); err != nil {
		n.counters["invalid"]++
		n.counters["invalid_json"]++
		return nil
	}
	event, ok, err := mapJSONLEvent(n.opts.Ingest, raw, 0)
	if err != nil {
		n.counters["invalid"]++
		n.counters["invalid_mapping"]++
		return nil
	}
	if !ok {
		n.counters["skipped"]++
		return nil
	}
	if n.opts.Ingest.excludeEvent(raw, event) {
		n.counters["excluded"]++
		return nil
	}
	if firstNonEmpty(stringAt(raw, "id"), stringAt(raw, "uuid"), stringAt(raw, "event_id")) == "" {
		// The generic JSONL mapper uses a file line number. A live stream has
		// many files, so retain a distinct producer-epoch/sequence identity.
		n.sequence++
		event.RawEventID = fmt.Sprintf("%s:%d", n.producerID, n.sequence)
	}
	if event.Timestamp == "" {
		event.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if _, err := time.Parse(time.RFC3339Nano, event.Timestamp); err != nil {
		n.counters["invalid"]++
		n.counters["invalid_timestamp"]++
		return nil
	}
	if err := ValidateRawPayload(event.EventType, event.Payload); err != nil {
		n.counters["invalid"]++
		// Native event types are a fixed allow-list, so diagnostic cardinality
		// stays bounded even during a long-running malformed input stream.
		n.counters["invalid_payload_"+event.EventType]++
		return nil
	}
	event.Payload = redact.RedactString(event.Payload)
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if int64(len(encoded)) > n.opts.BatchBytes || len(encoded) >= 1<<20 {
		return incrementNative(n.service.DB, "dropped_oversize", 1)
	}
	if n.file != nil && (n.count >= n.opts.BatchEvents || n.size+int64(len(encoded)) > n.opts.BatchBytes) {
		if err := n.seal(); err != nil {
			return err
		}
	}
	if n.file == nil {
		if err := n.openBatch(); err != nil {
			var pressure SpoolBackpressureError
			if errors.As(err, &pressure) {
				return incrementNative(n.service.DB, "dropped_queue_full", 1)
			}
			return err
		}
	}
	if _, err := n.file.Write(encoded); err != nil {
		return err
	}
	if err := n.file.Sync(); err != nil {
		return err
	}
	n.count++
	n.size += int64(len(encoded))
	n.counters["captured"]++
	if n.count >= n.opts.BatchEvents {
		return n.seal()
	}
	return nil
}

func (n *NativeStream) seal() error {
	if n.file == nil {
		return n.flushCounters()
	}
	if err := n.file.Sync(); err != nil {
		return err
	}
	if err := n.file.Close(); err != nil {
		return err
	}
	n.file = nil
	if err := n.sealFile(n.id); err != nil {
		return err
	}
	n.id, n.size, n.count = "", 0, 0
	return n.flushCounters()
}

func (n *NativeStream) sealFile(id string) error {
	var path string
	if err := n.service.DB.QueryRow(`SELECT spool_path FROM telemetry_spool_batches WHERE id=?`, id).Scan(&path); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return i18n.Errorf("native capture file %s is missing; captured evidence cannot be recovered", id)
		}
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() > 16<<20 {
		return i18n.Errorf("native capture file exceeds 16 MiB limit")
	}
	reader := bufio.NewReaderSize(f, 64*1024)
	hash := sha256.New()
	var size int64
	count := 0
	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) > 1<<20 {
			return i18n.Errorf("native spool row exceeds 1 MiB")
		}
		if readErr != nil {
			if readErr != io.EOF {
				return readErr
			}
			if len(line) != 0 {
				if err := f.Truncate(size); err != nil {
					return err
				}
				if err := f.Sync(); err != nil {
					return err
				}
				if err := incrementNative(n.service.DB, "dropped_partial_recovery", 1); err != nil {
					return err
				}
			}
			break
		}
		hash.Write(line)
		size += int64(len(line))
		count++
	}
	_, err = n.service.DB.Exec(`UPDATE telemetry_spool_batches SET status='queued',size_bytes=?,file_sha256=?,event_count=?,updated_at=? WHERE id=? AND status='capturing'`, size, hex.EncodeToString(hash.Sum(nil)), count, time.Now().UTC().Format(time.RFC3339Nano), id)
	return err
}

func (n *NativeStream) recover() error {
	// Page recovery metadata so even a store with years of processed batches
	// has bounded startup memory. Processed payload cleanup is deferred to
	// bounded runtime sweeps so a removal failure cannot block startup.
	cursor := ""
	for {
		rows, err := n.service.DB.Query(`SELECT id,status,spool_path FROM telemetry_spool_batches WHERE format='native' AND id>? AND status IN ('initializing','capturing','processing') ORDER BY id LIMIT 256`, cursor)
		if err != nil {
			return err
		}
		type item struct{ id, status, path string }
		pending := make([]item, 0, 256)
		for rows.Next() {
			var v item
			if err := rows.Scan(&v.id, &v.status, &v.path); err != nil {
				rows.Close()
				return err
			}
			pending = append(pending, v)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if len(pending) == 0 {
			return nil
		}
		for _, v := range pending {
			cursor = v.id
			switch v.status {
			case "initializing":
				// No producer row is accepted until creation and directory sync finish.
				info, err := os.Stat(v.path)
				if err != nil && !os.IsNotExist(err) {
					return err
				}
				if err == nil {
					if info.Size() != 0 {
						return i18n.Errorf("uninitialized native file unexpectedly contains data: %s", v.id)
					}
					if err := os.Remove(v.path); err != nil {
						return err
					}
					if err := syncNativeDirectory(n.service.Paths.Spool); err != nil {
						return err
					}
				}
				if _, err := n.service.DB.Exec(`DELETE FROM telemetry_spool_batches WHERE id=? AND status='initializing'`, v.id); err != nil {
					return err
				}
			case "capturing":
				if err := n.sealFile(v.id); err != nil {
					if _, writeErr := n.service.DB.Exec(`UPDATE telemetry_spool_batches SET error=? WHERE id=?`, err.Error(), v.id); writeErr != nil {
						return writeErr
					}
					return err
				}
			case "processing":
				if _, err := n.service.DB.Exec(`UPDATE telemetry_spool_batches SET status='queued',retry_at=0 WHERE id=?`, v.id); err != nil {
					return err
				}
			}
		}
	}
}

func (n *NativeStream) removeProcessedFile(id, path string) error {
	remove := n.removeFile
	if remove == nil {
		remove = os.Remove
	}
	if err := remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := syncNativeDirectory(n.service.Paths.Spool); err != nil {
		return err
	}
	_, err := n.service.DB.Exec(`UPDATE telemetry_spool_batches SET spool_path='',error='',retry_at=0 WHERE id=? AND status='processed'`, id)
	return err
}

func (n *NativeStream) cleanupProcessed(limit int) error {
	rows, err := n.service.DB.Query(`SELECT id,spool_path FROM telemetry_spool_batches WHERE format='native' AND status='processed' AND spool_path!='' AND retry_at<=? ORDER BY retry_at,updated_at LIMIT ?`, time.Now().UnixMilli(), limit)
	if err != nil {
		return err
	}
	type item struct{ id, path string }
	items := make([]item, 0, limit)
	for rows.Next() {
		var v item
		if err := rows.Scan(&v.id, &v.path); err != nil {
			rows.Close()
			return err
		}
		items = append(items, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	var firstErr error
	for _, v := range items {
		if err := n.removeProcessedFile(v.id, v.path); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			if _, updateErr := n.service.DB.Exec(`UPDATE telemetry_spool_batches SET error=?,retry_at=?,updated_at=? WHERE id=? AND status='processed' AND spool_path!=''`, err.Error(), time.Now().Add(5*time.Second).UnixMilli(), time.Now().UTC().Format(time.RFC3339Nano), v.id); updateErr != nil {
				return updateErr
			}
			if err := incrementNative(n.service.DB, "cleanup_failures", 1); err != nil {
				return err
			}
		}
	}
	return firstErr
}

// Flush seals live batches. Processing is independent of capture; a slow
// database fills the bounded disk queue rather than accumulating event IDs.
func (n *NativeStream) Flush() error { n.mu.Lock(); defer n.mu.Unlock(); return n.seal() }

func (n *NativeStream) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil
	}
	n.closed = true
	if len(n.partial) > 0 {
		n.counters["dropped_partial_shutdown"]++
		n.partial = nil
	}
	err := n.seal()
	if n.file != nil {
		n.file.Close()
		n.file = nil
	}
	lockErr := n.lock.Close()
	if err != nil {
		return err
	}
	return lockErr
}

// Run retries all eligible batches fairly: pending batches wait one second,
// while new batches remain immediately eligible. A failed batch stays queued
// and its error/counter are durable; shutdown leaves pending rows for restart.
func (n *NativeStream) Run(ctx context.Context, report func(error)) error {
	tick := time.NewTicker(n.opts.FlushInterval)
	defer tick.Stop()
	for {
		if err := n.Process(32); err != nil {
			if report != nil {
				report(err)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			if err := n.Flush(); err != nil {
				return err
			}
		}
	}
}

func (n *NativeStream) Process(limit int) error {
	if limit < 1 {
		limit = 32
	}
	firstErr := n.cleanupProcessed(limit)
	now := time.Now().UnixMilli()
	// Expired batches must not be starved by a continuous supply of fresh
	// batches; release their capacity before prioritizing new work.
	rows, err := n.service.DB.Query(`SELECT id FROM telemetry_spool_batches WHERE format='native' AND status='queued' AND retry_at<=? ORDER BY CASE WHEN expires_at<=? THEN 0 ELSE 1 END,retry_at,created_at LIMIT ?`, now, now, limit)
	if err != nil {
		return err
	}
	var batchIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		batchIDs = append(batchIDs, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range batchIDs {
		if err := n.processBatch(id); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			_, updateErr := n.service.DB.Exec(`UPDATE telemetry_spool_batches SET status='queued',error=?,retry_at=? WHERE id=? AND status='processing'`, err.Error(), time.Now().Add(5*time.Second).UnixMilli(), id)
			if updateErr != nil {
				return updateErr
			}
			if err := incrementNative(n.service.DB, "retry_failures", 1); err != nil {
				return err
			}
			// A cleanup error occurs after the evidence transaction committed;
			// keep it processed and retry only deletion, never event ingestion.
			if _, updateErr := n.service.DB.Exec(`UPDATE telemetry_spool_batches SET error=?,retry_at=?,updated_at=? WHERE id=? AND status='processed' AND spool_path!=''`, err.Error(), time.Now().Add(5*time.Second).UnixMilli(), time.Now().UTC().Format(time.RFC3339Nano), id); updateErr != nil {
				return updateErr
			}
		}
	}
	return firstErr
}

func (n *NativeStream) processBatch(id string) error {
	db := n.service.DB
	claim, err := db.Exec(`UPDATE telemetry_spool_batches SET status='processing',attempts=attempts+1 WHERE id=? AND status='queued'`, id)
	if err != nil {
		return err
	}
	affected, err := claim.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return nil
	}
	var path, expectedHash, optionsJSON string
	var expires int64
	var eventCount int
	if err := db.QueryRow(`SELECT spool_path,file_sha256,native_options,expires_at,event_count FROM telemetry_spool_batches WHERE id=?`, id).Scan(&path, &expectedHash, &optionsJSON, &expires, &eventCount); err != nil {
		return err
	}
	var opts NativeStreamOptions
	if err := json.Unmarshal([]byte(optionsJSON), &opts); err != nil {
		return err
	}
	if eventCount > 4096 {
		return i18n.Errorf("native spool batch exceeds event limit")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(f, (16<<20)+1)); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != expectedHash {
		return i18n.Errorf("native spool content hash mismatch: %s", id)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Obtain the SQLite writer lock before reading row receipts. Event insertion,
	// side effects, row receipts, windows and batch manifests commit together.
	if _, err := tx.Exec(`UPDATE telemetry_spool_batches SET updated_at=? WHERE id=?`, time.Now().UTC().Format(time.RFC3339Nano), id); err != nil {
		return err
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	line := 0
	ingested, dropped, failed, pending := 0, 0, 0, 0
	groups := map[string]*JSONLIngestResult{}
	for scanner.Scan() {
		line++
		var existing string
		err := tx.QueryRow(`SELECT outcome FROM telemetry_native_rows WHERE batch_id=? AND line=?`, id, line).Scan(&existing)
		if err == nil {
			continue
		}
		if err != sql.ErrNoRows {
			return err
		}
		var event IngestEvent
		outcome, eventID := "", ""
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			outcome = "invalid"
			failed++
		} else {
			if opts.Ingest.DropUncorrelated && event.EventType != "resource_pressure" {
				_, ok, err := correlation.Resolve(tx, correlation.RawIdentity{RunID: event.RunID, ProcessID: event.ProcessID, ContainerID: event.ContainerID, CgroupID: event.CgroupID, PID: event.PID, TGID: event.TGID, PPID: event.PPID, Timestamp: event.Timestamp})
				if err != nil {
					return err
				}
				if !ok && (event.RunID == "" || event.SessionID == "" || event.ToolCallID == "") {
					if time.Now().UnixMilli() < expires {
						pending++
						continue
					}
					outcome = "expired_uncorrelated"
					dropped++
				}
			}
			if outcome == "" {
				var err error
				eventID, err = ingestFilteredWithStore(tx, event)
				if err != nil {
					return err
				}
				record, err := eventRecordByID(tx, eventID)
				if err != nil {
					return err
				}
				if err := recordNativeCoverage(tx, event); err != nil {
					return err
				}
				if err := updateNativeWindows(tx, record); err != nil {
					return err
				}
				result := groups[record.RunID]
				if result == nil {
					result = &JSONLIngestResult{Format: "native", Path: path, FileSHA256: expectedHash}
					groups[record.RunID] = result
				}
				result.Read++
				result.Ingested++
				result.EventIDs = append(result.EventIDs, eventID)
				outcome = "ingested"
				ingested++
			}
		}
		if _, err := tx.Exec(`INSERT INTO telemetry_native_rows(batch_id,line,outcome,event_id) VALUES (?,?,?,?)`, id, line, outcome, eventID); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if line != eventCount {
		return i18n.Errorf("native spool row count mismatch")
	}
	for runID, result := range groups {
		result.EventIDsSHA256 = hashStrings(result.EventIDs)
		if err := persistJSONLBatch(tx, JSONLIngestOptions{RunID: runID}, result); err != nil {
			return err
		}
	}
	for name, count := range map[string]int{"ingested": ingested, "expired_uncorrelated": dropped, "invalid": failed} {
		if err := incrementNative(tx, name, int64(count)); err != nil {
			return err
		}
	}
	status := "queued"
	retry := time.Now().Add(time.Second).UnixMilli()
	processed := ""
	if pending == 0 {
		status = "processed"
		retry = 0
		processed = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if _, err := tx.Exec(`UPDATE telemetry_spool_batches SET status=?,retry_at=?,processed_at=?,ingested_count=ingested_count+?,dropped_count=dropped_count+?,failed_count=failed_count+?,error='' WHERE id=?`, status, retry, processed, ingested, dropped, failed, id); err != nil {
		return err
	}
	if pending == 0 {
		if _, err := tx.Exec(`DELETE FROM telemetry_native_rows WHERE batch_id=?`, id); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if pending == 0 {
		if err := n.removeProcessedFile(id, path); err != nil {
			return err
		}
	}
	if opts.PolicyEnabled {
		for _, result := range groups {
			evaluateSpoolPolicy(db, result)
			if err := incrementNative(db, "policy_failures", int64(result.Failed)); err != nil {
				return err
			}
			if err := incrementNative(db, "policy_decisions", int64(result.PolicyDecisions)); err != nil {
				return err
			}
		}
	}
	return nil
}

func updateNativeWindows(db sqlStore, record EventRecord) error {
	if record.RunID == "" {
		return nil
	}
	timestamp, err := time.Parse(time.RFC3339Nano, record.CreatedAt)
	if err != nil {
		return err
	}
	resolved, unresolved, high := 1, 0, 0
	if isUncorrelatedRecord(record) {
		resolved, unresolved = 0, 1
	}
	if highRiskWindowEvent(record.EventType) {
		high = 1
	}
	for _, seconds := range []int{10, 60} {
		_, err := db.Exec(`INSERT INTO telemetry_event_windows(run_id,session_id,tool_call_id,source,event_type,window_seconds,window_start,event_count,resolved_count,unresolved_count,high_risk_count,updated_at) VALUES (?,?,?,?,?,?,?,1,?,?,?,?) ON CONFLICT(run_id,session_id,tool_call_id,source,event_type,window_seconds,window_start) DO UPDATE SET event_count=event_count+1,resolved_count=resolved_count+excluded.resolved_count,unresolved_count=unresolved_count+excluded.unresolved_count,high_risk_count=high_risk_count+excluded.high_risk_count,updated_at=excluded.updated_at`, record.RunID, record.SessionID, record.ToolCallID, record.Source, record.EventType, seconds, timestamp.Truncate(time.Duration(seconds)*time.Second).UTC().Format(time.RFC3339Nano), resolved, unresolved, high, record.CreatedAt)
		if err != nil {
			return err
		}
	}
	return nil
}

func recordNativeCoverage(db sqlStore, event IngestEvent) error {
	var body struct {
		Resource          string `json:"resource"`
		Signal            string `json:"signal"`
		DroppedDelta      int64  `json:"dropped_delta"`
		DroppedBytesDelta int64  `json:"dropped_bytes_delta"`
		Truncated         bool   `json:"truncated"`
	}
	if event.EventType != "resource_pressure" && event.EventType != "tls_read" && event.EventType != "tls_write" {
		return nil
	}
	if err := json.Unmarshal([]byte(event.Payload), &body); err != nil {
		return err
	}
	if body.Truncated {
		if err := incrementNative(db, "tls_truncated_messages", 1); err != nil {
			return err
		}
	}
	if body.Resource == "sensor_ringbuf" && body.Signal == "event_drop" && body.DroppedDelta > 0 {
		return incrementNative(db, "kernel_dropped_events", body.DroppedDelta)
	}
	if body.Resource == "sensor_tls_reassembly" {
		if body.DroppedDelta > 0 {
			if err := incrementNative(db, "tls_reassembly_dropped_streams", body.DroppedDelta); err != nil {
				return err
			}
		}
		if body.DroppedBytesDelta > 0 {
			if err := incrementNative(db, "tls_reassembly_dropped_bytes", body.DroppedBytesDelta); err != nil {
				return err
			}
		}
	}
	return nil
}
