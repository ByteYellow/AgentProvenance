package telemetry

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/store"
)

const AuditCollectionSchema = "agentprovenance.audit_collection/v1"

type AuditFollowOptions struct {
	AuditIngestOptions
	ReaderID     string
	PollInterval time.Duration
	Once         bool
}

// These counters describe the selected source file, not every event the kernel
// could have audited. Unknown upstream loss is deliberately not a zero counter.
type AuditCollectionObservation struct {
	SchemaVersion      string `json:"schema_version"`
	EvidenceKind       string `json:"evidence_kind"`
	ReaderID           string `json:"reader_id"`
	SourcePath         string `json:"source_path"`
	Mechanism          string `json:"mechanism"`
	RawRecordsRetained bool   `json:"raw_records_retained"`
	Status             string `json:"status"`
	Reason             string `json:"reason"`
	CoverageScope      string `json:"coverage_scope"`
	UpstreamLoss       string `json:"upstream_loss"`
	ObservedAt         string `json:"observed_at"`
	LastStartAt        string `json:"last_start_at"`
	LastReadAt         string `json:"last_read_at,omitempty"`
	CommittedOffset    int64  `json:"committed_offset"`
	PendingBytes       int64  `json:"pending_bytes"`
	Read               int    `json:"read"`
	Ingested           int    `json:"ingested"`
	Duplicates         int    `json:"duplicates"`
	Skipped            int    `json:"skipped"`
	Failed             int    `json:"failed"`
	IdentityIncomplete int    `json:"identity_incomplete"`
	Batches            int    `json:"batches"`
	LastBatchID        string `json:"last_batch_id,omitempty"`
}

type AuditFollowStatus struct {
	SchemaVersion string                     `json:"schema_version"`
	RunID         string                     `json:"run_id"`
	Reader        AuditCollectionObservation `json:"reader"`
}

type auditCheckpoint struct {
	Version        int                        `json:"version"`
	Options        AuditIngestOptions         `json:"options"`
	Observation    AuditCollectionObservation `json:"observation"`
	FileIdentity   string                     `json:"file_identity"`
	HeadSHA256     string                     `json:"head_sha256"`
	TailSHA256     string                     `json:"tail_sha256"`
	LastEvidenceAt string                     `json:"last_evidence_at"`
	revision       int
}

// FollowAuditFile reads existing append-only audit text or journal JSON files.
// It uses the source as its durable queue, bounds each in-memory batch, and
// commits events, receipts and the source checkpoint together. It stops on
// rotation/truncation rather than guessing where an unread generation went.
func FollowAuditFile(ctx context.Context, db *sql.DB, paths store.Paths, opts AuditFollowOptions, report func(AuditFollowStatus) error) (AuditFollowStatus, error) {
	result := AuditFollowStatus{SchemaVersion: "agentprovenance.audit_reader/v1", RunID: opts.RunID}
	if db == nil || strings.TrimSpace(opts.RunID) == "" || len(opts.RunID) > 1024 || opts.Path == "" || opts.Path == "-" || len(opts.Path) > 4096 || len(opts.ReaderID) > 256 {
		return auditFollowFailure(result, "invalid_options", fmt.Errorf("audit following requires a database, run (up to 1024 bytes), file path (up to 4096 bytes) and reader id (up to 256 bytes)"))
	}
	if len(opts.Source.HostID) > 256 || len(opts.Source.BootID) > 64 || strings.ContainsAny(opts.Source.HostID+opts.Source.BootID+opts.RunID+opts.ReaderID+opts.Path, "\r\n\x00") {
		return auditFollowFailure(result, "invalid_options", fmt.Errorf("audit source identity or reader options are invalid"))
	}
	if opts.Mechanism == "" {
		opts.Mechanism = "all"
	}
	if opts.Mechanism != "all" && opts.Mechanism != "apparmor" && opts.Mechanism != "seccomp" {
		return auditFollowFailure(result, "invalid_options", fmt.Errorf("audit mechanism must be all, apparmor or seccomp"))
	}
	if opts.PollInterval == 0 {
		opts.PollInterval = time.Second
	}
	if opts.PollInterval < 50*time.Millisecond || opts.PollInterval > time.Minute {
		return auditFollowFailure(result, "invalid_options", fmt.Errorf("audit poll interval must be between 50ms and 1m"))
	}
	var err error
	opts.Path, err = filepath.Abs(opts.Path)
	if err != nil {
		return auditFollowFailure(result, "invalid_options", err)
	}
	if opts.ReaderID == "" {
		identity, _ := json.Marshal([]string{opts.RunID, opts.Path, opts.Mechanism})
		opts.ReaderID = fmt.Sprintf("audit-%x", sha256.Sum256(identity))
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	cp := auditCheckpoint{Version: 1, Options: opts.AuditIngestOptions, Observation: AuditCollectionObservation{
		SchemaVersion: AuditCollectionSchema, EvidenceKind: "collection_status", ReaderID: opts.ReaderID,
		SourcePath: opts.Path, Mechanism: opts.Mechanism, RawRecordsRetained: opts.RetainRaw,
		Status: "reading", Reason: "started", CoverageScope: "selected_source_file", UpstreamLoss: "unknown", ObservedAt: now, LastStartAt: now}}
	result.Reader = cp.Observation
	if err := os.MkdirAll(paths.Spool, 0700); err != nil {
		return auditFollowFailure(result, "reader_lock_unavailable", err)
	}
	lockPath := filepath.Join(paths.Spool, fmt.Sprintf("audit-%x.lock", sha256.Sum256([]byte(opts.ReaderID))))
	lock, err := lockAuditReader(lockPath)
	if err != nil {
		return auditFollowFailure(result, "reader_lock_unavailable", err)
	}
	defer lock.Close()
	var raw string
	var revision int
	err = db.QueryRowContext(ctx, `SELECT CASE WHEN length(checkpoint_json)<=65536 THEN checkpoint_json ELSE '' END,revision FROM telemetry_audit_checkpoints WHERE id=?`, opts.ReaderID).Scan(&raw, &revision)
	if err == nil {
		var saved auditCheckpoint
		if len(raw) > 64<<10 || json.Unmarshal([]byte(raw), &saved) != nil || saved.Version != 1 || saved.Observation.SchemaVersion != AuditCollectionSchema || saved.Observation.ReaderID != opts.ReaderID || saved.Observation.CommittedOffset < 0 || saved.Observation.Read < 0 || revision < 1 {
			return auditFollowFailure(result, "invalid_checkpoint", fmt.Errorf("invalid saved audit checkpoint"))
		}
		if saved.Options != opts.AuditIngestOptions {
			return auditFollowFailure(result, "settings_conflict", fmt.Errorf("audit reader settings differ from its checkpoint; use the original settings or an explicit new reader id"))
		}
		observation, marshalErr := json.Marshal(saved.Observation)
		if marshalErr != nil || ValidateRawPayload("access_control_collection", string(observation)) != nil || saved.Observation.SourcePath != opts.Path || saved.Observation.Mechanism != opts.Mechanism || saved.Observation.RawRecordsRetained != opts.RetainRaw {
			return auditFollowFailure(result, "invalid_checkpoint", fmt.Errorf("invalid saved audit observation"))
		}
		cp = saved
		cp.revision = revision
		cp.Observation.Status, cp.Observation.Reason = "reading", "resumed"
		cp.Observation.ObservedAt, cp.Observation.LastStartAt = now, now
	} else if !errors.Is(err, sql.ErrNoRows) {
		return auditFollowFailure(result, "storage_error", err)
	}
	result.Reader = cp.Observation
	publish := func() error {
		result.Reader = cp.Observation
		if report != nil {
			return report(result)
		}
		return nil
	}
	fail := func(reason string, cause error) (AuditFollowStatus, error) {
		next := cp
		next.Observation.Status, next.Observation.Reason = "failed", reason
		next.Observation.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
		persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		persistErr := store.WithWriteTx(persistCtx, db, func(tx *sql.Tx) error { return saveAuditCheckpoint(tx, &next, true) })
		if persistErr == nil {
			cp = next
		}
		result.Reader = next.Observation
		return result, errors.Join(fmt.Errorf("audit reader stopped: %s: %w", reason, cause), persistErr)
	}
	file, identity, err := openAuditLog(opts.Path)
	if err != nil {
		return fail(auditReadErrorReason(err), err)
	}
	defer file.Close()
	if cp.FileIdentity == "" && cp.Observation.CommittedOffset == 0 {
		cp.FileIdentity = identity
	} else if cp.FileIdentity != identity {
		return fail("source_replaced", fmt.Errorf("audit source identity changed; preserve the previous file and start a new reader for the new generation"))
	}
	size, reason, err := checkAuditSource(file, cp)
	if err != nil {
		return fail(reason, err)
	}
	cp.Observation.PendingBytes = size - cp.Observation.CommittedOffset
	if err := store.WithWriteTx(ctx, db, func(tx *sql.Tx) error { return saveAuditCheckpoint(tx, &cp, true) }); err != nil {
		return auditFollowFailure(result, "storage_error", fmt.Errorf("save audit reader start: %w", err))
	}
	if err := publish(); err != nil {
		return fail("status_output_failed", err)
	}
	onceEnd := size
	for ctx.Err() == nil {
		size, reason, err := checkAuditSource(file, cp)
		if err != nil {
			return fail(reason, err)
		}
		end := size
		if opts.Once && end > onceEnd {
			end = onceEnd
		}
		rows, bytesRead, digest, incomplete, readErr := readAuditFollowBatch(file, cp, end)
		if readErr != nil {
			return fail("source_read_failed", readErr)
		}
		next := cp
		next.Observation.CommittedOffset += bytesRead
		next.Observation.PendingBytes = size - next.Observation.CommittedOffset
		next.Observation.Status, next.Observation.Reason = "reading", "draining"
		if next.Observation.CommittedOffset >= end || incomplete {
			next.Observation.Status, next.Observation.Reason = "waiting", "caught_up"
			if incomplete {
				next.Observation.Reason = "partial_record"
			}
		}
		next.Observation.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
		due := next.Observation.Status != cp.Observation.Status || next.Observation.Reason != cp.Observation.Reason || time.Since(parseAuditFollowTime(cp.LastEvidenceAt)) >= 30*time.Second
		if len(rows) > 0 || due || next.Observation.PendingBytes != cp.Observation.PendingBytes {
			if _, reason, err := checkAuditSource(file, cp); err != nil {
				return fail(reason, err)
			}
			if bytesRead > 0 {
				actual, err := auditFileDigest(file, cp.Observation.CommittedOffset, bytesRead)
				if err != nil || actual != hex.EncodeToString(digest.Sum(nil)) {
					return fail("source_rewritten", errors.Join(fmt.Errorf("audit batch changed while being read"), err))
				}
			}
			next.HeadSHA256, next.TailSHA256, err = auditAnchors(file, next.Observation.CommittedOffset)
			if err != nil {
				return fail("source_read_failed", err)
			}
			err = store.WithWriteTx(ctx, db, func(tx *sql.Tx) error {
				if len(rows) > 0 {
					batch, _, duplicates, unidentified, err := ingestAuditBatchTx(tx, opts.AuditIngestOptions, rows, digest)
					if err != nil {
						return err
					}
					next.Observation.Read += len(rows)
					next.Observation.Ingested += batch.Ingested
					next.Observation.Duplicates += duplicates
					next.Observation.Skipped += batch.Skipped - duplicates
					next.Observation.Failed += batch.Failed
					next.Observation.IdentityIncomplete += unidentified
					next.Observation.Batches++
					next.Observation.LastBatchID = batch.BatchID
					next.Observation.LastReadAt = next.Observation.ObservedAt
					due = due || batch.Failed > 0
				}
				return saveAuditCheckpoint(tx, &next, due)
			})
			if err != nil {
				if ctx.Err() != nil {
					break
				}
				return fail("storage_error", err)
			}
			cp = next
			if err := publish(); err != nil {
				return fail("status_output_failed", err)
			}
		}
		if opts.Once && next.Observation.Status == "waiting" {
			break
		}
		if next.Observation.Status == "reading" {
			continue
		}
		timer := time.NewTimer(opts.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	next := cp
	next.Observation.Status = "stopped"
	next.Observation.Reason = "requested_stop"
	if opts.Once && ctx.Err() == nil {
		next.Observation.Reason = "snapshot_drained"
		if next.Observation.PendingBytes > 0 {
			next.Observation.Reason = "pending_source_bytes"
		}
	}
	next.Observation.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := store.WithWriteTx(stopCtx, db, func(tx *sql.Tx) error { return saveAuditCheckpoint(tx, &next, true) }); err != nil {
		result.Reader = cp.Observation
		return auditFollowFailure(result, "storage_error", fmt.Errorf("save audit reader stop: %w", err))
	}
	cp = next
	err = publish()
	return result, err
}

func auditFollowFailure(result AuditFollowStatus, reason string, err error) (AuditFollowStatus, error) {
	result.Reader.SchemaVersion, result.Reader.EvidenceKind = AuditCollectionSchema, "collection_status"
	result.Reader.Status, result.Reader.Reason = "failed", reason
	result.Reader.CoverageScope, result.Reader.UpstreamLoss = "selected_source_file", "unknown"
	result.Reader.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return result, err
}

func parseAuditFollowTime(text string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, text)
	return t
}

func saveAuditCheckpoint(tx *sql.Tx, cp *auditCheckpoint, evidence bool) error {
	if evidence {
		payload, err := json.Marshal(cp.Observation)
		if err != nil {
			return err
		}
		if _, err := ingestFilteredWithStore(tx, IngestEvent{RunID: cp.Options.RunID, EventType: "access_control_collection", Source: "audit_reader", Payload: string(payload), Timestamp: cp.Observation.ObservedAt}); err != nil {
			return err
		}
		cp.LastEvidenceAt = cp.Observation.ObservedAt
	}
	raw, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	if cp.revision == 0 {
		_, err = tx.Exec(`INSERT INTO telemetry_audit_checkpoints(id,run_id,revision,checkpoint_json,updated_at) VALUES(?,?,1,?,?)`, cp.Observation.ReaderID, cp.Options.RunID, string(raw), cp.Observation.ObservedAt)
	} else {
		var result sql.Result
		result, err = tx.Exec(`UPDATE telemetry_audit_checkpoints SET revision=revision+1,checkpoint_json=?,updated_at=? WHERE id=? AND revision=?`, string(raw), cp.Observation.ObservedAt, cp.Observation.ReaderID, cp.revision)
		if err == nil {
			var count int64
			count, err = result.RowsAffected()
			if err == nil && count != 1 {
				err = fmt.Errorf("audit checkpoint changed concurrently")
			}
		}
	}
	if err == nil {
		cp.revision++
	}
	return err
}

func readAuditFollowBatch(file *os.File, cp auditCheckpoint, end int64) ([]auditInputRow, int64, hash.Hash, bool, error) {
	reader := bufio.NewReaderSize(io.NewSectionReader(file, cp.Observation.CommittedOffset, end-cp.Observation.CommittedOffset), MaxAuditLineBytes+1)
	var rows []auditInputRow
	var consumed int64
	digest := sha256.New()
	for len(rows) < 128 && consumed < 1<<20 {
		line, err := reader.ReadSlice('\n')
		if len(line) > MaxAuditLineBytes || errors.Is(err, bufio.ErrBufferFull) {
			return nil, 0, digest, false, fmt.Errorf("audit line exceeds 64 KiB at source offset %d", cp.Observation.CommittedOffset+consumed)
		}
		if err == io.EOF {
			return rows, consumed, digest, len(line) > 0, nil
		}
		if err != nil {
			return nil, 0, digest, false, err
		}
		if consumed+int64(len(line)) > 1<<20 && len(rows) > 0 {
			return rows, consumed, digest, false, nil
		}
		record, ok, parseErr := ParseAuditLine(line, cp.Options.Source)
		row := auditInputRow{line: cp.Observation.Read + len(rows) + 1, err: parseErr}
		if ok && (cp.Options.Mechanism == "all" || cp.Options.Mechanism == record.Mechanism) {
			row.record = &record
		}
		rows = append(rows, row)
		consumed += int64(len(line))
		_, _ = digest.Write(line)
	}
	return rows, consumed, digest, false, nil
}

func checkAuditSource(file *os.File, cp auditCheckpoint) (int64, string, error) {
	info, err := file.Stat()
	if err != nil {
		return 0, auditReadErrorReason(err), err
	}
	current, err := os.Stat(cp.Options.Path)
	if err != nil {
		return 0, auditReadErrorReason(err), err
	}
	if !os.SameFile(info, current) {
		return 0, "source_replaced", fmt.Errorf("audit source was rotated or replaced")
	}
	if info.Size() < cp.Observation.CommittedOffset {
		return 0, "source_truncated", fmt.Errorf("audit source is shorter than its committed offset")
	}
	head, tail, err := auditAnchors(file, cp.Observation.CommittedOffset)
	if err != nil {
		return 0, auditReadErrorReason(err), err
	}
	if head != cp.HeadSHA256 || tail != cp.TailSHA256 {
		return 0, "source_rewritten", fmt.Errorf("audit source checkpoint fingerprints changed")
	}
	return info.Size(), "", nil
}

func auditAnchors(file *os.File, offset int64) (string, string, error) {
	if offset == 0 {
		return "", "", nil
	}
	length := min(offset, int64(4096))
	head, err := auditFileDigest(file, 0, length)
	if err != nil {
		return "", "", err
	}
	tail, err := auditFileDigest(file, offset-length, length)
	return head, tail, err
}

func auditFileDigest(file *os.File, offset, length int64) (string, error) {
	h := sha256.New()
	n, err := io.Copy(h, io.NewSectionReader(file, offset, length))
	if err != nil {
		return "", err
	}
	if n != length {
		return "", io.ErrUnexpectedEOF
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func auditReadErrorReason(err error) string {
	switch {
	case errors.Is(err, os.ErrPermission):
		return "permission_denied"
	case errors.Is(err, os.ErrNotExist):
		return "source_missing"
	default:
		return "source_unavailable"
	}
}
