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
	"strings"

	"github.com/byteyellow/agentprovenance/internal/ids"
	"github.com/byteyellow/agentprovenance/internal/redact"
	"github.com/byteyellow/agentprovenance/internal/store"
)

type AuditIngestOptions struct {
	RunID     string
	Path      string
	Source    AuditSource
	Mechanism string // all, apparmor, or seccomp
	RetainRaw bool   // caller resolves the run's fixed capture policy
}

type AuditIngestResult struct {
	SchemaVersion      string      `json:"schema_version"`
	RunID              string      `json:"run_id"`
	Path               string      `json:"path"`
	Status             string      `json:"status"`
	RawRecordsRetained bool        `json:"raw_records_retained"`
	Read               int         `json:"read"`
	Ingested           int         `json:"ingested"`
	Duplicates         int         `json:"duplicates"`
	Skipped            int         `json:"skipped"`
	Failed             int         `json:"failed"`
	IdentityIncomplete int         `json:"identity_incomplete"`
	Batches            int         `json:"batches"`
	LastBatchID        string      `json:"last_batch_id,omitempty"`
	FileSHA256         string      `json:"file_sha256,omitempty"`
	Rows               []RowResult `json:"row_results,omitempty"`
	RowsTruncated      bool        `json:"row_results_truncated,omitempty"`
	Errors             []string    `json:"errors,omitempty"`
	ErrorsTruncated    bool        `json:"errors_truncated,omitempty"`
}

type auditInputRow struct {
	line   int
	record *AuditRecord
	err    error
}

// IngestAuditReader imports existing logs without changing auditd, AppArmor or
// seccomp. Batches are bounded and transactional, including dedup and edges.
// Re-running a failed import is safe when source host/boot identity is present.
func IngestAuditReader(ctx context.Context, db *sql.DB, opts AuditIngestOptions, input io.Reader) (AuditIngestResult, error) {
	result := AuditIngestResult{SchemaVersion: "agentprovenance.audit_ingest/v1", RunID: opts.RunID,
		Path: opts.Path, Status: "partial", RawRecordsRetained: opts.RetainRaw}
	if db == nil || input == nil || strings.TrimSpace(opts.RunID) == "" {
		return result, fmt.Errorf("audit import requires database, input and run")
	}
	if opts.Mechanism == "" {
		opts.Mechanism = "all"
	}
	if opts.Mechanism != "all" && opts.Mechanism != "apparmor" && opts.Mechanism != "seccomp" {
		return result, fmt.Errorf("audit mechanism must be all, apparmor or seccomp")
	}
	wholeHash, batchHash := sha256.New(), sha256.New()
	reader := bufio.NewReaderSize(io.TeeReader(input, wholeHash), MaxAuditLineBytes+1)
	var rows []auditInputRow
	lineNo, batchBytes := 0, 0
	flush := func() error {
		if len(rows) == 0 {
			return nil
		}
		batch, rowResults, duplicates, unidentified, err := ingestAuditBatch(ctx, db, opts, rows, batchHash)
		if err != nil {
			return err
		}
		result.Read += len(rows)
		result.Ingested += batch.Ingested
		result.Duplicates += duplicates
		result.Skipped += batch.Skipped - duplicates
		result.Failed += batch.Failed
		result.IdentityIncomplete += unidentified
		result.Batches++
		result.LastBatchID = batch.BatchID
		for _, row := range rowResults {
			if len(result.Rows) < 1000 {
				result.Rows = append(result.Rows, row)
			} else {
				result.RowsTruncated = true
			}
			if row.Error != "" {
				if len(result.Errors) < 20 {
					result.Errors = append(result.Errors, row.Error)
				} else {
					result.ErrorsTruncated = true
				}
			}
		}
		rows, batchBytes = nil, 0
		batchHash.Reset()
		return nil
	}
	for {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		line, readErr := reader.ReadSlice('\n')
		if errors.Is(readErr, bufio.ErrBufferFull) || len(line) > MaxAuditLineBytes {
			if err := flush(); err != nil {
				return result, err
			}
			return result, fmt.Errorf("audit line %d exceeds 64 KiB; import stopped after %d committed lines", lineNo+1, result.Read)
		}
		if readErr != nil && readErr != io.EOF {
			if err := flush(); err != nil {
				return result, err
			}
			return result, readErr
		}
		if len(line) != 0 {
			lineNo++
			_, _ = batchHash.Write(line)
			batchBytes += len(line)
			row := auditInputRow{line: lineNo}
			record, ok, err := ParseAuditLine(line, opts.Source)
			row.err = err
			if ok && (opts.Mechanism == "all" || opts.Mechanism == record.Mechanism) {
				row.record = &record
			}
			rows = append(rows, row)
		}
		if len(rows) >= 128 || batchBytes >= 1<<20 || readErr == io.EOF {
			if err := flush(); err != nil {
				return result, fmt.Errorf("audit batch failed after %d committed lines: %w", result.Read, err)
			}
		}
		if readErr == io.EOF {
			break
		}
	}
	result.FileSHA256 = hex.EncodeToString(wholeHash.Sum(nil))
	if result.Failed == 0 {
		result.Status = "completed"
	}
	return result, nil
}

func ingestAuditBatch(ctx context.Context, db *sql.DB, opts AuditIngestOptions, rows []auditInputRow, hash hash.Hash) (JSONLIngestResult, []RowResult, int, int, error) {
	batch := JSONLIngestResult{Format: "linux_audit", Path: fmt.Sprintf("%s#lines=%d-%d", opts.Path, rows[0].line, rows[len(rows)-1].line),
		Read: len(rows), FileSHA256: hex.EncodeToString(hash.Sum(nil))}
	var results []RowResult
	duplicates, unidentified := 0, 0
	err := store.WithWriteTx(ctx, db, func(tx *sql.Tx) error {
		for _, input := range rows {
			row := RowResult{Line: input.line, DetectedFormat: "linux_audit", Status: "skipped"}
			switch {
			case input.err != nil:
				row.Status, row.Error = "failed", fmt.Sprintf("line %d: %v", input.line, input.err)
				batch.Failed++
			case input.record == nil:
				batch.Skipped++
			default:
				record := *input.record
				if record.RecordID == "" {
					unidentified++
				}
				id := auditEventID(opts.RunID, record.RecordID)
				row.EventID, row.EventType, row.Source, row.RawEventID = id, "access_control", record.Mechanism+"_audit", record.RecordID
				var storedSource, storedRawID string
				err := tx.QueryRow(`SELECT source, COALESCE(raw_event_id,'') FROM events WHERE id=?`, id).Scan(&storedSource, &storedRawID)
				if err == nil {
					if storedSource != row.Source || storedRawID != record.RecordID {
						return fmt.Errorf("audit identity conflicts with an existing event")
					}
					row.Status = "duplicate"
					batch.Skipped++
					duplicates++
					break
				}
				if err != sql.ErrNoRows {
					return err
				}
				if !opts.RetainRaw {
					record.RawRecord.Text, record.RawRecord.State, record.RawRecord.Reason = "", "omitted", "capture_policy"
				} else {
					clean := redact.RedactString(record.RawRecord.Text)
					record.RawRecord.Redacted = clean != record.RawRecord.Text
					record.RawRecord.Text = clean
				}
				payload, err := json.Marshal(record)
				if err != nil {
					return err
				}
				// Logged PIDs stay in the audit payload. A separate, versioned
				// correlation pass must establish lifetime before adding links.
				_, err = ingestFilteredWithID(tx, IngestEvent{RunID: opts.RunID, Source: row.Source,
					EventType: row.EventType, RawEventID: record.RecordID, Timestamp: record.Timestamp, Payload: string(payload)}, id)
				if err != nil {
					return err
				}
				saved, err := eventRecordByID(tx, id)
				if err != nil {
					return err
				}
				if err := updateNativeWindows(tx, saved); err != nil {
					return err
				}
				row.Status, row.CorrelationMethod = "ingested", saved.CorrelationMethod
				batch.Ingested++
				batch.EventIDs = append(batch.EventIDs, id)
			}
			results = append(results, row)
		}
		batch.EventIDsSHA256 = hashStrings(batch.EventIDs)
		return persistJSONLBatch(tx, JSONLIngestOptions{RunID: opts.RunID}, &batch)
	})
	return batch, results, duplicates, unidentified, err
}

func auditEventID(run, record string) string {
	if record == "" {
		return ids.New("evt")
	}
	identity, _ := json.Marshal([]string{run, record})
	sum := sha256.Sum256(identity)
	return fmt.Sprintf("evt-audit-%x", sum)
}
