package agentcontext

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/redact"
	"github.com/byteyellow/agentprovenance/internal/store"
)

type Service struct {
	DB    *sql.DB
	Paths store.Paths
}

func sourceID(src Source) string {
	identity := []string{src.Harness, src.SessionID, src.AgentID, src.Channel}
	if src.SessionID == "" {
		identity = append(identity, src.Path)
	}
	return "source-" + digest(identity)
}

func digest(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Save atomically appends immutable record revisions and a processing report.
// Re-reading unchanged records is a no-op; a late result or changed snapshot is
// a new revision. Neither a retry nor a parse failure deletes earlier evidence.
func (s Service) Save(ctx context.Context, runID string, src Source, records []Record, report Coverage) (SaveResult, error) {
	if s.DB == nil || runID == "" || src.Harness == "" || src.ParserVersion == "" {
		return SaveResult{}, fmt.Errorf("context import requires database, run, harness and parser version")
	}
	if len(records) > 0 && (src.SessionID == "" || (src.Binding != "explicit" && src.Binding != "exact" && src.Binding != "matched")) {
		return SaveResult{}, fmt.Errorf("context records require an explicit, exact, or uniquely matched session binding")
	}
	if !validStatus(report.Status) {
		return SaveResult{}, fmt.Errorf("invalid context coverage status %q", report.Status)
	}
	if len(records) > MaxRecords {
		return SaveResult{}, fmt.Errorf("context record count exceeds limit")
	}
	// Apply the same redaction boundary to source metadata, not only bodies.
	raw, err := json.Marshal(src)
	if err != nil {
		return SaveResult{}, err
	}
	if err := json.Unmarshal([]byte(redact.RedactString(string(raw))), &src); err != nil {
		return SaveResult{}, err
	}
	src.ID = sourceID(src)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return SaveResult{}, err
	}
	defer tx.Rollback()
	objects := provenance.ObjectStore{DB: s.DB, Paths: s.Paths, Tx: tx}
	result := SaveResult{}
	report.Counts.Stored, report.Counts.Duplicates = Number(0), Number(0)
	if report.PriorContext != nil {
		prior := *report.PriorContext
		report.PriorContext = &prior
		prior.Counts.Stored, prior.Counts.Duplicates = Number(0), Number(0)
		if prior.MissingFields == nil {
			prior.MissingFields = []string{}
		}
	}
	lastCreated := time.Time{}
	truncated := map[int64]bool{}
	for _, r := range records {
		if r.Key == "" || r.Sequence < 0 || r.SourceOrdinal < 0 || r.SourceOrdinal > MaxRecords || !validKind(r.Kind) {
			return SaveResult{}, fmt.Errorf("invalid context record identity or kind")
		}
		counts := &report.Counts
		switch r.ExecutionScope {
		case "", CurrentExecution:
		case PriorContext:
			if report.PriorContext == nil || r.Sequence < report.PriorContext.FirstLine || r.Sequence > report.PriorContext.LastLine {
				return SaveResult{}, fmt.Errorf("prior context record is outside the retained range")
			}
			counts = &report.PriorContext.Counts
		default:
			return SaveResult{}, fmt.Errorf("invalid context execution scope")
		}
		entry := Entry{
			SchemaVersion: SchemaVersion, RunID: runID, Source: src,
			SourceKey: r.Key, Sequence: r.Sequence, SourceOrdinal: r.SourceOrdinal, Kind: r.Kind,
			Role: r.Role, AgentID: r.AgentID, ToolCallID: r.ToolCallID, ToolName: r.ToolName, Status: r.Status,
			RecordedAt: r.RecordedAt, MissingFields: r.MissingFields,
			Content:        ContentRef{State: "unavailable", Reason: r.MissingReason},
			RawContent:     ContentRef{State: "unavailable", Reason: "source_not_recorded"},
			ExecutionScope: r.ExecutionScope,
		}
		if entry.AgentID == "" {
			entry.AgentID = src.AgentID
		}
		if r.Workdir != nil {
			entry.Source.Workdir = *r.Workdir
		}
		if r.ApplicationVersion != nil {
			entry.Source.ApplicationVersion = *r.ApplicationVersion
		}
		if r.Body != nil {
			if len(*r.Body) > provenance.MaxTextContentBytes {
				entry.Content = ContentRef{State: "omitted", Reason: "capture_limit"}
				report.Status = Partial
				report.Issues = append(report.Issues, Issue{Code: "capture_limit", Line: r.Sequence, Field: "content", Scope: r.ExecutionScope})
			} else {
				body, err := objects.PutTextContent(provenance.TextContentInput{
					RunID: runID, SourceID: "context/" + src.ID + "/" + digest([]string{r.Key, r.Kind}),
					Text: *r.Body, MediaType: r.MediaType,
				})
				if err != nil {
					return SaveResult{}, err
				}
				entry.Content = contentReference(body)
			}
		} else if entry.Content.Reason == "" {
			entry.Content.Reason = "source_not_recorded"
		}
		if r.RawBody != nil {
			if len(*r.RawBody) > provenance.MaxTextContentBytes {
				entry.RawContent = ContentRef{State: "omitted", Reason: "capture_limit"}
				report.Status = Partial
				report.Issues = append(report.Issues, Issue{Code: "capture_limit", Line: r.Sequence, Field: "raw_content", Scope: r.ExecutionScope})
			} else {
				raw, err := objects.PutTextContent(provenance.TextContentInput{RunID: runID,
					SourceID: fmt.Sprintf("context/%s/raw/%d", src.ID, r.Sequence), Text: *r.RawBody, MediaType: "application/json"})
				if err != nil {
					return SaveResult{}, err
				}
				entry.RawContent = contentReference(raw)
			}
		}
		if (entry.Content.Reason == "capture_limit" || entry.RawContent.Reason == "capture_limit") && !truncated[r.Sequence] {
			if counts.Truncated == nil {
				counts.Truncated = Number(0)
			}
			if r.Status != "source_truncated" {
				*counts.Truncated++
			}
			truncated[r.Sequence] = true
		}
		payload, err := entryPayload(entry)
		if err != nil {
			return SaveResult{}, err
		}
		// Keep searchable columns identical to the redacted evidence payload.
		safe, err := json.Marshal(payload)
		if err != nil {
			return SaveResult{}, err
		}
		if err := json.Unmarshal(safe, &entry); err != nil {
			return SaveResult{}, err
		}
		entry.ID = "context-" + digest(payload)
		payload["id"] = entry.ID
		var existing int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_context_entries WHERE run_id = ? AND id = ?`, runID, entry.ID).Scan(&existing); err != nil {
			return SaveResult{}, err
		}
		if existing != 0 {
			result.Duplicates++
			*counts.Duplicates++
			continue
		}
		parents := []string{}
		if entry.Content.Ref != "" {
			parents = append(parents, entry.Content.Ref)
		}
		if entry.RawContent.Ref != "" {
			parents = append(parents, entry.RawContent.Ref)
		}
		obj, err := objects.PutExternalObject(provenance.ExternalObjectInput{
			Type: "agent_context", SourceID: entry.ID, RunID: runID, Payload: payload, Parents: parents,
		})
		if err != nil {
			return SaveResult{}, err
		}
		// Import order breaks ties between revisions of the same physical row.
		// This is storage time, never a substitute for the source event time.
		created := time.Now().UTC()
		if !created.After(lastCreated) {
			created = lastCreated.Add(time.Nanosecond)
		}
		lastCreated = created
		_, err = tx.ExecContext(ctx, `INSERT INTO agent_context_entries
			(id, run_id, source_id, session_id, parent_session_id, agent_id, source_key,
			source_sequence, source_ordinal, kind, role, tool_call_id, tool_name, status, recorded_at,
			object_hash, content_ref, parser_version, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			entry.ID, runID, src.ID, src.SessionID, src.ParentSessionID, entry.AgentID, entry.SourceKey,
			entry.Sequence, entry.SourceOrdinal, entry.Kind, entry.Role, entry.ToolCallID, entry.ToolName, entry.Status, entry.RecordedAt,
			obj.Hash, entry.Content.Ref, src.ParserVersion, created.Format("2006-01-02T15:04:05.000000000Z"))
		if err != nil {
			return SaveResult{}, err
		}
		result.Stored++
		*counts.Stored++
	}
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z")
	report.SchemaVersion, report.RunID, report.Source = SchemaVersion, runID, src
	if report.ObservedAt == "" {
		report.ObservedAt = now
	} else if t, err := time.Parse(time.RFC3339Nano, report.ObservedAt); err != nil {
		return SaveResult{}, fmt.Errorf("invalid report observation time")
	} else {
		report.ObservedAt = t.UTC().Format("2006-01-02T15:04:05.000000000Z")
	}
	if report.Issues == nil {
		report.Issues = []Issue{}
	}
	if len(report.Issues) > 100 {
		report.Issues = append(report.Issues[:99], Issue{Code: "diagnostic_limit"})
	}
	if report.MissingFields == nil {
		report.MissingFields = []string{}
	}
	report.ID, report.ObjectHash = "", ""
	report.ID = "coverage-" + digest(report)
	payload, err := mapPayload(report)
	if err != nil {
		return SaveResult{}, err
	}
	obj, err := objects.PutExternalObject(provenance.ExternalObjectInput{
		Type: "agent_context_coverage", SourceID: report.ID, RunID: runID, Payload: payload,
	})
	if err != nil {
		return SaveResult{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO agent_context_reports
		(id, run_id, source_id, harness, session_id, status, object_hash, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, report.ID, runID, src.ID, src.Harness,
		src.SessionID, report.Status, obj.Hash, report.ObservedAt)
	if err != nil {
		return SaveResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return SaveResult{}, err
	}
	report.ObjectHash = obj.Hash
	result.Coverage = report
	return result, nil
}

func mapPayload(v any) (map[string]any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var payload map[string]any
	err = json.Unmarshal([]byte(redact.RedactString(string(raw))), &payload)
	return payload, err
}

func entryPayload(e Entry) (map[string]any, error) {
	e.ID, e.ObjectHash, e.CreatedAt = "", "", ""
	return mapPayload(e)
}

func validKind(kind string) bool {
	switch kind {
	case "message", "tool_call", "tool_result", "task", "configuration", "approval", "session":
		return true
	default:
		return false
	}
}

func validStatus(status Status) bool {
	switch status {
	case Disabled, NoInput, Empty, OK, Partial, Failed, Ambiguous, LegacyNotRecorded:
		return true
	default:
		return false
	}
}

func normalizedTime(value string) string {
	if t, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return t.UTC().Format(time.RFC3339Nano)
	}
	return ""
}

func cleanIdentifier(value string) string { return strings.TrimSpace(redact.RedactString(value)) }
