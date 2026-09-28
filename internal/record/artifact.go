package record

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
	"unicode/utf8"

	"github.com/byteyellow/agentprovenance/internal/provenance"
)

const (
	maxCapturedFiles     = 512
	maxCapturedTextBytes = 128 << 20
)

// ArtifactCaptureReport describes post-execution snapshots, not every version
// written during a run. Limits and omissions are evidence, not silent skips.
type ArtifactCaptureReport struct {
	SchemaVersion    string             `json:"schema_version"`
	Status           string             `json:"status"`
	Method           string             `json:"method"`
	Candidates       *int               `json:"candidates"`
	Stored           int                `json:"stored"`
	Omitted          int                `json:"omitted"`
	Failed           int                `json:"failed"`
	StoredBytes      int64              `json:"stored_bytes"`
	ReadBytes        int64              `json:"read_bytes"`
	FileLimit        int                `json:"file_limit"`
	PerFileByteLimit int64              `json:"per_file_byte_limit"`
	TotalByteLimit   int64              `json:"total_byte_limit"`
	Reason           string             `json:"reason,omitempty"`
	Issues           []string           `json:"issues,omitempty"`
	Ref              string             `json:"ref,omitempty"`
	Files            []CapturedArtifact `json:"files,omitempty"`
}

type CapturedArtifact struct {
	Path         string `json:"path"`
	SourceBytes  *int64 `json:"source_bytes"`
	ReadBytes    int64  `json:"read_bytes"`
	ContentState string `json:"content_state"`
	ContentRef   string `json:"content_ref,omitempty"`
	ContentBytes *int64 `json:"content_bytes"`
	SHA256       string `json:"sha256,omitempty"`
	Redacted     bool   `json:"redacted"`
	Reason       string `json:"reason,omitempty"`
	ReasonCode   string `json:"reason_code,omitempty"`
	CapturedAt   string `json:"captured_at"`
	Method       string `json:"capture_method"`
	Ref          string `json:"ref,omitempty"`
}

func newArtifactCaptureReport() ArtifactCaptureReport {
	return ArtifactCaptureReport{SchemaVersion: "agentprovenance.artifact_capture/v1",
		Status: "disabled", Method: "post_execution_snapshot", FileLimit: maxCapturedFiles,
		PerFileByteLimit: provenance.MaxTextContentBytes, TotalByteLimit: maxCapturedTextBytes,
		Reason: "File snapshot capture was not enabled."}
}

func (s Service) captureArtifacts(runID, rolloutID, workdir string, paths []string) ArtifactCaptureReport {
	report := newArtifactCaptureReport()
	count := len(paths)
	report.Candidates, report.Status, report.Reason = &count, "ok", ""
	if count == 0 {
		report.Status = "empty"
	}
	for i, path := range paths {
		if i >= report.FileLimit {
			report.Omitted += len(paths) - i
			report.Reason = "Changed-file selection exceeds the capture count limit."
			break
		}
		remaining := min(report.TotalByteLimit-report.StoredBytes, report.TotalByteLimit-report.ReadBytes)
		item, err := s.captureArtifact(runID, rolloutID, workdir, path, remaining)
		report.ReadBytes += item.ReadBytes
		if err != nil {
			item.ContentState, item.ReasonCode = "failed", "storage_failed"
			item.Reason = "Artifact evidence could not be stored."
			item.ContentRef, item.ContentBytes, item.SHA256, item.Redacted = "", nil, "", false
			report.Failed++
		} else if item.ContentState == "stored" {
			report.Stored++
			report.StoredBytes += *item.ContentBytes
		} else {
			report.Omitted++
		}
		report.Files = append(report.Files, item)
	}
	if report.Omitted+report.Failed > 0 {
		report.Status = "partial"
	}
	if report.Failed == count && count > 0 {
		report.Status = "failed"
	}
	return report
}

// Each descriptor and its text chunks share a transaction. On a failed write,
// no usable descriptor points at a partial set of registered chunks.
func (s Service) captureArtifact(runID, rolloutID, workdir, path string, remaining int64) (CapturedArtifact, error) {
	item := CapturedArtifact{Path: path, ContentState: "unavailable", CapturedAt: time.Now().UTC().Format(time.RFC3339Nano), Method: "post_execution_snapshot"}
	data := readArtifactFile(workdir, path, remaining, &item)
	tx, err := s.DB.Begin()
	if err != nil {
		return item, err
	}
	defer tx.Rollback()
	objects := provenance.ObjectStore{DB: s.DB, Paths: s.Paths, Tx: tx}
	var parents []string
	if item.ContentState == "stored" {
		content, err := objects.PutTextContent(provenance.TextContentInput{RunID: runID, SourceID: "workspace_file/" + path, Text: string(data), MaxBytes: remaining})
		if errors.Is(err, provenance.ErrTextContentLimit) {
			item.ContentState, item.ReasonCode, item.Reason = "collection_limit", "redacted_content_limit", "Redacted content exceeds the remaining capture budget."
		} else if err != nil {
			return item, err
		} else {
			item.ContentRef, item.ContentBytes, item.SHA256, item.Redacted = content.Ref, &content.Bytes, content.SHA256, content.Redacted
			parents = []string{content.Ref}
		}
	}
	raw, err := json.Marshal(item)
	if err != nil {
		return item, err
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return item, err
	}
	obj, err := objects.PutExternalObject(provenance.ExternalObjectInput{Type: "artifact", RunID: runID, RolloutID: rolloutID, SourceID: "workspace_file/" + path, Parents: parents, Payload: payload})
	if err != nil {
		return item, err
	}
	if err := tx.Commit(); err != nil {
		return item, err
	}
	item.Ref = obj.Hash
	return item, nil
}

func readArtifactFile(workdir, path string, remaining int64, item *CapturedArtifact) []byte {
	if remaining <= 0 {
		item.ContentState, item.ReasonCode, item.Reason = "collection_limit", "run_content_limit", "The run's saved-text budget is exhausted."
		return nil
	}
	f, err := openArtifactFile(workdir, path)
	if err != nil {
		item.ReasonCode, item.Reason = "source_unreadable", "The file could not be safely opened at capture time."
		if errors.Is(err, os.ErrNotExist) {
			item.ContentState, item.ReasonCode, item.Reason = "source_missing", "source_missing", "The file was absent at post-execution capture."
		}
		return nil
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() {
		item.ReasonCode, item.Reason = "unsupported_file_type", "Only regular files are captured; links and special files are not followed."
		return nil
	}
	size := before.Size()
	item.SourceBytes = &size
	limit := min(remaining, int64(provenance.MaxTextContentBytes))
	if size > limit {
		item.ContentState, item.ReasonCode, item.Reason = "collection_limit", "file_content_limit", "The file exceeds the remaining per-file or run capture budget."
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	item.ReadBytes = int64(len(data))
	if err != nil {
		item.ReasonCode, item.Reason = "source_read_failed", "The file could not be fully read at capture time."
		return nil
	}
	if int64(len(data)) > limit {
		item.ContentState, item.ReasonCode, item.Reason = "collection_limit", "file_content_limit", "The file exceeds the remaining per-file or run capture budget."
		return nil
	}
	after, err := f.Stat()
	if err != nil || after.Size() != size || !after.ModTime().Equal(before.ModTime()) || int64(len(data)) != size {
		item.ReasonCode, item.Reason = "source_changed", "The file changed while its post-execution content was being read."
		return nil
	}
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		item.ContentState, item.ReasonCode, item.Reason = "binary_omitted", "binary_omitted", "Binary file content is not saved by the text capture path."
		return nil
	}
	item.ContentState = "stored"
	return data
}

func (s Service) persistArtifactReport(runID, rolloutID string, report *ArtifactCaptureReport) error {
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return err
	}
	var parents []string
	for _, item := range report.Files {
		if item.Ref != "" {
			parents = append(parents, item.Ref)
		}
	}
	obj, err := (provenance.ObjectStore{DB: s.DB, Paths: s.Paths}).PutExternalObject(provenance.ExternalObjectInput{Type: "artifact_capture", RunID: runID, RolloutID: rolloutID, SourceID: "record/" + rolloutID + "/artifact_capture", Parents: parents, Payload: payload})
	if err != nil {
		return fmt.Errorf("artifact capture report could not be stored: %w", err)
	}
	report.Ref = obj.Hash
	return nil
}
