package provenance

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/byteyellow/agentprovenance/internal/substrate/state"
)

// Only the short line preview is bounded here. Full retained text remains
// available through the chunked content reader.
const patchBytes = 64 << 10

// Older managed forks stored their file comparisons in the materialized
// trajectory, rather than a post-execution artifact report.
func savedForkFiles(db *sql.DB, run string) (map[string]TrajectoryEvidence, error) {
	result := map[string]TrajectoryEvidence{}
	var ref string
	err := db.QueryRow(`SELECT hash FROM provenance_objects WHERE run_id=? AND object_type='trajectory_manifest' AND source_id=?
		ORDER BY created_at DESC, hash LIMIT 1`, run, run).Scan(&ref)
	if errors.Is(err, sql.ErrNoRows) {
		return result, nil
	}
	if err != nil {
		return nil, err
	}
	var manifest TrajectoryManifest
	if err := ReadObjectPayload(db, run, ref, &manifest); err != nil {
		return nil, err
	}
	if manifest.RunID != run || manifest.SchemaVersion != "agentprovenance.trajectories/v1" {
		return nil, fmt.Errorf("invalid saved trajectory for %s", run)
	}
	for _, a := range manifest.Trajectories {
		if a.RunID == run && a.Strategy != "zero-sdk-record" {
			result[a.AttemptID] = a
		}
	}
	return result, nil
}

func savedForkFile(saved map[string]TrajectoryEvidence, a attemptFileView, path string) TrajectoryFileChange {
	c := TrajectoryFileChange{Path: path, ChangeType: "unknown", ContentState: "not_recorded", BaseSHA256: "unknown", NextSHA256: "unknown"}
	t, ok := saved[a.AttemptID]
	if !ok || t.RolloutID != a.RolloutID || t.FileCaptureState != "" && t.FileCaptureState != "ok" {
		return c
	}
	for _, item := range t.FileChanges {
		if item.Path == path {
			return item
		}
	}
	c.ChangeType, c.ContentState = "unchanged", "unchanged"
	// Sibling attempts in the same rollout share this captured base.
	for _, sibling := range saved {
		if sibling.RolloutID != a.RolloutID {
			continue
		}
		for _, item := range sibling.FileChanges {
			if item.Path == path {
				c.BaseSHA256, c.NextSHA256 = item.BaseSHA256, item.BaseSHA256
				c.BaseExists, c.NextExists = item.BaseExists, item.BaseExists
				return c
			}
		}
	}
	return c
}

type recordedFile struct {
	Path   string `json:"path"`
	Change string `json:"snapshot_change"`
	State  string `json:"content_state"`
	Ref    string `json:"ref"`
	Body   string `json:"content_ref"`
	SHA    string `json:"sha256"`
	Bytes  *int64 `json:"content_bytes"`
}

type recordedFiles struct {
	Status     string         `json:"status"`
	Candidates *int           `json:"candidates"`
	Files      []recordedFile `json:"files"`
	root       string
}

func recordedFilesFor(db *sql.DB, run, rollout, snap string) (recordedFiles, error) {
	r := recordedFiles{Status: "not_recorded"}
	var ref string
	var count int
	err := db.QueryRow(`SELECT COUNT(*), COALESCE(MIN(hash),'') FROM provenance_objects
		WHERE run_id=? AND rollout_id=? AND object_type='artifact_capture' AND source_id=?`, run, rollout, "record/"+rollout+"/artifact_capture").Scan(&count, &ref)
	if err != nil || count == 0 {
		return r, err
	}
	if count > 1 {
		r.Status = "ambiguous"
		return r, nil
	}
	if err := ReadObjectPayload(db, run, ref, &r); err != nil {
		return r, err
	}
	// Imported snapshot paths belong to the sender. Only consult snapshots
	// under this store's own data root, never an imported host/workspace path.
	var database string
	if err := db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&database); err != nil {
		return r, err
	}
	if database != "" && filepath.IsLocal(snap) && filepath.Base(snap) == snap && snap != "." {
		r.root = filepath.Join(filepath.Dir(database), "snapshots", snap)
	}
	return r, nil
}

func (r recordedFiles) complete() bool {
	return r.Candidates != nil && *r.Candidates == len(r.Files) && (r.Status == "ok" || r.Status == "empty" || r.Status == "partial")
}

// A missing snapshot root is unknown; a missing entry in an available base
// snapshot is absent. Mask the base with the same rules as the recorded text.
func (r recordedFiles) base(path string) (digest string, body []byte, size int64, err error) {
	if r.root == "" || r.Candidates == nil {
		return "unknown", nil, 0, nil
	}
	st, err := os.Lstat(r.root)
	if errors.Is(err, os.ErrNotExist) {
		return "unknown", nil, 0, nil
	}
	if err != nil {
		return "", nil, 0, err
	}
	if !st.IsDir() {
		return "unknown", nil, 0, nil
	}
	p := r.root
	for _, part := range strings.Split(path, string(filepath.Separator)) {
		p = filepath.Join(p, part)
		st, err = os.Lstat(p)
		if errors.Is(err, os.ErrNotExist) {
			return "missing", nil, 0, nil
		}
		if err != nil {
			return "", nil, 0, err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return "unknown", nil, 0, nil
		}
	}
	if !st.Mode().IsRegular() {
		return "unknown", nil, 0, nil
	}
	if st.Size() > patchBytes {
		return "not_retained", nil, st.Size(), nil
	}
	f, err := os.Open(p)
	if err != nil {
		return "", nil, 0, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, patchBytes+1))
	if err != nil {
		return "", nil, 0, err
	}
	if len(raw) > patchBytes || !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
		return "not_retained", nil, st.Size(), nil
	}
	text, _ := RedactText(string(raw))
	return sha256Hex([]byte(text)), []byte(text), int64(len(text)), nil
}

func (r recordedFiles) comparison(db *sql.DB, run, path string, item *recordedFile) (TrajectoryFileChange, error) {
	c := TrajectoryFileChange{Path: path, ChangeType: "unknown", NextSHA256: "unknown", ContentState: r.Status}
	if item == nil && state.RecordFileExcluded(path) {
		c.BaseSHA256, c.ContentState = "unknown", "excluded"
		return c, nil
	}
	base, body, n, err := r.base(path)
	if err != nil {
		return c, err
	}
	c.BaseSHA256, c.BaseBytes, c.BaseExists = base, n, base != "missing" && base != "unknown"
	if item == nil {
		if r.complete() && base != "unknown" {
			c.ChangeType, c.ContentState, c.NextExists, c.NextSHA256, c.NextBytes = "unchanged", "unchanged", c.BaseExists, base, n
		} else if r.Candidates != nil && *r.Candidates > len(r.Files) {
			c.ContentState = "collection_limit"
		}
		return c, nil
	}
	c.ContentState, c.EvidenceRef, c.ContentRef = item.State, item.Ref, item.Body
	c.ChangeType = item.Change
	switch c.ChangeType {
	case "created":
		c.BaseExists, c.BaseSHA256, c.BaseBytes, body = false, "missing", 0, nil
	case "deleted", "modified":
		c.BaseExists = true
		if c.BaseSHA256 == "missing" {
			c.BaseSHA256 = "unknown"
		}
	default:
		c.ChangeType = "changed"
	}
	c.NextExists = item.Change == "created" || item.Change == "modified" || item.State == "stored" || item.State == "binary_omitted"
	switch item.State {
	case "deleted":
		c.ChangeType, c.NextExists, c.NextSHA256 = "deleted", false, "missing"
	case "stored":
		c.NextSHA256 = item.SHA
		if item.Bytes != nil {
			c.NextBytes = *item.Bytes
		}
		if c.ChangeType == "changed" && base != "unknown" {
			if base == "missing" {
				c.ChangeType = "created"
			} else {
				c.ChangeType = "modified"
			}
		}
	default:
		return c, nil
	}
	if c.BaseSHA256 == "unknown" || c.BaseSHA256 == "not_retained" {
		c.PatchState = "base_unavailable"
		return c, nil
	}
	var after []byte
	if c.NextExists {
		if item.Bytes == nil || *item.Bytes > patchBytes {
			c.PatchState = "size_limit"
			return c, nil
		}
		page, err := ReadTextContentPage(db, run, item.Body, 0, patchBytes)
		if err != nil {
			return c, err
		}
		after = []byte(page.Content)
		if page.HasMore || page.TotalBytes != *item.Bytes || sha256Hex(after) != item.SHA {
			return c, fmt.Errorf("recorded file content mismatch: %s", path)
		}
	}
	if (int64(bytes.Count(body, []byte{'\n'}))+2)*(int64(bytes.Count(after, []byte{'\n'}))+2) > 1_000_000 {
		c.PatchState = "line_limit"
		return c, nil
	}
	c.UnifiedDiff = unifiedLines(body, c.BaseExists, after, c.NextExists)
	return c, nil
}
