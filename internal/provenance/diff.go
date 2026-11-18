package provenance

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/byteyellow/agentprovenance/internal/i18n"
)

type attemptFileView struct {
	AttemptID     string
	RolloutID     string
	ToolCallID    string
	SnapshotID    string
	WorkspacePath string
	Strategy      string
	Command       string
	Status        string
	IsWinner      bool
	ArtifactRef   string
	BaseID        string
}

type FileDiffManifest struct {
	SchemaVersion  string            `json:"schema_version"`
	RunID          string            `json:"run_id"`
	File           string            `json:"file"`
	BaseSnapshotID string            `json:"base_snapshot_id"`
	BasePath       string            `json:"base_path"`
	BaseExists     *bool             `json:"base_exists"`
	BaseSHA256     string            `json:"base_sha256"`
	Attempts       []FileDiffAttempt `json:"attempts"`
}

type FileDiffAttempt struct {
	AttemptID     string   `json:"attempt_id"`
	RolloutID     string   `json:"rollout_id"`
	ToolCallID    string   `json:"tool_call_id"`
	SnapshotID    string   `json:"snapshot_id"`
	WorkspacePath string   `json:"workspace_path"`
	Strategy      string   `json:"strategy"`
	Command       string   `json:"command"`
	Status        string   `json:"status"`
	IsWinner      bool     `json:"is_winner"`
	ArtifactRef   string   `json:"artifact_ref,omitempty"`
	Changed       *bool    `json:"changed"`
	FileExists    *bool    `json:"file_exists"`
	FileSHA256    string   `json:"file_sha256"`
	UnifiedDiff   []string `json:"unified_diff,omitempty"`
	ChangeType    string   `json:"change_type,omitempty"`
	ContentState  string   `json:"content_state,omitempty"`
	PatchState    string   `json:"patch_state,omitempty"`
	Source        string   `json:"source,omitempty"`
	ContentRef    string   `json:"content_ref,omitempty"`
	BaseSHA256    string   `json:"base_sha256,omitempty"`
}

type FileBlameManifest struct {
	SchemaVersion  string           `json:"schema_version"`
	RunID          string           `json:"run_id"`
	File           string           `json:"file"`
	BaseSnapshotID string           `json:"base_snapshot_id"`
	BaseSHA256     string           `json:"base_sha256"`
	Entries        []FileBlameEntry `json:"entries"`
}

type FileBlameEntry struct {
	File          string `json:"file"`
	AttemptID     string `json:"attempt_id"`
	RolloutID     string `json:"rollout_id"`
	ToolCallID    string `json:"tool_call_id"`
	SnapshotID    string `json:"snapshot_id"`
	IsWinner      bool   `json:"is_winner"`
	Changed       *bool  `json:"changed"`
	Reason        string `json:"reason"`
	Source        string `json:"source,omitempty"`
	ContentState  string `json:"content_state,omitempty"`
	SHA256        string `json:"sha256"`
	Status        string `json:"status"`
	Strategy      string `json:"strategy"`
	Command       string `json:"command"`
	ArtifactRef   string `json:"artifact_ref,omitempty"`
	WorkspacePath string `json:"workspace_path"`
}

func DiffFile(db *sql.DB, runID, filePath string, out io.Writer, languages ...i18n.Locale) error {
	manifest, err := BuildDiffFile(db, runID, filePath)
	if err != nil {
		return err
	}
	PrintDiffFile(out, manifest, languages...)
	return nil
}

func DiffFileJSON(db *sql.DB, runID, filePath string, out io.Writer) error {
	manifest, err := BuildDiffFile(db, runID, filePath)
	if err != nil {
		return err
	}
	return printJSON(out, manifest)
}

func BuildDiffFile(db *sql.DB, runID, filePath string) (FileDiffManifest, error) {
	filePath, err := cleanRelativeFile(filePath)
	if err != nil {
		return FileDiffManifest{}, err
	}
	baseSnapshotID, baseRoot, err := baseSnapshotForRun(db, runID)
	if err != nil {
		return FileDiffManifest{}, err
	}
	attempts, err := attemptsForRun(db, runID)
	if err != nil {
		return FileDiffManifest{}, err
	}
	m := FileDiffManifest{SchemaVersion: "agentprovenance.diff/v1", RunID: runID, File: filePath, BaseSnapshotID: baseSnapshotID, BasePath: filepath.Join(baseRoot, filePath), BaseSHA256: "unknown"}
	var saved map[string]TrajectoryEvidence
	for _, a := range attempts {
		var c TrajectoryFileChange
		source := "retained_fork_snapshot"
		if a.Strategy == "zero-sdk-record" {
			source = "recorded_snapshot"
			r, err := recordedFilesFor(db, runID, a.RolloutID, a.BaseID)
			if err != nil {
				return m, err
			}
			var item *recordedFile
			for i := range r.Files {
				if r.Files[i].Path == filePath {
					item = &r.Files[i]
					break
				}
			}
			c, err = r.comparison(db, runID, filePath, item)
			if err != nil {
				return m, err
			}
		} else {
			if saved == nil {
				saved, err = savedForkFiles(db, runID)
				if err != nil {
					return m, err
				}
			}
			c = savedForkFile(saved, a, filePath)
		}
		if a.BaseID == baseSnapshotID {
			m.BaseExists, m.BaseSHA256 = boolWhen(c.BaseExists, c.BaseSHA256 != "unknown" || c.BaseExists), c.BaseSHA256
		}
		ref := a.ArtifactRef
		if c.EvidenceRef != "" {
			ref = c.EvidenceRef
		}
		m.Attempts = append(m.Attempts, FileDiffAttempt{AttemptID: a.AttemptID, RolloutID: a.RolloutID, ToolCallID: a.ToolCallID, SnapshotID: a.SnapshotID,
			WorkspacePath: a.WorkspacePath, Strategy: a.Strategy, Command: a.Command, Status: a.Status, IsWinner: a.IsWinner, ArtifactRef: ref,
			Changed: boolWhen(c.ChangeType != "unchanged", c.ChangeType != "unknown"), FileExists: boolWhen(c.NextExists, c.NextExists || c.NextSHA256 != "unknown"), FileSHA256: c.NextSHA256,
			BaseSHA256: c.BaseSHA256, UnifiedDiff: c.UnifiedDiff, ChangeType: c.ChangeType, Source: source, ContentState: c.ContentState, ContentRef: c.ContentRef, PatchState: c.PatchState})
	}
	return m, nil
}

func PrintDiffFile(out io.Writer, manifest FileDiffManifest, languages ...i18n.Locale) {
	lang := presentationLocale(languages)
	fmt.Fprintf(out, i18n.T(lang, "run=%s file=%s base_snapshot=%s\n"), manifest.RunID, manifest.File, manifest.BaseSnapshotID)
	fmt.Fprintf(out, i18n.T(lang, "base_sha256=%s base_path=%s\n"), manifest.BaseSHA256, manifest.BasePath)
	fmt.Fprintln(out, i18n.T(lang, "diffs:"))
	for _, attempt := range manifest.Attempts {
		fmt.Fprintf(out, i18n.T(lang, "  attempt=%s rollout=%s tool_call=%s winner=%t status=%s strategy=%s changed=%s base_sha256=%s attempt_sha256=%s workspace=%s\n"),
			attempt.AttemptID, attempt.RolloutID, attempt.ToolCallID, attempt.IsWinner, attempt.Status, attempt.Strategy, boolText(attempt.Changed), attempt.BaseSHA256, attempt.FileSHA256, attempt.WorkspacePath)
		if attempt.Source != "" {
			fmt.Fprintf(out, i18n.T(lang, "    source=%s change=%s content=%s\n"), attempt.Source, attempt.ChangeType, attempt.ContentState)
		}
		if attempt.PatchState != "" {
			fmt.Fprintf(out, i18n.T(lang, "    patch=%s\n"), attempt.PatchState)
		}
		if len(attempt.UnifiedDiff) == 0 {
			continue
		}
		fmt.Fprintf(out, "  --- base/%s\n", manifest.File)
		fmt.Fprintf(out, "  +++ attempt/%s/%s\n", attempt.AttemptID, manifest.File)
		for _, line := range attempt.UnifiedDiff {
			fmt.Fprintf(out, "  %s\n", line)
		}
	}
}

func BlameFileJSON(db *sql.DB, runID, filePath string, out io.Writer) error {
	manifest, err := BuildBlameFile(db, runID, filePath)
	if err != nil {
		return err
	}
	return printJSON(out, manifest)
}

func BuildBlameFile(db *sql.DB, runID, filePath string) (FileBlameManifest, error) {
	diff, err := BuildDiffFile(db, runID, filePath)
	if err != nil {
		return FileBlameManifest{}, err
	}
	m := FileBlameManifest{SchemaVersion: "agentprovenance.blame/v1", RunID: runID, File: diff.File, BaseSnapshotID: diff.BaseSnapshotID, BaseSHA256: diff.BaseSHA256}
	for _, a := range diff.Attempts {
		reason := a.ChangeType
		switch reason {
		case "created", "deleted", "modified":
			reason += "_by_attempt"
		case "unchanged":
			reason = "unchanged_from_base"
		case "changed":
			reason = "snapshot_change_recorded"
		}
		m.Entries = append(m.Entries, FileBlameEntry{File: diff.File, AttemptID: a.AttemptID, RolloutID: a.RolloutID, ToolCallID: a.ToolCallID,
			SnapshotID: a.SnapshotID, IsWinner: a.IsWinner, Changed: a.Changed, Reason: reason, SHA256: a.FileSHA256, Status: a.Status, Strategy: a.Strategy,
			Command: a.Command, ArtifactRef: a.ArtifactRef, WorkspacePath: a.WorkspacePath, Source: a.Source, ContentState: a.ContentState})
	}
	return m, nil
}

func PrintBlameFile(out io.Writer, manifest FileBlameManifest, languages ...i18n.Locale) {
	lang := presentationLocale(languages)
	fmt.Fprintf(out, i18n.T(lang, "run=%s file=%s base_snapshot=%s base_sha256=%s\n"), manifest.RunID, manifest.File, manifest.BaseSnapshotID, manifest.BaseSHA256)
	fmt.Fprintln(out, i18n.T(lang, "blame:"))
	for _, entry := range manifest.Entries {
		fmt.Fprintf(out, i18n.T(lang, "  file=%s attempt=%s rollout=%s tool_call=%s winner=%t changed=%s reason=%s sha256=%s status=%s strategy=%s artifact=%s command=%q workspace=%s\n"),
			entry.File, entry.AttemptID, entry.RolloutID, entry.ToolCallID, entry.IsWinner, boolText(entry.Changed), entry.Reason, entry.SHA256, entry.Status, entry.Strategy, entry.ArtifactRef, entry.Command, entry.WorkspacePath)
	}
}

func boolWhen(value, known bool) *bool {
	if !known {
		return nil
	}
	return &value
}
func boolText(value *bool) string {
	if value == nil {
		return "unknown"
	}
	return strconv.FormatBool(*value)
}

func printJSON(out io.Writer, value any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

func BlameFile(db *sql.DB, runID, filePath string, out io.Writer, languages ...i18n.Locale) error {
	manifest, err := BuildBlameFile(db, runID, filePath)
	if err != nil {
		return err
	}
	PrintBlameFile(out, manifest, languages...)
	return nil
}

func baseSnapshotForRun(db *sql.DB, runID string) (string, string, error) {
	if strings.TrimSpace(runID) == "" {
		return "", "", fmt.Errorf("--run is required")
	}
	var snapshotID, root string
	err := db.QueryRow(`SELECT s.id, s.path
		FROM rollouts r JOIN snapshots s ON r.base_snapshot_id = s.id
		WHERE r.run_id = ?
		ORDER BY r.created_at DESC LIMIT 1`, runID).Scan(&snapshotID, &root)
	if err != nil {
		return "", "", err
	}
	return snapshotID, root, nil
}

func attemptsForRun(db *sql.DB, runID string) ([]attemptFileView, error) {
	rows, err := db.Query(`SELECT a.id, a.rollout_id, a.tool_call_id, a.snapshot_id, a.workspace_path,
			a.strategy, a.command, a.status, a.is_winner, COALESCE(a.artifact_result, ''), r.base_snapshot_id
		FROM fork_attempts a JOIN rollouts r ON a.rollout_id = r.id
		WHERE r.run_id = ?
		ORDER BY a.created_at ASC`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var attempts []attemptFileView
	for rows.Next() {
		var item attemptFileView
		var isWinner int
		if err := rows.Scan(&item.AttemptID, &item.RolloutID, &item.ToolCallID, &item.SnapshotID, &item.WorkspacePath, &item.Strategy, &item.Command, &item.Status, &isWinner, &item.ArtifactRef, &item.BaseID); err != nil {
			return nil, err
		}
		item.IsWinner = isWinner != 0
		attempts = append(attempts, item)
	}
	return attempts, rows.Err()
}

func cleanRelativeFile(value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("--file is required")
	}
	if filepath.IsAbs(value) {
		return "", fmt.Errorf("--file must be workspace-relative")
	}
	clean := filepath.Clean(value)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("--file escapes workspace")
	}
	return clean, nil
}

func sha256Hex(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func hashOrMissing(content []byte, ok bool) string {
	if !ok {
		return "missing"
	}
	return sha256Hex(content)
}

func unifiedLines(base []byte, baseOK bool, next []byte, nextOK bool) []string {
	if !baseOK {
		return prefixLines("+", splitLines(next))
	}
	if !nextOK {
		return prefixLines("-", splitLines(base))
	}
	a := splitLines(base)
	b := splitLines(next)
	table := make([][]int, len(a)+1)
	for i := range table {
		table[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				table[i][j] = table[i+1][j+1] + 1
			} else if table[i+1][j] >= table[i][j+1] {
				table[i][j] = table[i+1][j]
			} else {
				table[i][j] = table[i][j+1]
			}
		}
	}
	var out []string
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if a[i] == b[j] {
			out = append(out, " "+a[i])
			i++
			j++
		} else if table[i+1][j] >= table[i][j+1] {
			out = append(out, "-"+a[i])
			i++
		} else {
			out = append(out, "+"+b[j])
			j++
		}
	}
	for ; i < len(a); i++ {
		out = append(out, "-"+a[i])
	}
	for ; j < len(b); j++ {
		out = append(out, "+"+b[j])
	}
	return out
}

func splitLines(content []byte) []string {
	text := strings.ReplaceAll(string(content), "\r\n", "\n")
	text = strings.TrimSuffix(text, "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

func prefixLines(prefix string, lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		out = append(out, prefix+line)
	}
	return out
}
