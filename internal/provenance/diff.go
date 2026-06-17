package provenance

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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
}

func DiffFile(db *sql.DB, runID, filePath string, out io.Writer) error {
	filePath, err := cleanRelativeFile(filePath)
	if err != nil {
		return err
	}
	baseSnapshotID, baseRoot, err := baseSnapshotForRun(db, runID)
	if err != nil {
		return err
	}
	baseContent, baseOK, err := readRelativeFile(baseRoot, filePath)
	if err != nil {
		return err
	}
	attempts, err := attemptsForRun(db, runID)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "run=%s file=%s base_snapshot=%s\n", runID, filePath, baseSnapshotID)
	if baseOK {
		fmt.Fprintf(out, "base_sha256=%s base_path=%s\n", sha256Hex(baseContent), filepath.Join(baseRoot, filePath))
	} else {
		fmt.Fprintf(out, "base_sha256=missing base_path=%s\n", filepath.Join(baseRoot, filePath))
	}
	fmt.Fprintln(out, "diffs:")
	for _, attempt := range attempts {
		content, ok, err := readRelativeFile(attempt.WorkspacePath, filePath)
		if err != nil {
			return err
		}
		changed := !baseOK || !ok || sha256Hex(baseContent) != sha256Hex(content)
		attemptHash := "missing"
		if ok {
			attemptHash = sha256Hex(content)
		}
		fmt.Fprintf(out, "  attempt=%s rollout=%s tool_call=%s winner=%t status=%s strategy=%s changed=%t base_sha256=%s attempt_sha256=%s workspace=%s\n",
			attempt.AttemptID, attempt.RolloutID, attempt.ToolCallID, attempt.IsWinner, attempt.Status, attempt.Strategy, changed, hashOrMissing(baseContent, baseOK), attemptHash, attempt.WorkspacePath)
		if !changed {
			continue
		}
		fmt.Fprintf(out, "  --- base/%s\n", filePath)
		fmt.Fprintf(out, "  +++ attempt/%s/%s\n", attempt.AttemptID, filePath)
		for _, line := range unifiedLines(baseContent, baseOK, content, ok) {
			fmt.Fprintf(out, "  %s\n", line)
		}
	}
	return nil
}

func BlameFile(db *sql.DB, runID, filePath string, out io.Writer) error {
	filePath, err := cleanRelativeFile(filePath)
	if err != nil {
		return err
	}
	baseSnapshotID, baseRoot, err := baseSnapshotForRun(db, runID)
	if err != nil {
		return err
	}
	baseContent, baseOK, err := readRelativeFile(baseRoot, filePath)
	if err != nil {
		return err
	}
	baseHash := hashOrMissing(baseContent, baseOK)
	attempts, err := attemptsForRun(db, runID)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "run=%s file=%s base_snapshot=%s base_sha256=%s\n", runID, filePath, baseSnapshotID, baseHash)
	fmt.Fprintln(out, "blame:")
	for _, attempt := range attempts {
		content, ok, err := readRelativeFile(attempt.WorkspacePath, filePath)
		if err != nil {
			return err
		}
		fileHash := "missing"
		if ok {
			fileHash = sha256Hex(content)
		}
		changed := fileHash != baseHash
		reason := "unchanged_from_base"
		if !baseOK && ok {
			reason = "created_by_attempt"
		} else if baseOK && !ok {
			reason = "deleted_by_attempt"
		} else if changed {
			reason = "modified_by_attempt"
		}
		fmt.Fprintf(out, "  file=%s attempt=%s rollout=%s tool_call=%s winner=%t changed=%t reason=%s sha256=%s status=%s strategy=%s artifact=%s command=%q workspace=%s\n",
			filePath, attempt.AttemptID, attempt.RolloutID, attempt.ToolCallID, attempt.IsWinner, changed, reason, fileHash, attempt.Status, attempt.Strategy, attempt.ArtifactRef, attempt.Command, attempt.WorkspacePath)
	}
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
			a.strategy, a.command, a.status, a.is_winner, COALESCE(a.artifact_result, '')
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
		if err := rows.Scan(&item.AttemptID, &item.RolloutID, &item.ToolCallID, &item.SnapshotID, &item.WorkspacePath, &item.Strategy, &item.Command, &item.Status, &isWinner, &item.ArtifactRef); err != nil {
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

func readRelativeFile(root, rel string) ([]byte, bool, error) {
	path := filepath.Join(root, rel)
	content, err := os.ReadFile(path)
	if err == nil {
		return content, true, nil
	}
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	return nil, false, err
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
