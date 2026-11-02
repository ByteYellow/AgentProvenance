package computerapi

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/control"
	"github.com/byteyellow/agentprovenance/internal/ids"
	"github.com/byteyellow/agentprovenance/internal/security"
	"github.com/byteyellow/agentprovenance/internal/store"
	runtimeplane "github.com/byteyellow/agentprovenance/internal/substrate/runtime"
	"github.com/byteyellow/agentprovenance/internal/substrate/session"
)

type Service struct {
	DB    *sql.DB
	Paths store.Paths
}

type SessionMeta struct {
	RunID         string
	ContainerID   string
	WorkspacePath string
}

type SearchMatch struct {
	Path string `json:"path"`
	Line int    `json:"line"`
	Text string `json:"text"`
}

func (s Service) ReadFile(sessionID, filePath, toolCallID string) (string, security.DecisionRecord, error) {
	meta, err := s.sessionMeta(sessionID)
	if err != nil {
		return "", security.DecisionRecord{}, err
	}
	hostPath, err := s.workspacePath(meta.WorkspacePath, filePath)
	if err != nil {
		return "", security.DecisionRecord{}, err
	}
	body, err := os.ReadFile(hostPath)
	if err != nil {
		return "", security.DecisionRecord{}, err
	}
	payload := map[string]any{
		"path":       filePath,
		"result_ref": hostPath,
		"bytes":      len(body),
	}
	record, err := s.recordEvent(security.Event{
		Source:     "computer_api",
		EventType:  "file_read",
		RunID:      meta.RunID,
		SessionID:  sessionID,
		ToolCallID: ensureToolCallID(toolCallID),
		Path:       filePath,
	}, payload)
	return string(body), record, err
}

func (s Service) WriteFile(sessionID, filePath, content, toolCallID string) (security.DecisionRecord, error) {
	meta, err := s.sessionMeta(sessionID)
	if err != nil {
		return security.DecisionRecord{}, err
	}
	hostPath, err := s.workspacePath(meta.WorkspacePath, filePath)
	if err != nil {
		return security.DecisionRecord{}, err
	}
	if err := os.MkdirAll(filepath.Dir(hostPath), 0o755); err != nil {
		return security.DecisionRecord{}, err
	}
	if err := os.WriteFile(hostPath, []byte(content), 0o644); err != nil {
		return security.DecisionRecord{}, err
	}
	return s.recordEvent(security.Event{
		Source:     "computer_api",
		EventType:  "file_write",
		RunID:      meta.RunID,
		SessionID:  sessionID,
		ToolCallID: ensureToolCallID(toolCallID),
		Path:       filePath,
	}, map[string]any{
		"path":       filePath,
		"result_ref": hostPath,
		"bytes":      len(content),
	})
}

func (s Service) Search(sessionID, pattern, toolCallID string) ([]SearchMatch, security.DecisionRecord, error) {
	meta, err := s.sessionMeta(sessionID)
	if err != nil {
		return nil, security.DecisionRecord{}, err
	}
	var matches []SearchMatch
	err = filepath.Walk(meta.WorkspacePath, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lines := strings.Split(string(body), "\n")
		rel, _ := filepath.Rel(meta.WorkspacePath, path)
		for i, line := range lines {
			if strings.Contains(line, pattern) {
				matches = append(matches, SearchMatch{Path: "/" + filepath.ToSlash(rel), Line: i + 1, Text: line})
			}
		}
		return nil
	})
	if err != nil {
		return nil, security.DecisionRecord{}, err
	}
	record, err := s.recordEvent(security.Event{
		Source:     "computer_api",
		EventType:  "search",
		RunID:      meta.RunID,
		SessionID:  sessionID,
		ToolCallID: ensureToolCallID(toolCallID),
		Args:       []string{pattern},
	}, map[string]any{
		"pattern":     pattern,
		"match_count": len(matches),
		"result_ref":  "search:" + ensureToolCallID(toolCallID),
	})
	return matches, record, err
}

func (s Service) ExportArtifact(sessionID, filePath, name, toolCallID string) (string, security.DecisionRecord, error) {
	meta, err := s.sessionMeta(sessionID)
	if err != nil {
		return "", security.DecisionRecord{}, err
	}
	hostPath, err := s.workspacePath(meta.WorkspacePath, filePath)
	if err != nil {
		return "", security.DecisionRecord{}, err
	}
	body, err := os.ReadFile(hostPath)
	if err != nil {
		return "", security.DecisionRecord{}, err
	}
	if name == "" {
		name = filepath.Base(filePath)
	}
	cleanName, err := sanitizeArtifactName(name)
	if err != nil {
		return "", security.DecisionRecord{}, err
	}
	artifactID := ids.New("artifact")
	artifactPath := filepath.Join(s.Paths.Artifacts, artifactID+"-"+cleanName)
	// 最终 join+Clean 后二次复核：即使拼接前缀吸收了首个 ".."（如 artifactID+"-"+name），
	// 只要 Clean 后的落点越出 Artifacts 目录即拒绝（M9 路径穿越任意写）。
	if err := ensureInsideArtifacts(s.Paths.Artifacts, artifactPath); err != nil {
		return "", security.DecisionRecord{}, err
	}
	if err := os.WriteFile(artifactPath, body, 0o600); err != nil {
		return "", security.DecisionRecord{}, err
	}
	record, err := s.recordEvent(security.Event{
		Source:     "computer_api",
		EventType:  "artifact_export",
		RunID:      meta.RunID,
		SessionID:  sessionID,
		ToolCallID: ensureToolCallID(toolCallID),
		Path:       filePath,
	}, map[string]any{
		"path":       filePath,
		"name":       name,
		"result_ref": artifactPath,
		"bytes":      len(body),
	})
	return artifactPath, record, err
}

func (s Service) Call(sessionID, module, function string, args map[string]string, toolCallID string, stream bool) (string, security.DecisionRecord, error) {
	// exec 入容器前校验：会话必须存在、running 且 lease 活跃（H3 跨会话 RCE 加固）。
	if err := session.GuardExec(s.DB, sessionID); err != nil {
		return "", security.DecisionRecord{}, err
	}
	meta, err := s.sessionMeta(sessionID)
	if err != nil {
		return "", security.DecisionRecord{}, err
	}
	if module != "shell" || function != "exec" {
		return "", security.DecisionRecord{}, fmt.Errorf("unsupported call target %s/%s; v1 supports shell/exec", module, function)
	}
	command := strings.TrimSpace(args["command"])
	if command == "" {
		return "", security.DecisionRecord{}, fmt.Errorf("call arg command is required")
	}
	driver, err := runtimeplane.NewDriver("docker", s.Paths)
	if err != nil {
		return "", security.DecisionRecord{}, err
	}
	processID, err := control.Service{DB: s.DB, Paths: s.Paths, Driver: driver}.Exec(sessionID, []string{"sh", "-lc", command}, stream)
	if err != nil {
		return "", security.DecisionRecord{}, err
	}
	record, err := s.recordEvent(security.Event{
		Source:     "computer_api",
		EventType:  "call",
		RunID:      meta.RunID,
		SessionID:  sessionID,
		ToolCallID: ensureToolCallID(toolCallID),
		ProcessID:  processID,
		Args:       []string{module, function, command},
	}, map[string]any{
		"module":     module,
		"function":   function,
		"command":    command,
		"process_id": processID,
		"result_ref": "process:" + processID,
	})
	return processID, record, err
}

// ErrInvalidArtifactName 导出目标名不合法（空、含路径分隔符、含 ".."、以 "." 开头
// 或含 [A-Za-z0-9._-] 之外字符）。调用方可用 errors.Is 判别。
var ErrInvalidArtifactName = errors.New("invalid artifact name")

// sanitizeArtifactName 白名单化导出名（M9 修复）：只允许 [A-Za-z0-9._-]，
// 并额外拒绝以 "." 开头与包含 ".." 的名字，杜绝把穿越段拼进 artifactID+"-"+name。
// 兜底校验由 ensureInsideArtifacts 在最终 join+Clean 后完成。
func sanitizeArtifactName(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("%w: name is empty", ErrInvalidArtifactName)
	}
	if strings.ContainsAny(name, `/\`) {
		return "", fmt.Errorf("%w: %q contains a path separator", ErrInvalidArtifactName, name)
	}
	if strings.Contains(name, "..") {
		return "", fmt.Errorf("%w: %q contains a parent-directory segment", ErrInvalidArtifactName, name)
	}
	if strings.HasPrefix(name, ".") {
		return "", fmt.Errorf("%w: %q starts with a dot (hidden or relative segment)", ErrInvalidArtifactName, name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return "", fmt.Errorf("%w: %q contains character %q outside [A-Za-z0-9._-]", ErrInvalidArtifactName, name, r)
		}
	}
	return name, nil
}

// ensureInsideArtifacts 校验最终落点严格位于 artifacts 目录之内。
// 注意不能用 cleanPath == cleanRoot 放行边界值：目录本身不可作为导出文件。
func ensureInsideArtifacts(artifactsDir, artifactPath string) error {
	cleanRoot := filepath.Clean(artifactsDir)
	cleanPath := filepath.Clean(artifactPath)
	if cleanPath == cleanRoot || !strings.HasPrefix(cleanPath, cleanRoot+string(os.PathSeparator)) {
		return fmt.Errorf("%w: destination %q escapes artifacts directory", ErrInvalidArtifactName, artifactPath)
	}
	return nil
}

func (s Service) sessionMeta(sessionID string) (SessionMeta, error) {
	var meta SessionMeta
	err := s.DB.QueryRow(`SELECT run_id, COALESCE(container_id, ''), workspace_host_path FROM sessions WHERE id = ?`, sessionID).
		Scan(&meta.RunID, &meta.ContainerID, &meta.WorkspacePath)
	return meta, err
}

func (s Service) workspacePath(workspaceRoot, requested string) (string, error) {
	trimmed := strings.TrimPrefix(requested, "/workspace")
	trimmed = strings.TrimPrefix(trimmed, "/")
	hostPath := filepath.Join(workspaceRoot, trimmed)
	cleanRoot := filepath.Clean(workspaceRoot)
	cleanPath := filepath.Clean(hostPath)
	if cleanPath != cleanRoot && !strings.HasPrefix(cleanPath, cleanRoot+string(os.PathSeparator)) {
		return "", fmt.Errorf("path escapes workspace: %s", requested)
	}
	return cleanPath, nil
}

func (s Service) recordEvent(event security.Event, payload map[string]any) (security.DecisionRecord, error) {
	payload["recorded_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	keys := make([]string, 0, len(payload))
	for key := range payload {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	ordered := make(map[string]any, len(payload))
	for _, key := range keys {
		ordered[key] = payload[key]
	}
	raw, err := json.Marshal(ordered)
	if err != nil {
		return security.DecisionRecord{}, err
	}
	return security.EvaluateAndPersist(s.DB, event, string(raw))
}

func ensureToolCallID(toolCallID string) string {
	if strings.TrimSpace(toolCallID) != "" {
		return toolCallID
	}
	return ids.New("tool")
}
