package launch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/attest"
	"github.com/byteyellow/agentprovenance/internal/handoff"
	"github.com/byteyellow/agentprovenance/internal/store"
)

const remoteRouteSchema = "agentprovenance.claude_command_route/v1"

func checkRemoteClaudeMode(command []string) error {
	for _, name := range []string{"CLAUDE_CODE_SIMPLE", "CLAUDE_CODE_SAFE_MODE"} {
		value := strings.ToLower(os.Getenv(name))
		if value != "" && value != "0" && value != "false" {
			return fmt.Errorf("remote routing requires hooks; unset %s", name)
		}
	}
	for _, arg := range command[1:] {
		flag, _, _ := strings.Cut(arg, "=")
		switch flag {
		case "--bare", "--safe-mode", "--bg", "--background", "--cloud", "--desktop", "--teleport", "--environment":
			return fmt.Errorf("remote routing requires a local foreground Claude session; %s is unsupported", flag)
		}
	}
	return nil
}

func checkRemoteClaudeVersion(executable string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(ctx, executable, "--version").Output()
	if err != nil {
		return fmt.Errorf("cannot check Claude Code remote routing support: %w", err)
	}
	fields := strings.Fields(string(raw))
	if len(fields) > 0 {
		parts := strings.Split(fields[0], ".")
		if len(parts) == 3 {
			major, e1 := strconv.Atoi(parts[0])
			minor, e2 := strconv.Atoi(parts[1])
			patch, e3 := strconv.Atoi(parts[2])
			if e1 == nil && e2 == nil && e3 == nil && (major > 2 || major == 2 && (minor > 1 || minor == 1 && patch >= 295)) {
				return nil
			}
		}
	}
	return fmt.Errorf("remote routing requires Claude Code 2.1.295 or later for onFailure=block")
}

// Probe the real settings loader without a model request or a persisted session.
// A missing hook must stop launch before Claude can execute an unrouted command.
func checkRemoteClaudeHooks(command []string, opts Options, routePath string) error {
	var overlay struct {
		Hooks map[string][]map[string]any `json:"hooks"`
	}
	if err := readRouteJSON(command[2], &overlay, 64<<10); err != nil {
		return err
	}
	starts := overlay.Hooks["SessionStart"]
	if len(starts) == 0 {
		return fmt.Errorf("remote SessionStart hook is missing")
	}
	probePath := filepath.Join(filepath.Dir(routePath), "hook-probe.json")
	probe := map[string]any{"hooks": map[string]any{"SessionStart": starts[len(starts)-1:]}}
	if err := saveRouteJSON(probePath, probe, true); err != nil {
		return err
	}
	defer os.Remove(probePath)
	readyPath := filepath.Join(filepath.Dir(routePath), "hook-ready")
	if err := os.Remove(readyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	args := append([]string{"--init-only", "--no-session-persistence", "-p"}, command[1:]...)
	args[4] = probePath
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	logPath := filepath.Join(filepath.Dir(routePath), "hook-probe.log")
	log, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, command[0], args...)
	cmd.Dir, cmd.Stdout, cmd.Stderr = opts.Workdir, log, log
	err = errors.Join(cmd.Run(), log.Close())
	if err != nil {
		return fmt.Errorf("Claude hook preflight failed; inspect %s: %w", logPath, err)
	}
	var ready struct {
		RunID     string `json:"run_id"`
		SessionID string `json:"session_id"`
	}
	route, err := ReadRemoteRoute(routePath)
	if err != nil {
		return err
	}
	if err := readRouteJSON(readyPath, &ready, 4096); err != nil || ready.RunID != route.RunID || ready.SessionID == "" {
		return fmt.Errorf("Claude remote hook did not initialize; enable hooks in the effective settings and inspect %s", logPath)
	}
	return nil
}

// RemoteExecutionConfig is operator-owned, outside the agent workspace. Only
// native session/tool identities and the command come from the hook input.
type RemoteExecutionConfig struct {
	SchemaVersion   string `json:"schema_version"`
	URL             string `json:"url"`
	TokenFile       string `json:"token_file"`
	ExecutionConfig string `json:"execution_config"`
	Workdir         string `json:"workdir"`
	Shell           string `json:"shell"`
	ReceiverID      string `json:"receiver_id"`
	SignKeyFile     string `json:"sign_key_file"`
	PublicKeyFile   string `json:"public_key_file"`
	TimeoutSeconds  int    `json:"timeout_seconds"`
	FileDiff        bool   `json:"file_diff,omitempty"`
}

type RemoteRoute struct {
	SchemaVersion string                     `json:"schema_version"`
	RunID         string                     `json:"run_id"`
	DataDir       string                     `json:"data_dir"`
	SelfExe       string                     `json:"self_exe"`
	Config        RemoteExecutionConfig      `json:"config"`
	Principal     handoff.Principal          `json:"principal"`
	Target        handoff.Target             `json:"target"`
	WaitCapture   bool                       `json:"wait_capture"`
	Policy        agentcontext.CapturePolicy `json:"capture_policy"`
}

type PreparedRemoteCall struct {
	SchemaVersion string          `json:"schema_version"`
	Request       handoff.Request `json:"request"`
	RequestHash   string          `json:"request_sha256"`
	TimeoutMS     int64           `json:"timeout_ms"`
}

func readRouteJSON(path string, out any, limit int64) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return err
	}
	if int64(len(raw)) > limit {
		return fmt.Errorf("remote execution input exceeds size limit")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("remote execution input must contain one JSON object")
	}
	return nil
}

func (c RemoteExecutionConfig) validate() error {
	u, err := url.Parse(c.URL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return fmt.Errorf("remote execution requires an endpoint origin")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && ip != nil && ip.IsLoopback()) {
		return fmt.Errorf("remote execution requires HTTPS or a literal loopback HTTP endpoint")
	}
	if c.SchemaVersion != remoteRouteSchema || !filepath.IsAbs(c.Workdir) || !filepath.IsAbs(c.Shell) ||
		strings.ContainsRune(c.Workdir+c.Shell, 0) || c.TimeoutSeconds < 1 || c.TimeoutSeconds > 3600 || c.ReceiverID == "" {
		return fmt.Errorf("invalid remote execution configuration")
	}
	for _, path := range []string{c.TokenFile, c.ExecutionConfig, c.SignKeyFile, c.PublicKeyFile} {
		if !filepath.IsAbs(path) {
			return fmt.Errorf("remote execution credential and configuration paths must be absolute")
		}
	}
	return nil
}

func prepareRemoteRoute(opts Options, paths store.Paths, runID string, policy agentcontext.CapturePolicy) (string, error) {
	var config RemoteExecutionConfig
	if err := readRouteJSON(opts.RemoteExecution, &config, 64<<10); err != nil {
		return "", err
	}
	base, err := filepath.Abs(filepath.Dir(opts.RemoteExecution))
	if err != nil {
		return "", err
	}
	for _, path := range []*string{&config.TokenFile, &config.ExecutionConfig, &config.SignKeyFile, &config.PublicKeyFile} {
		if *path == "" {
			return "", fmt.Errorf("remote execution requires token, configuration and signing key files")
		}
		if !filepath.IsAbs(*path) {
			*path = filepath.Join(base, *path)
		}
	}
	if config.Shell == "" {
		config.Shell = "/bin/bash"
	}
	if config.TimeoutSeconds == 0 {
		config.TimeoutSeconds = 300
	}
	if err := config.validate(); err != nil {
		return "", err
	}
	// This transport returns the retained, signed command output to the tool.
	// Never silently override a caller's omission policy to obtain that output.
	if !policy.ToolResults {
		return "", fmt.Errorf("remote command output requires --capture-tool-results=true (basic capture remains available)")
	}
	f, err := os.Open(config.ExecutionConfig)
	if err != nil {
		return "", err
	}
	execution, readErr := handoff.ReadConfig(f)
	if err := errors.Join(readErr, f.Close()); err != nil {
		return "", err
	}
	if _, err := routeToken(config.TokenFile); err != nil {
		return "", err
	}
	if _, err := attest.LoadPrivateKeyHex(config.SignKeyFile); err != nil {
		return "", err
	}
	if _, err := attest.LoadPublicKeyHex(config.PublicKeyFile); err != nil {
		return "", err
	}
	root, err := filepath.Abs(paths.Root)
	if err != nil {
		return "", err
	}
	exe, err := filepath.Abs(opts.SelfExe)
	if err != nil {
		return "", err
	}
	route := RemoteRoute{SchemaVersion: remoteRouteSchema, RunID: runID, DataDir: root, SelfExe: exe,
		Config: config, Target: execution.Target, Principal: execution.Principal(), Policy: policy,
		WaitCapture: execution.Capture != nil}
	dir := filepath.Join(root, "execution-routes", runID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "route.json")
	return path, saveRouteJSON(path, route, false)
}

func ReadRemoteRoute(path string) (RemoteRoute, error) {
	var route RemoteRoute
	if err := readRouteJSON(path, &route, 64<<10); err != nil {
		return route, err
	}
	source := handoff.Source{ProducerID: route.Principal.ProducerID, Namespace: route.Principal.Namespace,
		RunID: route.RunID, Harness: "claude", SessionID: "validate", ToolCallID: "validate"}
	if route.SchemaVersion != remoteRouteSchema || source.Validate() != nil || route.Principal.Authorize(source, route.Target) != nil ||
		!filepath.IsAbs(route.DataDir) || !filepath.IsAbs(route.SelfExe) || !route.Policy.ToolResults {
		return route, fmt.Errorf("invalid saved remote execution route")
	}
	return route, route.Config.validate()
}

// PrepareClaudeRemoteCall has no network or execution side effects. The exact
// original command stays visible in the rewritten permission prompt.
func PrepareClaudeRemoteCall(path string, raw []byte) (map[string]any, error) {
	route, err := ReadRemoteRoute(path)
	if err != nil {
		return nil, err
	}
	var hook struct {
		Event   string                     `json:"hook_event_name"`
		Session string                     `json:"session_id"`
		Tool    string                     `json:"tool_name"`
		Call    string                     `json:"tool_use_id"`
		Input   map[string]json.RawMessage `json:"tool_input"`
	}
	if len(raw) > agentcontext.MaxLineBytes || json.Unmarshal(raw, &hook) != nil {
		return nil, fmt.Errorf("invalid native Claude hook input")
	}
	if hook.Event == "SessionStart" {
		if hook.Session == "" {
			return nil, fmt.Errorf("native Claude session identity is required")
		}
		if err := saveRouteJSON(filepath.Join(filepath.Dir(path), "hook-ready"), map[string]string{
			"run_id": route.RunID, "session_id": hook.Session,
		}, true); err != nil {
			return nil, err
		}
		return map[string]any{"hookSpecificOutput": map[string]any{"hookEventName": hook.Event,
			"additionalContext": fmt.Sprintf("Bash commands execute as independent commands on remote instance %s, working directory %s. Read/Write/Edit remain local. Use Bash for remote files; shell directory and environment changes do not persist between calls.", route.Target.InstanceID, route.Config.Workdir)}}, nil
	}
	if hook.Event != "PreToolUse" || hook.Tool != "Bash" {
		return map[string]any{}, nil
	}
	var command string
	var background bool
	var timeoutMS int64
	if json.Unmarshal(hook.Input["command"], &command) != nil || strings.TrimSpace(command) == "" {
		return nil, fmt.Errorf("native Bash command is required")
	}
	if value, ok := hook.Input["run_in_background"]; ok {
		if json.Unmarshal(value, &background) != nil || background {
			return nil, fmt.Errorf("remote execution supports foreground independent Bash commands")
		}
	}
	timeoutMS = int64(route.Config.TimeoutSeconds) * 1000
	if value, ok := hook.Input["timeout"]; ok {
		var requested int64
		if json.Unmarshal(value, &requested) != nil || requested < 1 {
			return nil, fmt.Errorf("invalid native Bash timeout")
		}
		if requested < timeoutMS {
			timeoutMS = requested
		}
	}
	source := handoff.Source{ProducerID: route.Principal.ProducerID, Namespace: route.Principal.Namespace,
		RunID: route.RunID, Harness: "claude", SessionID: hook.Session, ToolCallID: hook.Call}
	if err := source.Validate(); err != nil {
		return nil, err
	}
	identity, _ := json.Marshal(source)
	hash := sha256.Sum256(append([]byte("claude-command/v1\x00"), identity...))
	id := hex.EncodeToString(hash[:])
	keep := route.Policy.ToolResults
	request := handoff.Request{SchemaVersion: handoff.SchemaVersion, Source: source, Target: route.Target,
		DispatchID: "claude-" + id, OperationID: "initial-" + id, ValidUntil: time.Now().UTC().Add(time.Hour),
		Command: handoff.Command{Argv: []string{route.Config.Shell, "-lc", command}, Workdir: route.Config.Workdir,
			DisableSnapshot: !route.Config.FileDiff, CapturePreset: route.Policy.Preset, ToolResults: &keep}}
	preparedPath := filepath.Join(filepath.Dir(path), id+".json")
	prepared := PreparedRemoteCall{SchemaVersion: remoteRouteSchema, TimeoutMS: timeoutMS}
	prepared.Request, _, prepared.RequestHash, err = request.Canonical()
	if err != nil {
		return nil, err
	}
	if err := saveRouteJSON(preparedPath, prepared, false); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		var previous PreparedRemoteCall
		if err := readRouteJSON(preparedPath, &previous, 2<<20); err != nil {
			return nil, err
		}
		request.ValidUntil = previous.Request.ValidUntil
		_, _, expected, err := request.Canonical()
		_, _, saved, savedErr := previous.Request.Canonical()
		if err != nil || savedErr != nil || previous.SchemaVersion != remoteRouteSchema || saved != expected ||
			previous.RequestHash != saved || previous.TimeoutMS != timeoutMS {
			return nil, fmt.Errorf("native tool call changed after preparation: %w", handoff.ErrConflict)
		}
	}
	hook.Input["command"], _ = json.Marshal(shQuote(route.SelfExe) + " internal remote-command --route " + shQuote(path) +
		" --request " + shQuote(preparedPath) + " --native-command " + shQuote(command))
	// Do not return permissionDecision=allow: the harness checks the rewritten
	// command using its normal permission flow before the wrapper can submit it.
	return map[string]any{"hookSpecificOutput": map[string]any{"hookEventName": "PreToolUse", "updatedInput": hook.Input,
		"additionalContext": "This Bash command will execute remotely on " + route.Target.InstanceID + "."}}, nil
}

func saveRouteJSON(path string, value any, replace bool) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".route-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, writeErr := f.Write(raw)
	err = errors.Join(writeErr, f.Sync(), f.Close())
	if err != nil {
		return err
	}
	if replace {
		err = os.Rename(f.Name(), path)
	} else {
		err = os.Link(f.Name(), path)
	}
	if err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func routeToken(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	token := strings.TrimSpace(string(raw))
	if err != nil {
		return "", err
	}
	if len(raw) > 4096 || token == "" || strings.ContainsAny(token, "\r\n\x00") {
		return "", fmt.Errorf("invalid remote execution token file")
	}
	return token, nil
}
