//go:build linux || darwin

package cli

import (
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
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/ids"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/substrate/state"
	"github.com/byteyellow/agentprovenance/internal/workspace"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

const workspaceCLISchema = "agentprovenance.workspace_cli/v1"
const workspaceResultSchema = "agentprovenance.workspace_tool_result/v1"
const maxWorkspaceRequestBytes = 40 << 20

type workspaceOperatorConfig struct {
	Schema             string                `json:"schema"`
	WorkspaceID        string                `json:"workspace_id"`
	RunID              string                `json:"run_id"`
	Root               string                `json:"root"`
	StateDir           string                `json:"state_dir"`
	DataDir            string                `json:"data_dir"`
	Target             workspace.Target      `json:"target"`
	TargetFile         string                `json:"target_file"`
	AllowedOperations  []workspace.Operation `json:"allowed_operations"`
	Limits             workspace.Limits      `json:"limits,omitempty"`
	BashTimeoutSeconds int                   `json:"bash_timeout_seconds,omitempty"`
}

type workspaceToolRequest struct {
	WorkspaceID      string           `json:"workspace_id"`
	Target           workspace.Target `json:"target"`
	ExpectedRevision *uint64          `json:"expected_revision,omitempty"`
	ExpectedDigest   string           `json:"expected_digest,omitempty"`
	Path             string           `json:"path,omitempty"`
	Content          *string          `json:"content,omitempty"`
	OldText          *string          `json:"old_text,omitempty"`
	NewText          *string          `json:"new_text,omitempty"`
	Count            int              `json:"count,omitempty"`
	Command          string           `json:"command,omitempty"`
}

type workspaceToolError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	NextAction string `json:"next_action"`
}

type workspaceToolView struct {
	Binding     workspace.WorkspaceBinding `json:"binding"`
	LastReceipt workspace.Receipt          `json:"last_receipt"`
}

type workspaceToolResult struct {
	Schema           string              `json:"schema"`
	OK               bool                `json:"ok"`
	Error            *workspaceToolError `json:"error,omitempty"`
	RunID            string              `json:"run_id,omitempty"`
	ToolCallID       string              `json:"tool_call_id,omitempty"`
	View             *workspaceToolView  `json:"view,omitempty"`
	OperationRef     string              `json:"operation_ref,omitempty"`
	Files            []state.FileEntry   `json:"files,omitempty"`
	Content          *string             `json:"content,omitempty"`
	SHA256           string              `json:"sha256,omitempty"`
	ContentEvidence  *workspace.Content  `json:"content_evidence,omitempty"`
	Stdout           string              `json:"stdout,omitempty"`
	Stderr           string              `json:"stderr,omitempty"`
	OutputTruncated  bool                `json:"output_truncated"`
	RecordToolCallID string              `json:"record_tool_call_id,omitempty"`
	ContextStatus    string              `json:"context_status,omitempty"`
}

func init() { workspaceCmd = newWorkspaceCmd }

func newWorkspaceCmd() *cobra.Command {
	var config string
	var withJSON bool
	cmd := &cobra.Command{Use: "workspace", Short: "controlled remote-authoritative workspace tools"}
	cmd.PersistentFlags().StringVar(&config, "config", "", "operator-owned workspace JSON configuration")
	cmd.PersistentFlags().BoolVar(&withJSON, "json", false, "emit one JSON response (required)")
	for _, operation := range []string{"inspect", "read", "write", "edit", "bash"} {
		op := operation
		child := &cobra.Command{Use: op, Short: "workspace " + op + " from a JSON stdin request", Args: cobra.NoArgs, SilenceUsage: true,
			RunE: func(cmd *cobra.Command, args []string) error {
				result := workspaceToolResult{Schema: workspaceResultSchema}
				var err error
				if !withJSON || config == "" {
					err = workspace.ErrInvalid
				} else {
					ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
					defer stop()
					result, err = runWorkspaceTool(ctx, cmd.InOrStdin(), config, op)
				}
				if err != nil {
					result.OK = false
					result.Error = workspaceJSONError(err)
				}
				if writeErr := json.NewEncoder(cmd.OutOrStdout()).Encode(result); writeErr != nil {
					return writeErr
				}
				if err != nil {
					return errors.New(result.Error.Code)
				}
				return nil
			}}
		cmd.AddCommand(child)
	}
	return cmd
}

func workspaceDecode(raw []byte, value any) error {
	if !utf8.Valid(raw) {
		return workspace.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return workspace.ErrInvalid
	}
	if d.Decode(new(any)) != io.EOF {
		return workspace.ErrInvalid
	}
	return nil
}

// Config and the live target are local control-plane files, never tool payloads.
// Canonical paths plus NOFOLLOW reject link substitution; the containing operator
// namespace must remain protected from the workload.
func workspaceReadOperatorFile(path string, value any) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return workspace.ErrUnsafePath
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	if real != path {
		return workspace.ErrUnsafePath
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Mode&0o022 != 0 || (int(stat.Uid) != os.Geteuid() && stat.Uid != 0) || stat.Size > 64<<10 {
		return workspace.ErrUnsafePath
	}
	before, err := f.Stat()
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil {
		return err
	}
	if len(raw) > 64<<10 {
		return workspace.ErrLimit
	}
	after, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return workspace.ErrStaleTarget
	}
	return workspaceDecode(raw, value)
}

func workspaceInside(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func workspaceID(s string) bool {
	if s == "" || len(s) > 256 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func loadWorkspaceConfig(path string) (workspaceOperatorConfig, error) {
	var c workspaceOperatorConfig
	if err := workspaceReadOperatorFile(path, &c); err != nil {
		return c, err
	}
	if c.Schema != workspaceCLISchema || !workspaceID(c.WorkspaceID) || !workspaceID(c.RunID) || !workspaceID(c.Target.ProducerID) || !workspaceID(c.Target.InstanceID) || !workspaceID(c.Target.Generation) {
		return c, workspace.ErrInvalid
	}
	for _, p := range []string{c.Root, c.StateDir, c.DataDir, c.TargetFile} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return c, workspace.ErrUnsafePath
		}
	}
	if c.Root == "/" || workspaceInside(c.Root, path) || workspaceInside(c.Root, c.StateDir) || workspaceInside(c.StateDir, c.Root) || workspaceInside(c.Root, c.DataDir) || workspaceInside(c.Root, c.TargetFile) {
		return c, workspace.ErrUnsafePath
	}
	// Validate the existing paths/parents before store.Init can create anything.
	for _, p := range []string{c.Root, filepath.Dir(c.StateDir), filepath.Dir(c.DataDir)} {
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			return c, err
		}
		if real != p {
			return c, workspace.ErrUnsafePath
		}
	}
	for _, p := range []string{c.StateDir, c.DataDir} {
		if info, err := os.Lstat(p); err == nil && !info.IsDir() {
			return c, workspace.ErrUnsafePath
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return c, err
		}
	}
	if c.BashTimeoutSeconds == 0 {
		c.BashTimeoutSeconds = 60
	}
	if c.BashTimeoutSeconds < 1 || c.BashTimeoutSeconds > 300 {
		return c, workspace.ErrInvalid
	}
	if c.Limits.FileBytes == 0 {
		c.Limits.FileBytes = 2 << 20
	}
	if c.Limits.TotalBytes == 0 {
		c.Limits.TotalBytes = 16 << 20
	}
	if c.Limits.Entries == 0 {
		c.Limits.Entries = 1024
	}
	if c.Limits.OutputBytes == 0 {
		c.Limits.OutputBytes = 2 << 20
	}
	if c.Limits.FileBytes < 1 || c.Limits.FileBytes > 32<<20 || c.Limits.TotalBytes < c.Limits.FileBytes || c.Limits.TotalBytes > 128<<20 || c.Limits.Entries < 1 || c.Limits.Entries > 8192 || c.Limits.OutputBytes < 1 || c.Limits.OutputBytes > 32<<20 {
		return c, workspace.ErrLimit
	}
	seen := map[workspace.Operation]bool{}
	for _, op := range c.AllowedOperations {
		if seen[op] {
			return c, workspace.ErrInvalid
		}
		seen[op] = true
		switch op {
		case workspace.Read, workspace.Write, workspace.Edit, workspace.Execute:
		default:
			return c, workspace.ErrInvalid
		}
	}
	if len(seen) == 0 {
		return c, workspace.ErrInvalid
	}
	var target workspace.Target
	if err := workspaceReadOperatorFile(c.TargetFile, &target); err != nil {
		return c, err
	}
	if target != c.Target {
		return c, workspace.ErrStaleTarget
	}
	return c, nil
}

func validateWorkspaceRequest(r workspaceToolRequest, op string) error {
	if !workspaceID(r.WorkspaceID) || !workspaceID(r.Target.ProducerID) || !workspaceID(r.Target.InstanceID) || !workspaceID(r.Target.Generation) {
		return workspace.ErrInvalid
	}
	if op != "write" && r.Content != nil || op != "edit" && (r.OldText != nil || r.NewText != nil || r.Count != 0) || op != "bash" && r.Command != "" {
		return workspace.ErrInvalid
	}
	switch op {
	case "inspect":
		if r.Path != "" || r.ExpectedDigest != "" {
			return workspace.ErrInvalid
		}
	case "read":
		if r.Path == "" {
			return workspace.ErrInvalid
		}
	case "write":
		if r.Path == "" || r.Content == nil {
			return workspace.ErrInvalid
		}
	case "edit":
		if r.Path == "" || r.OldText == nil || r.NewText == nil || r.Count < 1 {
			return workspace.ErrInvalid
		}
	case "bash":
		if r.Path != "" || r.ExpectedDigest != "" || r.ExpectedRevision == nil || strings.TrimSpace(r.Command) == "" || len(r.Command) > 64<<10 || strings.ContainsRune(r.Command, 0) {
			return workspace.ErrInvalid
		}
	default:
		return workspace.ErrInvalid
	}
	if (op == "write" || op == "edit") && r.ExpectedRevision == nil && r.ExpectedDigest == "" {
		return workspace.ErrInvalid
	}
	return nil
}

func runWorkspaceTool(ctx context.Context, input io.Reader, configPath, op string) (workspaceToolResult, error) {
	out := workspaceToolResult{Schema: workspaceResultSchema}
	raw, err := io.ReadAll(io.LimitReader(input, maxWorkspaceRequestBytes+1))
	if err != nil {
		return out, err
	}
	if len(raw) > maxWorkspaceRequestBytes {
		return out, workspace.ErrLimit
	}
	var req workspaceToolRequest
	if err := workspaceDecode(raw, &req); err != nil {
		return out, err
	}
	if err := validateWorkspaceRequest(req, op); err != nil {
		return out, err
	}
	c, err := loadWorkspaceConfig(configPath)
	if err != nil {
		return out, err
	}
	if req.Target != c.Target {
		return out, workspace.ErrStaleTarget
	}
	if req.WorkspaceID != c.WorkspaceID {
		return out, workspace.ErrForbidden
	}
	allowedOp := workspace.Operation(op)
	if op == "inspect" {
		allowedOp = workspace.Read
	}
	if op == "bash" {
		allowedOp = workspace.Execute
	}
	allowed := false
	for _, candidate := range c.AllowedOperations {
		allowed = allowed || candidate == allowedOp
	}
	if !allowed {
		return out, workspace.ErrForbidden
	}
	paths, err := store.Init(c.DataDir)
	if err != nil {
		return out, err
	}
	db, err := store.Open(paths)
	if err != nil {
		return out, err
	}
	defer db.Close()
	w, err := workspace.Open(ctx, workspace.Config{StateDir: c.StateDir, RunID: c.RunID, Limits: c.Limits, Objects: provenance.ObjectStore{DB: db, Paths: paths},
		Binding: workspace.WorkspaceBinding{WorkspaceID: c.WorkspaceID, Target: c.Target, Root: c.Root, Mode: workspace.RemoteAuthoritative, AllowedOperations: c.AllowedOperations},
		CurrentTarget: func(ctx context.Context) (workspace.Target, error) {
			var current workspace.Target
			if err := ctx.Err(); err != nil {
				return current, err
			}
			err := workspaceReadOperatorFile(c.TargetFile, &current)
			return current, err
		}})
	if err != nil {
		return out, err
	}
	out.RunID, out.ToolCallID = c.RunID, ids.New("workspace-tool")
	request := workspace.Request{WorkspaceID: req.WorkspaceID, Target: req.Target, ExpectedRevision: req.ExpectedRevision, ExpectedDigest: req.ExpectedDigest, Path: req.Path, ToolCallID: out.ToolCallID}
	if err := saveWorkspaceContext(ctx, db, paths, c, out.ToolCallID, op, "tool_call", workspaceRequestSummary(req), nil); err != nil {
		return out, fmt.Errorf("context write failed: %w", err)
	}
	var view workspace.View
	switch op {
	case "inspect":
		view, err = w.Inspect(ctx, request)
		if err == nil {
			for _, e := range view.Snapshot.Entries {
				out.Files = append(out.Files, e.FileEntry)
			}
		}
	case "read":
		var read workspace.ReadResult
		read, err = w.ReadFile(ctx, request)
		view = read.View
		if err == nil {
			out.SHA256 = read.SHA256
			for _, e := range view.Snapshot.Entries {
				if e.Path == req.Path {
					copy := e.Content
					out.ContentEvidence = &copy
				}
			}
			if !utf8.Valid(read.Data) || bytes.IndexByte(read.Data, 0) >= 0 {
				err = workspace.ErrInvalid
			} else {
				text := string(read.Data)
				out.Content = &text
			}
		}
	case "write":
		view, err = w.WriteFile(ctx, workspace.WriteRequest{Request: request, Data: []byte(*req.Content)})
	case "edit":
		view, err = w.EditFile(ctx, workspace.EditRequest{Request: request, Old: []byte(*req.OldText), New: []byte(*req.NewText), Count: req.Count})
	case "bash":
		output := &workspaceOutput{remaining: c.Limits.OutputBytes + 1}
		view, err = w.ObserveExecution(ctx, request, func(runCtx context.Context, input workspace.ExecutionInput) (workspace.ExecutionResult, error) {
			runner := record.Service{DB: db, Paths: paths, Options: record.Options{Timeout: time.Duration(c.BashTimeoutSeconds) * time.Second, AllowShell: true, WorkspaceRoot: input.Binding.Root}}
			rr, runErr := runner.RunContext(runCtx, record.Request{RunID: c.RunID, Name: "workspace-bash", Workdir: input.Binding.Root, Command: []string{"/bin/bash", "--noprofile", "--norc", "-c", req.Command},
				SampleIntervalMS: 25, PostRootGraceMS: 25, Stdin: strings.NewReader(""), Stdout: workspaceOutputStream{output, false}, Stderr: workspaceOutputStream{output, true}})
			out.RecordToolCallID = rr.ToolCallID
			result := workspace.ExecutionResult{ExitCode: rr.ExitCode, Stdout: output.stdout, Stderr: output.stderr}
			if rr.AttemptID != "" {
				result.Record = &workspace.RecordReference{RunID: rr.RunID, RolloutID: rr.RolloutID, AttemptID: rr.AttemptID, BaseSnapshotID: rr.BaseSnapshotID}
			}
			return result, errors.Join(runErr, runCtx.Err())
		})
		out.OutputTruncated = output.truncated || int64(len(output.stdout)+len(output.stderr)) > c.Limits.OutputBytes
		if !out.OutputTruncated {
			out.Stdout, _ = provenance.RedactText(string(bytes.ToValidUTF8(output.stdout, []byte("?"))))
			out.Stderr, _ = provenance.RedactText(string(bytes.ToValidUTF8(output.stderr, []byte("?"))))
		}
	}
	finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if view.Binding.WorkspaceID != "" {
		out.View = &workspaceToolView{Binding: view.Binding, LastReceipt: view.LastReceipt}
		if verifyErr := verifyWorkspaceRefs(finish, db, c, view); verifyErr != nil {
			err = errors.Join(workspace.ErrRecovery, err, verifyErr)
			out.Content = nil
			out.ContentEvidence = nil
			out.View = nil
			out.Files = nil
			out.SHA256 = ""
			out.Stdout = ""
			out.Stderr = ""
		} else if view.LastReceipt.ToolCallID == out.ToolCallID {
			out.OperationRef = view.LastReceipt.Ref
		}
	}
	out.OK = err == nil
	if err != nil {
		out.Error = workspaceJSONError(err)
	}
	// Context binds the trusted entry identity and validated CAS refs, not model
	// claims. Bodies are metadata only; source file bytes live in the core store.
	metadata := out
	metadata.Content = nil
	metadata.Files = nil
	metadata.Stdout = ""
	metadata.Stderr = ""
	if saveErr := saveWorkspaceContext(finish, db, paths, c, out.ToolCallID, op, "tool_result", metadata, out.View); saveErr != nil {
		out.ContextStatus = "failed"
		err = errors.Join(err, workspace.ErrRecovery, saveErr)
	} else {
		out.ContextStatus = "stored"
	}
	return out, err
}

func workspaceRequestSummary(r workspaceToolRequest) map[string]any {
	result := map[string]any{"workspace_id": r.WorkspaceID, "target": r.Target, "path": r.Path, "expected_revision": r.ExpectedRevision, "expected_digest": r.ExpectedDigest, "count": r.Count}
	for key, value := range map[string]*string{"content": r.Content, "old_text": r.OldText, "new_text": r.NewText} {
		if value != nil {
			sum := sha256.Sum256([]byte(*value))
			result[key+"_sha256"] = hex.EncodeToString(sum[:])
			result[key+"_bytes"] = len(*value)
		}
	}
	if r.Command != "" {
		result["command"] = r.Command
	}
	return result
}

func saveWorkspaceContext(ctx context.Context, db *sql.DB, paths store.Paths, c workspaceOperatorConfig, tool, op, kind string, value any, view *workspaceToolView) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	body := string(raw)
	refs := []string{}
	if view != nil {
		refs = append(refs, view.Binding.ManifestRef)
		if view.LastReceipt.ToolCallID == tool {
			refs = append(refs, view.LastReceipt.Ref)
		}
	}
	_, err = (agentcontext.Service{DB: db, Paths: paths}).Save(ctx, c.RunID, agentcontext.Source{Harness: "workspace-cli", Channel: "controlled_tools", SessionID: c.WorkspaceID + "/" + c.Target.InstanceID + "/" + c.Target.Generation,
		ParserVersion: workspaceCLISchema, Binding: "explicit", BindingEvidence: refs, Workdir: c.Root},
		[]agentcontext.Record{{Key: tool + "/" + kind, Sequence: 0, Kind: kind, ToolCallID: tool, ToolName: "workspace_" + op, Status: "observed", RecordedAt: time.Now().UTC().Format(time.RFC3339Nano), Body: &body, MediaType: "application/json", ExecutionScope: agentcontext.CurrentExecution}},
		agentcontext.Coverage{Status: agentcontext.OK, Counts: agentcontext.Counts{Read: agentcontext.Number(1), Parsed: agentcontext.Number(1)}})
	return err
}

func verifyWorkspaceRefs(ctx context.Context, db *sql.DB, c workspaceOperatorConfig, v workspace.View) error {
	for _, ref := range []string{v.Binding.ManifestRef, v.Binding.EvidenceRef} {
		var body struct {
			Binding workspace.WorkspaceBinding `json:"binding"`
		}
		if err := provenance.ReadObjectPayload(db, c.RunID, ref, &body); err != nil {
			return err
		}
		if body.Binding.WorkspaceID != c.WorkspaceID || body.Binding.Target != c.Target || body.Binding.Root != c.Root {
			return workspace.ErrConflict
		}
	}
	for _, entry := range v.Snapshot.Entries {
		if entry.Content.Ref != "" {
			var run string
			if err := db.QueryRowContext(ctx, `SELECT run_id FROM provenance_objects WHERE hash=?`, entry.Content.Ref).Scan(&run); err != nil {
				return err
			}
			if run != c.RunID {
				return workspace.ErrConflict
			}
		}
	}
	return nil
}

type workspaceOutput struct {
	mu             sync.Mutex
	remaining      int64
	stdout, stderr []byte
	truncated      bool
}
type workspaceOutputStream struct {
	output *workspaceOutput
	stderr bool
}

func (w workspaceOutputStream) Write(p []byte) (int, error) {
	w.output.mu.Lock()
	defer w.output.mu.Unlock()
	n := min(int64(len(p)), w.output.remaining)
	w.output.remaining -= n
	if w.stderr {
		w.output.stderr = append(w.output.stderr, p[:n]...)
	} else {
		w.output.stdout = append(w.output.stdout, p[:n]...)
	}
	w.output.truncated = w.output.truncated || n < int64(len(p))
	return len(p), nil
}

func workspaceJSONError(err error) *workspaceToolError {
	e := &workspaceToolError{Code: "operation_failed", Message: "Workspace operation failed.", NextAction: "inspect"}
	switch {
	case errors.Is(err, workspace.ErrStaleTarget):
		e.Code = "stale_target"
		e.Message = "Target identity/generation changed."
		e.NextAction = "operator_rebind"
	case errors.Is(err, workspace.ErrRecovery):
		e.Code = "recovery_required"
		e.Message = "Query the observed outcome; do not replay the operation."
	case errors.Is(err, workspace.ErrConflict), errors.Is(err, workspace.ErrChanged):
		e.Code = "conflict"
		e.Message = "Workspace changed; read the current file before deciding a new edit."
		e.NextAction = "reread"
	case errors.Is(err, workspace.ErrForbidden):
		e.Code = "forbidden"
		e.Message = "Operation or workspace is not allowed."
		e.NextAction = "operator_config"
	case errors.Is(err, workspace.ErrUnsafePath):
		e.Code = "unsafe_path"
		e.Message = "Path is outside the supported workspace scope."
		e.NextAction = "correct_request"
	case errors.Is(err, workspace.ErrLimit):
		e.Code = "limit_exceeded"
		e.Message = "Configured workspace or output limit exceeded."
		e.NextAction = "inspect"
	case errors.Is(err, workspace.ErrInvalid):
		e.Code = "invalid_request"
		e.Message = "Invalid request, configuration, or unsupported text content."
		e.NextAction = "correct_request"
	case errors.Is(err, os.ErrNotExist):
		e.Code = "not_found"
		e.Message = "Required file or workspace state was not found."
		e.NextAction = "reread"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		e.Code = "interrupted"
		e.Message = "Operation interrupted; query its observed outcome."
	}
	return e
}
