package record

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// DefaultExecTimeout bounds every child execution unless the operator raises it
// via Options.Timeout (daemon flag wiring) or disables it with a negative value.
// It exists so a recorded command that never exits (hung agent, blocking read,
// infinite loop) cannot wedge the daemon worker -- and its HTTP handler --
// forever (C2 hardening).
const DefaultExecTimeout = 60 * time.Second

// Options carries the Service.Run execution policy. It is defense in depth /
// attack-surface reduction, NOT an execution-isolation boundary: an
// authenticated caller can always execute any non-shell program by design --
// that is the product's collection semantics, and this policy does not change
// it. The zero value is the fail-closed policy:
//
//   - Timeout: DefaultExecTimeout (60s); a timed-out child has its whole
//     owned Linux cgroup stopped, or the process group when no cgroup is available.
//   - AllowShell=false: argv[0] being a shell interpreter (sh/bash/zsh/dash/
//     fish/ksh/csh/tcsh/pwsh/cmd, absolute paths included -- i.e. every
//     `sh -c ...` shape) is refused, which removes the most common wrapper
//     shape for arbitrary code. It is surface reduction, not sandboxing:
//     anything a shell would do remains equally reachable by naming a
//     non-shell program.
//   - Workdir confinement: the child's cwd must resolve inside the workspace
//     root (Options.WorkspaceRoot, falling back to Paths.Workspaces). A
//     confined request path is validated before anything is created; missing
//     directories are then created 0700. A request without a workdir lands in
//     <root>/<run_id> instead of falling back to the daemon's own cwd.
//   - Minimal environment: the child inherits only PATH/HOME/TMPDIR/TERM, so
//     daemon credentials (API keys, auth tokens) never leak into a recorded
//     process.
//
// Local, same-privilege callers (the CLI wrapping an interactive agent in the
// user's own repo) may relax individual fields; the daemon-side defaults stay
// strict. See the field docs for each escape hatch.
type Options struct {
	// Timeout bounds each child execution. >0 is used verbatim; 0 (the default)
	// means DefaultExecTimeout; a negative value disables the bound entirely
	// (interactive `launch` sessions that legitimately run for hours).
	Timeout time.Duration
	// AllowShell permits shell interpreters as argv[0] (and therefore any
	// `sh -c ...` command). Default false: refused with an explicit error.
	// Refusing shell names shrinks the most common arbitrary-code wrapper
	// shape; it is not execution isolation -- authenticated callers can still
	// run any non-shell program.
	AllowShell bool
	// WorkspaceRoot confines the effective working directory inside this tree.
	// Empty falls back to Paths.Workspaces.
	WorkspaceRoot string
	// AllowAnyWorkdir lifts the workspace-root confinement for callers that
	// deliberately record arbitrary user directories (local CLI flows).
	AllowAnyWorkdir bool
	// InheritFullEnv passes the daemon process environment to the child
	// verbatim instead of the minimal allowlist. Default false.
	InheritFullEnv bool
	// Foreground preserves the caller's process group for local terminal
	// input and signals. It requires Timeout < 0; bounded noninteractive jobs
	// use an isolated process group so cancellation cannot kill the caller.
	Foreground bool
}

// shellInterpreterNames are the interpreter basenames whose invocation is
// equivalent to arbitrary code execution, so they need an explicit
// Options.AllowShell opt-in. Checked on the basename so absolute paths
// (/usr/bin/zsh) and .exe suffixes are caught too.
var shellInterpreterNames = map[string]struct{}{
	"sh": {}, "bash": {}, "zsh": {}, "dash": {}, "fish": {},
	"ksh": {}, "csh": {}, "tcsh": {}, "pwsh": {}, "powershell": {},
	"cmd": {}, "cmd.exe": {},
}

// checkShellPolicy refuses shell-interpreter commands unless explicitly
// allowed. It runs before any side effect, so a refused request writes no
// snapshot, no graph rows, and creates no directories. Note this is not
// command-execution isolation -- see Options.AllowShell for the exact
// (defense-in-depth) claim.
func checkShellPolicy(command []string, allowShell bool) error {
	if allowShell || len(command) == 0 {
		return nil
	}
	base := strings.ToLower(strings.TrimSuffix(filepath.Base(command[0]), ".exe"))
	if _, isShell := shellInterpreterNames[base]; isShell {
		return fmt.Errorf("record policy: refusing shell interpreter %q as argv[0]: a shell command is arbitrary code execution, not a single recordable command (set Options.AllowShell / --record-allow-shell to override)", command[0])
	}
	return nil
}

// minimalChildEnvKeys is the environment allowlist handed to the child. The
// daemon's own environment (API keys, auth tokens, service credentials) must
// not leak into a recorded process just because it inherited the parent.
var minimalChildEnvKeys = map[string]struct{}{
	"PATH": {}, "HOME": {}, "TMPDIR": {}, "TERM": {},
}

// childEnv builds the child environment: the four allowlisted variables, or
// the full daemon environment when the caller explicitly opts in.
func childEnv(full bool) []string {
	if full {
		return os.Environ()
	}
	seen := make(map[string]struct{}, len(minimalChildEnvKeys))
	out := make([]string, 0, len(minimalChildEnvKeys))
	for _, kv := range os.Environ() {
		key, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if _, allowed := minimalChildEnvKeys[key]; !allowed {
			continue
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, kv)
	}
	// The root command itself is resolved by the parent's PATH at exec time, so
	// a missing PATH only breaks children spawning further commands by name.
	// Provide the standard fallback rather than failing mysteriously.
	if _, ok := seen["PATH"]; !ok && runtime.GOOS != "windows" {
		out = append(out, "PATH=/usr/bin:/bin:/usr/local/bin")
	}
	sort.Strings(out)
	return out
}

// workspaceDirName reports whether runID is safe to use as a single workspace
// directory component. Anything with separators, dots-only, or empty is
// rejected so a crafted run_id can never point the auto-created workspace
// outside the workspace root.
func workspaceDirName(runID string) string {
	if runID == "" || runID == "." || runID == ".." {
		return ""
	}
	for _, r := range runID {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return ""
		}
	}
	return runID
}

// resolveWorkdir computes the child's working directory under the execution
// policy:
//
//   - confinement is on unless AllowAnyWorkdir is set; the root is
//     Options.WorkspaceRoot, else Paths.Workspaces (the daemon always
//     configures one via store.Init);
//   - an empty request workdir lands in <root>/<run_id> (NOT the daemon's own
//     cwd, which previously made the daemon snapshot and expose whatever
//     directory it happened to be started in);
//   - a confined request path is validated BEFORE anything is created: its
//     deepest existing ancestor is symlink-evaluated, the not-yet-existing
//     remainder is spliced on textually, and the projection must stay inside
//     the evaluated root -- so a refused path creates no directories (the
//     create-after-validate bug from PR #34 review);
//   - only then is the directory created 0700 and re-checked on its final
//     physical path (defense against a check-to-create swap to a symlink; if
//     that final check fails, a confined directory may already exist inside
//     the root, which is an acceptable residue);
//   - an unconfined (AllowAnyWorkdir) request is used as-is.
func (s Service) resolveWorkdir(requested, runID string, opts Options) (string, error) {
	root := opts.WorkspaceRoot
	if root == "" {
		root = s.Paths.Workspaces
	}
	confined := root != "" && !opts.AllowAnyWorkdir
	if confined {
		absRoot, err := filepath.Abs(root)
		if err != nil {
			return "", err
		}
		root = absRoot
		if err := os.MkdirAll(root, 0o700); err != nil {
			return "", err
		}
	}
	requested = strings.TrimSpace(requested)
	if requested == "" {
		if !confined {
			cwd, err := os.Getwd()
			if err != nil {
				return "", err
			}
			return filepath.Abs(cwd)
		}
		name := workspaceDirName(runID)
		if name == "" {
			return "", fmt.Errorf("record policy: run_id %q cannot name a workspace directory; provide an explicit workdir inside %q", runID, root)
		}
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
		return confineToWorkspace(root, dir)
	}
	abs, err := filepath.Abs(requested)
	if err != nil {
		return "", err
	}
	if !confined {
		return abs, nil
	}
	// Validate first: nothing may be created for a path that projects outside
	// the workspace root.
	if err := confinePendingWorkdir(root, abs); err != nil {
		return "", err
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return "", err
	}
	// Final check on the physical path: if the directory (or an ancestor) was
	// swapped to a symlink between the pre-check and the creation, this
	// catches it. On failure the request is still refused even though the
	// created directory may remain inside the root -- an acceptable residue.
	return confineToWorkspace(root, abs)
}

// confinePendingWorkdir is the create-time pre-check for a confined workdir
// candidate that may not exist yet. It performs no filesystem writes: the root
// and the deepest existing ancestor of dir are symlink-evaluated, the
// remaining (cleaned) segments are spliced on textually, and the projection
// must stay inside the evaluated root. A `..` among the remaining segments is
// refused outright. A refused request therefore leaves the filesystem
// untouched.
func confinePendingWorkdir(root, dir string) error {
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	remaining := ""
	probe := dir
	for {
		parent := filepath.Dir(probe)
		if parent == probe {
			break // reached the filesystem top
		}
		if _, statErr := os.Lstat(probe); statErr == nil {
			break // deepest existing ancestor found
		}
		seg := filepath.Base(probe)
		if seg == ".." || seg == "." {
			return fmt.Errorf("record policy: workdir %q contains a relative segment; use an absolute path inside the workspace root %q", dir, rootReal)
		}
		if remaining == "" {
			remaining = seg
		} else {
			remaining = filepath.Join(seg, remaining)
		}
		probe = parent
	}
	probeReal, err := filepath.EvalSymlinks(probe)
	if err != nil {
		return err
	}
	estimate := probeReal
	if remaining != "" {
		estimate = filepath.Join(probeReal, remaining)
	}
	rel, relErr := filepath.Rel(rootReal, estimate)
	if !relInsideRoot(rel, relErr) {
		return fmt.Errorf("record policy: workdir %q resolves outside the workspace root %q; choose a directory under the workspace root (or set Options.AllowAnyWorkdir for local use)", dir, rootReal)
	}
	return nil
}

// confineToWorkspace verifies dir resolves inside root (following symlinks on
// both sides) and returns the resolved physical path used as the child cwd.
func confineToWorkspace(root, dir string) (string, error) {
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	dirReal, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", err
	}
	rel, relErr := filepath.Rel(rootReal, dirReal)
	if !relInsideRoot(rel, relErr) {
		return "", fmt.Errorf("record policy: workdir %q resolves outside the workspace root %q; choose a directory under the workspace root (or set Options.AllowAnyWorkdir for local use)", dir, rootReal)
	}
	return dirReal, nil
}

// relInsideRoot reports whether rel -- the evaluated dir relative to the
// evaluated root -- is a strict descent inside the root.
func relInsideRoot(rel string, relErr error) bool {
	return relErr == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
