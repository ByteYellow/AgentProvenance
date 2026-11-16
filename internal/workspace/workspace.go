//go:build linux || darwin

package workspace

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/byteyellow/agentprovenance/internal/ids"
	"golang.org/x/sys/unix"
)

const maxJournalBytes = 128 << 20

type Workspace struct {
	config Config
	// Tests inject crashes at durable protocol boundaries, without changing APIs.
	fault func(string) error
}

type intent struct {
	Receipt       Receipt `json:"receipt"`
	PlannedDigest string  `json:"planned_digest,omitempty"`
}

type journal struct {
	Schema  string       `json:"schema"`
	RunID   string       `json:"run_id"`
	Limits  Limits       `json:"limits"`
	RootID  fileIdentity `json:"root_id"`
	View    View         `json:"view"`
	Pending *intent      `json:"pending,omitempty"`
}

func normalizeLimits(l Limits) (Limits, error) {
	if l.FileBytes == 0 {
		l.FileBytes = 2 << 20
	}
	if l.TotalBytes == 0 {
		l.TotalBytes = 16 << 20
	}
	if l.Entries == 0 {
		l.Entries = 1024
	}
	if l.OutputBytes == 0 {
		l.OutputBytes = 2 << 20
	}
	if l.FileBytes < 1 || l.FileBytes > 32<<20 || l.TotalBytes < l.FileBytes || l.TotalBytes > 128<<20 || l.Entries < 1 || l.Entries > 8192 || l.OutputBytes < 1 || l.OutputBytes > 32<<20 {
		return l, ErrLimit
	}
	return l, nil
}

func validID(s string) bool {
	if s == "" || len(s) > 256 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func validTarget(t Target) bool {
	return validID(t.ProducerID) && validID(t.InstanceID) && validID(t.Generation)
}

func configBinding(b WorkspaceBinding) WorkspaceBinding {
	b.Revision, b.ManifestDigest, b.ManifestRef, b.EvidenceRef = 0, "", "", ""
	return b
}

func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// Open creates the initial binding or recovers its existing journal. Existing
// identity, scope, permissions, limits, and run are immutable for this StateDir.
func Open(ctx context.Context, c Config) (*Workspace, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.Objects.DB == nil || c.Objects.Tx != nil || c.CurrentTarget == nil || !validID(c.RunID) || !validID(c.Binding.WorkspaceID) || !validTarget(c.Binding.Target) {
		return nil, ErrInvalid
	}
	if c.Binding.Mode == "" {
		c.Binding.Mode = RemoteAuthoritative
	}
	if c.Binding.Mode != RemoteAuthoritative {
		return nil, ErrInvalid
	}
	if !filepath.IsAbs(c.StateDir) || filepath.Clean(c.StateDir) != c.StateDir || !filepath.IsAbs(c.Binding.Root) || filepath.Clean(c.Binding.Root) != c.Binding.Root || c.Binding.Root == "/" {
		return nil, ErrUnsafePath
	}
	if within(c.Binding.Root, c.StateDir) || within(c.StateDir, c.Binding.Root) {
		return nil, ErrUnsafePath
	}
	if c.Objects.Paths.Provenance == "" {
		c.Objects.Paths.Provenance = filepath.Join(c.Objects.Paths.Root, "provenance")
	}
	for _, p := range []string{c.Objects.Paths.Root, c.Objects.Paths.DB, c.Objects.Paths.Provenance} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || within(c.Binding.Root, p) {
			return nil, ErrUnsafePath
		}
	}
	var err error
	c.Limits, err = normalizeLimits(c.Limits)
	if err != nil {
		return nil, err
	}
	c.Binding = configBinding(c.Binding)
	c.Binding.AllowedOperations = append([]Operation(nil), c.Binding.AllowedOperations...)
	sort.Slice(c.Binding.AllowedOperations, func(i, j int) bool { return c.Binding.AllowedOperations[i] < c.Binding.AllowedOperations[j] })
	if len(c.Binding.AllowedOperations) == 0 {
		return nil, ErrInvalid
	}
	for i, op := range c.Binding.AllowedOperations {
		switch op {
		case Read, Write, Edit, Rename, Delete, Chmod, Execute:
		default:
			return nil, ErrInvalid
		}
		if i > 0 && c.Binding.AllowedOperations[i-1] == op {
			return nil, ErrInvalid
		}
	}
	parent, err := openDir(filepath.Dir(c.StateDir))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	if err := unix.Mkdirat(int(parent.Fd()), filepath.Base(c.StateDir), 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	if err := parent.Sync(); err != nil {
		return nil, err
	}
	w := &Workspace{config: c}
	_, err = w.withLease(ctx, Request{WorkspaceID: c.Binding.WorkspaceID, Target: c.Binding.Target}, "", true, func(s *journal, root, dir *os.File, o observation) (View, error) { return s.View, nil })
	if err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Workspace) checkTarget(ctx context.Context, requested Target) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validTarget(requested) || requested != w.config.Binding.Target {
		return ErrStaleTarget
	}
	actual, err := w.config.CurrentTarget(ctx)
	if err != nil {
		return err
	}
	if !validTarget(actual) || actual != requested {
		return ErrStaleTarget
	}
	return nil
}

func (w *Workspace) withLease(ctx context.Context, req Request, op Operation, create bool, fn func(*journal, *os.File, *os.File, observation) (View, error)) (View, error) {
	if req.WorkspaceID != w.config.Binding.WorkspaceID || (req.ToolCallID != "" && !validID(req.ToolCallID)) {
		return View{}, ErrInvalid
	}
	if err := w.checkTarget(ctx, req.Target); err != nil {
		return View{}, err
	}
	if op != "" {
		allowed := false
		for _, candidate := range w.config.Binding.AllowedOperations {
			allowed = allowed || candidate == op
		}
		if !allowed {
			return View{}, ErrForbidden
		}
	}
	dir, err := openDir(w.config.StateDir)
	if err != nil {
		return View{}, err
	}
	defer dir.Close()
	var st unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &st); err != nil {
		return View{}, err
	}
	if int(st.Uid) != os.Geteuid() || st.Mode&0o077 != 0 {
		return View{}, ErrUnsafePath
	}
	lock, err := acquire(ctx, dir)
	if err != nil {
		return View{}, err
	}
	defer lock.Close()
	if err := w.checkTarget(ctx, req.Target); err != nil {
		return View{}, err
	}
	root, err := openDir(w.config.Binding.Root)
	if err != nil {
		return View{}, err
	}
	defer root.Close()
	rootID, err := identity(root)
	if err != nil {
		return View{}, err
	}
	s, err := loadJournal(dir)
	fresh := errors.Is(err, os.ErrNotExist) && create
	if err != nil && !fresh {
		return View{}, err
	}
	if fresh {
		info, err := lock.Stat()
		if err != nil {
			return View{}, err
		}
		if info.Size() != 0 {
			return View{}, ErrRecovery
		}
		s = journal{Schema: SchemaVersion, RunID: w.config.RunID, Limits: w.config.Limits, RootID: rootID, View: View{Binding: w.config.Binding}}
	} else if s.Schema != SchemaVersion || s.RootID != rootID || s.RunID != w.config.RunID || s.Limits != w.config.Limits || !reflect.DeepEqual(configBinding(s.View.Binding), w.config.Binding) {
		return View{}, ErrConflict
	} else if s.View.Binding.ManifestDigest != s.View.Snapshot.Digest || s.View.Snapshot.Digest != snapshotDigest(s.View.Snapshot.Entries) || s.View.Binding.ManifestRef == "" || s.View.Binding.EvidenceRef != s.View.LastReceipt.Ref {
		return View{}, ErrRecovery
	}
	if !fresh {
		if err := validateHead(ctx, w.config.Objects, s); err != nil {
			return s.View, errors.Join(ErrRecovery, err)
		}
	}
	o, err := scan(ctx, root, s.Limits)
	if err != nil {
		return s.View, err
	}
	if err := w.checkTarget(ctx, req.Target); err != nil {
		return s.View, err
	}
	if err := w.checkRoot(rootID); err != nil {
		return s.View, err
	}
	if fresh {
		r := newReceipt(s, Request{}, "bind")
		r.Outcome = "observed"
		if err := w.commit(ctx, dir, &s, o, r, true, nil); err != nil {
			return View{}, err
		}
	} else if s.Pending != nil {
		r := s.Pending.Receipt
		r.Kind, r.Outcome, r.Claim = "recovery_observation", "outcome_unknown", "filesystem_observation"
		if err := w.commit(ctx, dir, &s, o, r, true, nil); err != nil {
			return s.View, errors.Join(ErrRecovery, err)
		}
	} else if o.Digest != s.View.Snapshot.Digest {
		r := newReceipt(s, Request{}, "external_observation")
		r.Outcome = "observed"
		if err := w.commit(ctx, dir, &s, o, r, true, nil); err != nil {
			return s.View, err
		}
	}
	// A surviving lock marks a published binding, so a lost head never silently
	// creates a new revision history. Mark existing heads too after a crash.
	if _, err := lock.WriteAt([]byte(SchemaVersion+"\n"), 0); err != nil {
		return s.View, err
	}
	if err := lock.Sync(); err != nil {
		return s.View, err
	}
	return fn(&s, root, dir, o)
}

func loadJournal(dir *os.File) (journal, error) {
	f, err := openAt(dir, "state.json", unix.O_RDONLY, 0)
	if err != nil {
		return journal{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return journal{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxJournalBytes {
		return journal{}, ErrRecovery
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxJournalBytes+1))
	if err != nil {
		return journal{}, err
	}
	if len(raw) > maxJournalBytes {
		return journal{}, ErrLimit
	}
	var s journal
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&s); err != nil {
		return s, errors.Join(ErrRecovery, err)
	}
	if decoder.Decode(new(any)) != io.EOF {
		return s, ErrRecovery
	}
	return s, nil
}

func saveJournal(dir *os.File, s journal) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if len(raw) > maxJournalBytes {
		return ErrLimit
	}
	return atomicWrite(dir, "state.json", ".state-"+ids.New("tmp"), raw, 0o600, false)
}

func newReceipt(s journal, req Request, kind string) Receipt {
	r := Receipt{ID: ids.New("wop"), Kind: kind, Claim: "filesystem_observation", ToolCallID: req.ToolCallID, Path: req.Path,
		InputRevision: s.View.Binding.Revision, InputManifest: s.View.Binding.ManifestDigest, InputManifestRef: s.View.Binding.ManifestRef,
		StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	switch Operation(kind) {
	case Read, Write, Edit, Rename, Delete, Chmod, Execute:
		r.Operation = Operation(kind)
	}
	return r
}

func (w *Workspace) checkpoint(stage string) error {
	if w.fault != nil {
		return w.fault(stage)
	}
	return nil
}

func (w *Workspace) begin(dir *os.File, s *journal, r Receipt, planned string) error {
	if s.View.Binding.Revision == ^uint64(0) {
		return ErrLimit
	}
	s.Pending = &intent{Receipt: r, PlannedDigest: planned}
	if err := saveJournal(dir, *s); err != nil {
		return err
	}
	return w.checkpoint("after_intent")
}

// Inspect reconciles external changes and pending intents under the shared lease.
func (w *Workspace) Inspect(ctx context.Context, req Request) (View, error) {
	return w.withLease(ctx, req, Read, false, func(s *journal, root, dir *os.File, o observation) (View, error) {
		return s.View, preconditions(s, req, false)
	})
}

func (w *Workspace) checkRoot(want fileIdentity) error {
	f, err := openDir(w.config.Binding.Root)
	if err != nil {
		return err
	}
	defer f.Close()
	got, err := identity(f)
	if err != nil {
		return err
	}
	if got != want {
		return ErrChanged
	}
	return nil
}

func preconditions(s *journal, req Request, required bool) error {
	if required && req.ExpectedRevision == nil && req.ExpectedDigest == "" {
		return ErrInvalid
	}
	if req.ExpectedRevision != nil && *req.ExpectedRevision != s.View.Binding.Revision {
		return ErrConflict
	}
	if req.ExpectedDigest != "" {
		if req.Path == "" {
			return ErrInvalid
		}
		if req.ExpectedDigest != Absent {
			b, err := hex.DecodeString(req.ExpectedDigest)
			if err != nil || len(b) != 32 || strings.ToLower(req.ExpectedDigest) != req.ExpectedDigest {
				return ErrInvalid
			}
		}
		e := findEntry(s.View.Snapshot, req.Path)
		if req.ExpectedDigest == Absent {
			if e != nil {
				return ErrConflict
			}
		} else if e == nil || e.Directory || e.Hash != req.ExpectedDigest {
			return ErrConflict
		}
	}
	return nil
}

func findEntry(s Snapshot, path string) *Entry {
	for i := range s.Entries {
		if s.Entries[i].Path == path {
			return &s.Entries[i]
		}
	}
	return nil
}

func checkSpelling(s Snapshot, path string) error {
	if err := validatePath(path); err != nil {
		return err
	}
	for _, e := range s.Entries {
		for _, candidate := range []string{path, filepath.Dir(path)} {
			if strings.EqualFold(candidate, e.Path) && candidate != e.Path {
				return ErrUnsafePath
			}
		}
		parts := strings.Split(path, "/")
		for i := 1; i < len(parts); i++ {
			p := strings.Join(parts[:i], "/")
			if strings.EqualFold(p, e.Path) && p != e.Path {
				return ErrUnsafePath
			}
		}
	}
	return nil
}

func (w *Workspace) ReadFile(ctx context.Context, req Request) (ReadResult, error) {
	var data []byte
	var hash string
	v, err := w.withLease(ctx, req, Read, false, func(s *journal, root, dir *os.File, o observation) (View, error) {
		if err := checkSpelling(o.Snapshot, req.Path); err != nil {
			return s.View, err
		}
		if err := preconditions(s, req, false); err != nil {
			return s.View, err
		}
		e := findEntry(o.Snapshot, req.Path)
		if e == nil {
			return s.View, os.ErrNotExist
		}
		if e.Directory {
			return s.View, ErrUnsafePath
		}
		r := newReceipt(*s, req, string(Read))
		r.Outcome = "observed"
		if err := w.commit(ctx, dir, s, o, r, false, nil); err != nil {
			return s.View, err
		}
		data, hash = o.data[req.Path], e.Hash
		return s.View, nil
	})
	return ReadResult{View: v, Data: data, SHA256: hash}, err
}

func (w *Workspace) WriteFile(ctx context.Context, req WriteRequest) (View, error) {
	if int64(len(req.Data)) > w.config.Limits.FileBytes {
		return View{}, ErrLimit
	}
	data := bytes.Clone(req.Data)
	return w.mutate(ctx, req.Request, Write, func(o observation) (mutation, error) {
		mode := fs.FileMode(0o644)
		e := findEntry(o.Snapshot, req.Path)
		if e != nil {
			mode = o.mode[req.Path]
		}
		if req.Mode != nil {
			if !supportedMode(*req.Mode) {
				return mutation{}, ErrInvalid
			}
			if e != nil && *req.Mode != mode {
				return mutation{}, ErrInvalid
			}
			mode = *req.Mode
		}
		return mutation{kind: Write, path: req.Path, data: data, mode: mode, create: e == nil}, nil
	})
}

func (w *Workspace) EditFile(ctx context.Context, req EditRequest) (View, error) {
	if len(req.Old) == 0 || req.Count <= 0 {
		return View{}, ErrInvalid
	}
	if int64(len(req.Old)) > w.config.Limits.FileBytes || int64(len(req.New)) > w.config.Limits.FileBytes {
		return View{}, ErrLimit
	}
	old, replacement := bytes.Clone(req.Old), bytes.Clone(req.New)
	return w.mutate(ctx, req.Request, Edit, func(o observation) (mutation, error) {
		data := o.data[req.Path]
		if bytes.Count(data, old) != req.Count {
			return mutation{}, ErrConflict
		}
		size := int64(len(data)) + int64(req.Count)*int64(len(replacement)-len(old))
		if size > w.config.Limits.FileBytes {
			return mutation{}, ErrLimit
		}
		return mutation{kind: Edit, path: req.Path, data: bytes.ReplaceAll(data, old, replacement), mode: o.mode[req.Path]}, nil
	})
}

func (w *Workspace) RenameFile(ctx context.Context, req RenameRequest) (View, error) {
	return w.mutate(ctx, req.Request, Rename, func(o observation) (mutation, error) {
		if err := checkSpelling(o.Snapshot, req.Destination); err != nil {
			return mutation{}, err
		}
		if findEntry(o.Snapshot, req.Destination) != nil {
			return mutation{}, ErrConflict
		}
		if p := filepath.Dir(req.Destination); p != "." {
			e := findEntry(o.Snapshot, p)
			if e == nil || !e.Directory {
				return mutation{}, ErrUnsafePath
			}
		}
		return mutation{kind: Rename, path: req.Path, destination: req.Destination}, nil
	})
}

func (w *Workspace) DeleteFile(ctx context.Context, req Request) (View, error) {
	return w.mutate(ctx, req, Delete, func(o observation) (mutation, error) { return mutation{kind: Delete, path: req.Path}, nil })
}

func (w *Workspace) ChmodFile(ctx context.Context, req ChmodRequest) (View, error) {
	if !supportedMode(req.Mode) {
		return View{}, ErrInvalid
	}
	return w.mutate(ctx, req.Request, Chmod, func(o observation) (mutation, error) {
		return mutation{kind: Chmod, path: req.Path, data: o.data[req.Path], mode: req.Mode}, nil
	})
}

func supportedMode(mode fs.FileMode) bool { return mode & ^fs.FileMode(0o777) == 0 && mode&0o400 != 0 }

// Intent durability is a potentially slow boundary. Recheck after it, so a
// detected external write never gets overwritten by the already-validated plan.
func (w *Workspace) verifyInput(ctx context.Context, dir, root *os.File, s *journal) error {
	check, err := scan(ctx, root, s.Limits)
	if err != nil {
		return errors.Join(ErrRecovery, err)
	}
	if err := w.checkTarget(ctx, s.View.Binding.Target); err != nil {
		return errors.Join(ErrRecovery, err)
	}
	if err := w.checkRoot(s.RootID); err != nil {
		return errors.Join(ErrRecovery, err)
	}
	if check.Digest == s.View.Snapshot.Digest {
		return nil
	}
	r := s.Pending.Receipt
	r.Kind, r.Outcome, r.Claim = "external_observation", "conflict", "filesystem_observation"
	if err := w.commit(ctx, dir, s, check, r, true, nil); err != nil {
		return errors.Join(ErrRecovery, err)
	}
	return ErrConflict
}

func (w *Workspace) mutate(ctx context.Context, req Request, op Operation, plan func(observation) (mutation, error)) (View, error) {
	return w.withLease(ctx, req, op, false, func(s *journal, root, dir *os.File, o observation) (View, error) {
		if err := checkSpelling(o.Snapshot, req.Path); err != nil {
			return s.View, err
		}
		if err := preconditions(s, req, true); err != nil {
			return s.View, err
		}
		e := findEntry(o.Snapshot, req.Path)
		if e != nil && e.Directory {
			return s.View, ErrUnsafePath
		}
		if e == nil && op != Write {
			return s.View, os.ErrNotExist
		}
		if p := filepath.Dir(req.Path); p != "." {
			e := findEntry(o.Snapshot, p)
			if e == nil || !e.Directory {
				return s.View, ErrUnsafePath
			}
		}
		m, err := plan(o)
		if err != nil {
			return s.View, err
		}
		planned, err := plannedSnapshot(o.Snapshot, m, s.Limits)
		if err != nil {
			return s.View, err
		}
		r := newReceipt(*s, req, string(op))
		r.Destination = m.destination
		if err := w.checkTarget(ctx, req.Target); err != nil {
			return s.View, err
		}
		if err := w.begin(dir, s, r, planned.Digest); err != nil {
			return s.View, errors.Join(ErrRecovery, err)
		}
		if err := w.verifyInput(ctx, dir, root, s); err != nil {
			return s.View, err
		}
		if err := apply(root, m, r.ID); err != nil {
			return s.View, errors.Join(ErrRecovery, err)
		}
		if err := w.checkpoint("after_apply"); err != nil {
			return s.View, errors.Join(ErrRecovery, err)
		}
		after, err := scan(ctx, root, s.Limits)
		if err != nil {
			return s.View, errors.Join(ErrRecovery, err)
		}
		if err := w.checkTarget(ctx, req.Target); err != nil {
			return s.View, errors.Join(ErrRecovery, err)
		}
		if err := w.checkRoot(s.RootID); err != nil {
			return s.View, errors.Join(ErrRecovery, err)
		}
		r.Outcome, r.Claim = "applied", "managed_operation_with_observed_boundaries"
		var resultErr error
		if after.Digest != planned.Digest {
			r.Outcome, r.Claim, resultErr = "external_changes_observed", "filesystem_observation", ErrChanged
		}
		if err := w.commit(ctx, dir, s, after, r, true, nil); err != nil {
			return s.View, errors.Join(ErrRecovery, err)
		}
		return s.View, resultErr
	})
}

// ObserveExecution calls an existing runner once while holding the managed-tool
// lease. The callback must honor ctx and use input.Binding.Root as its workdir.
// Any callback error is still followed by an output observation where possible.
func (w *Workspace) ObserveExecution(ctx context.Context, req Request, run func(context.Context, ExecutionInput) (ExecutionResult, error)) (View, error) {
	if run == nil || req.ExpectedRevision == nil || req.Path != "" || req.ExpectedDigest != "" {
		return View{}, ErrInvalid
	}
	return w.withLease(ctx, req, Execute, false, func(s *journal, root, dir *os.File, o observation) (View, error) {
		if err := preconditions(s, req, true); err != nil {
			return s.View, err
		}
		r := newReceipt(*s, req, string(Execute))
		if err := w.begin(dir, s, r, ""); err != nil {
			return s.View, errors.Join(ErrRecovery, err)
		}
		if err := w.verifyInput(ctx, dir, root, s); err != nil {
			return s.View, err
		}
		input := ExecutionInput{Binding: s.View.Binding, Snapshot: s.View.Snapshot}
		input.Binding.AllowedOperations = append([]Operation(nil), input.Binding.AllowedOperations...)
		input.Snapshot.Entries = append([]Entry(nil), input.Snapshot.Entries...)
		result, runErr := run(ctx, input)
		// Completion evidence must still be attempted after caller cancellation.
		finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if err := w.checkTarget(finish, req.Target); err != nil {
			return s.View, errors.Join(ErrRecovery, runErr, err)
		}
		after, err := scan(finish, root, s.Limits)
		if err != nil {
			return s.View, errors.Join(ErrRecovery, runErr, err)
		}
		if err := w.checkTarget(finish, req.Target); err != nil {
			return s.View, errors.Join(ErrRecovery, runErr, err)
		}
		if err := w.checkRoot(s.RootID); err != nil {
			return s.View, errors.Join(ErrRecovery, runErr, err)
		}
		r.Outcome = "observed"
		if runErr != nil {
			r.Outcome = "runner_error"
		}
		if int64(len(result.Stdout))+int64(len(result.Stderr)) > s.Limits.OutputBytes {
			r.Stdout.State, r.Stderr.State = "limit_omitted", "limit_omitted"
			r.Stdout.SourceBytes, r.Stderr.SourceBytes = int64(len(result.Stdout)), int64(len(result.Stderr))
			result.Stdout, result.Stderr = nil, nil
			runErr = errors.Join(runErr, ErrLimit)
		}
		if err := w.commit(finish, dir, s, after, r, true, &result); err != nil {
			return s.View, errors.Join(ErrRecovery, runErr, err)
		}
		return s.View, runErr
	})
}

func plannedSnapshot(s Snapshot, m mutation, limits Limits) (Snapshot, error) {
	entries := append([]Entry(nil), s.Entries...)
	out := Snapshot{Entries: []Entry{}}
	for _, e := range entries {
		if e.Path == m.path {
			switch m.kind {
			case Delete:
				continue
			case Rename:
				e.Path = m.destination
			case Write, Edit, Chmod:
				e.Hash, e.SizeBytes, e.Mode = digestBytes(m.data), int64(len(m.data)), m.mode.String()
			}
		}
		out.Entries = append(out.Entries, e)
	}
	if m.create {
		out.Entries = append(out.Entries, Entry{FileEntry: fileEntry(m.path, m.data, m.mode)})
	}
	for _, e := range out.Entries {
		out.Bytes += e.SizeBytes
	}
	if out.Bytes > limits.TotalBytes || len(out.Entries) > limits.Entries {
		return out, ErrLimit
	}
	sort.Slice(out.Entries, func(i, j int) bool { return out.Entries[i].Path < out.Entries[j].Path })
	out.Digest = snapshotDigest(out.Entries)
	return out, nil
}
