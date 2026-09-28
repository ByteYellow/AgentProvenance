package agentcontext

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	MaxDiscoveryFiles  = 4096
	MaxDiscoveryVisits = 20000
	MaxDiscoveryBytes  = 256 << 20
	maxHeaderBytes     = 1 << 20
	maxHeaderLines     = 64
)

// Inventory contains identities and resume boundaries, never conversation text.
// An incomplete inventory cannot establish a unique automatic binding.
type Inventory struct {
	Harness     string      `json:"harness"`
	Root        string      `json:"root"`
	CatalogRoot string      `json:"catalog_root,omitempty"`
	Candidates  []Candidate `json:"candidates"`
	Complete    bool        `json:"complete"`
	Issues      []Issue     `json:"issues"`
}

type Candidate struct {
	Path            string       `json:"path"`
	SessionID       string       `json:"session_id"`
	ParentSessionID string       `json:"parent_session_id,omitempty"`
	AgentID         string       `json:"agent_id,omitempty"`
	Workdir         string       `json:"workdir,omitempty"`
	CreatedAt       string       `json:"created_at,omitempty"`
	ModifiedAt      time.Time    `json:"modified_at"`
	Size            int64        `json:"size"`
	Cursor          SourceCursor `json:"cursor"`
	Issue           string       `json:"issue,omitempty"`
}

// A cursor hashes complete decompressed physical lines. A growing final line
// stays outside the prefix and is retried, including in concatenated zstd files.
type SourceCursor struct {
	Lines  int64  `json:"lines"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
	Valid  bool   `json:"valid"`
}

type DiscoverOptions struct {
	Harness string
	Root    string
	// CatalogRoot optionally locates Codex state catalogs outside the scan root.
	// No ambient home directory is consulted for explicitly acquired sources.
	CatalogRoot string
	Workdir     string
	SessionID   string
	// Snapshot captures a pre-execution cursor for candidates in this workdir.
	Snapshot bool
}

func Discover(ctx context.Context, opts DiscoverOptions) (Inventory, error) {
	inv := Inventory{Harness: canonicalHarness(opts.Harness), Complete: true,
		Candidates: []Candidate{}, Issues: []Issue{}}
	if !supportedHarness(inv.Harness) {
		return inv, ErrInvalidArgument
	}
	root, err := filepath.Abs(opts.Root)
	if err != nil || opts.Root == "" {
		return inv, ErrInvalidArgument
	}
	inv.Root = root
	visits, budget := 0, int64(MaxDiscoveryBytes)
	type sourceFile struct {
		path string
		info fs.FileInfo
	}
	files := []sourceFile{}
	generations := map[string]string{}
	seen := map[string]int{}
	add := func(path, catalogID string, info fs.FileInfo) {
		if index, exists := seen[path]; exists {
			if catalogID != "" && inv.Candidates[index].SessionID != catalogID {
				inv.Candidates[index].Issue = "catalog_session_identity_conflict"
				inv.problem("catalog_session_identity_conflict")
			}
			return
		}
		if len(inv.Candidates) >= MaxDiscoveryFiles {
			inv.problem("discovery_count_limit")
			return
		}
		c := inspectCandidate(ctx, path, inv.Harness, &budget)
		if path == root && opts.SessionID != "" && c.Issue == "session_identity_missing" {
			c.SessionID, c.Issue = opts.SessionID, ""
		}
		if catalogID != "" && c.SessionID != catalogID {
			c.Issue = "catalog_session_identity_conflict"
			inv.problem(c.Issue)
		}
		c.Size, c.ModifiedAt = info.Size(), info.ModTime()
		if c.Issue != "" {
			inv.Complete = false
		}
		if opts.Snapshot && c.Issue == "" && (sameWorkdir(c.Workdir, opts.Workdir) || path == root || (opts.SessionID != "" && c.SessionID == opts.SessionID)) {
			cursor, code := snapshotCursor(ctx, path, &budget)
			c.Cursor = cursor
			if code != "" {
				c.Issue, inv.Complete = code, false
			}
		}
		seen[path] = len(inv.Candidates)
		inv.Candidates = append(inv.Candidates, c)
	}
	err = filepath.WalkDir(root, func(path string, ent fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			if path == root && os.IsNotExist(walkErr) {
				return fs.SkipAll
			}
			inv.Complete = false
			if len(inv.Issues) < 100 {
				inv.Issues = append(inv.Issues, Issue{Code: "discovery_unreadable"})
			}
			return nil
		}
		visits++
		if visits > MaxDiscoveryVisits {
			inv.Complete = false
			inv.Issues = append(inv.Issues, Issue{Code: "discovery_count_limit"})
			return fs.SkipAll
		}
		if ent.IsDir() || (path != root && !transcriptName(inv.Harness, ent.Name())) {
			return nil
		}
		if ent.Type()&os.ModeSymlink != 0 {
			if inv.Harness == "deepseek" {
				inv.problem("source_not_regular")
			}
			return nil
		}
		if len(files) >= MaxDiscoveryFiles {
			inv.Complete = false
			inv.Issues = append(inv.Issues, Issue{Code: "discovery_count_limit"})
			return fs.SkipAll
		}
		info, err := ent.Info()
		if err != nil || !info.Mode().IsRegular() {
			inv.Complete = false
			inv.Issues = append(inv.Issues, Issue{Code: "discovery_unreadable"})
			return nil
		}
		files = append(files, sourceFile{path, info})
		if inv.Harness == "deepseek" && path != root {
			generation, ok := deepseekGeneration(ent.Name())
			if !ok {
				inv.problem("source_generation_invalid")
			} else if directory := filepath.Dir(path); newerGeneration(generation, generations[directory]) {
				generations[directory] = generation
			}
		}
		return nil
	})
	if err == nil {
		for _, file := range files {
			if inv.Harness == "deepseek" && file.path != root {
				generation, ok := deepseekGeneration(filepath.Base(file.path))
				if ok && generation != generations[filepath.Dir(file.path)] {
					continue
				}
			}
			add(file.path, "", file.info)
			if budget <= 0 {
				inv.problem("discovery_size_limit")
				break
			}
		}
	}
	if err == nil && inv.Harness == "codex" {
		catalogRoot := opts.CatalogRoot
		if catalogRoot == "" {
			catalogRoot = root
		}
		catalogRoot, err = filepath.Abs(catalogRoot)
		if err == nil {
			inv.CatalogRoot = catalogRoot
			err = discoverCodexCatalogs(ctx, catalogRoot, &inv, &budget, add)
		}
	}
	if err == nil {
		err = ctx.Err()
	}
	return inv, err
}

func (inv *Inventory) problem(code string) {
	inv.Complete = false
	if len(inv.Issues) < 100 {
		inv.Issues = append(inv.Issues, Issue{Code: code})
	}
}

func supportedHarness(harness string) bool {
	switch harness {
	case "claude", "codex", "deepseek", "kimi", "grok":
		return true
	default:
		return false
	}
}

func transcriptName(harness, name string) bool {
	switch harness {
	case "codex":
		return strings.HasSuffix(name, ".jsonl") && strings.HasPrefix(name, "rollout-")
	case "claude":
		return strings.HasSuffix(name, ".jsonl")
	case "deepseek":
		return strings.HasPrefix(name, "session.v") && (strings.HasSuffix(name, ".jsonl") || strings.HasSuffix(name, ".jsonl.zstd"))
	case "kimi":
		return name == "wire.jsonl"
	case "grok":
		return name == "chat_history.jsonl"
	default:
		return false
	}
}

func openTranscript(path string) (io.Reader, func(), error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	r, closeDecoder, err := transcriptReader(f, path)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return r, func() { closeDecoder(); f.Close() }, nil
}

func inspectCandidate(ctx context.Context, path, harness string, budget *int64) Candidate {
	c := Candidate{Path: path}
	r, closeReader, err := openTranscript(path)
	if err != nil {
		c.Issue = "source_unreadable"
		return c
	}
	defer closeReader()
	limit := min(int64(maxHeaderBytes), *budget)
	reader := bufio.NewReader(io.LimitReader(r, limit))
	for line := 0; line < maxHeaderLines; line++ {
		if ctx.Err() != nil {
			c.Issue = "discovery_cancelled"
			return c
		}
		b, ended, err := readLine(reader)
		*budget -= int64(len(b))
		if !ended && err != nil && (len(b) == 0 || harness == "deepseek") {
			break
		}
		_ = visitSourceObjects(b, harness, func(top row, _ []byte, _ int) bool {
			switch harness {
			case "codex":
				if text(top, "type") != "session_meta" {
					return true
				}
				v := obj(top["payload"])
				c.SessionID, c.Workdir = text(v, "id", "session_id"), text(v, "cwd")
				c.CreatedAt = eventTime(top)
				c.ParentSessionID = text(obj(obj(obj(v["source"])["subagent"])["thread_spawn"]), "parent_thread_id")
				if c.ParentSessionID != "" {
					c.AgentID = c.SessionID
				}
			case "deepseek":
				if text(top, "type") != "session" {
					return true
				}
				c.SessionID, c.ParentSessionID = text(top, "id"), text(top, "parentSession")
				c.Workdir, c.CreatedAt = text(top, "cwd"), eventTime(top)
				if text(top, "origin") == "subagent" {
					c.AgentID = c.SessionID
				}
			case "claude":
				c.SessionID, c.AgentID = text(top, "sessionId", "session_id"), text(top, "agentId", "agent_id")
				c.Workdir, c.CreatedAt = text(top, "cwd"), eventTime(top)
			case "kimi", "grok":
				c.SessionID, c.Workdir = text(top, "sessionId", "session_id"), text(top, "cwd", "workdir")
				c.CreatedAt = eventTime(top)
			}
			return c.SessionID == ""
		})
		if c.SessionID != "" {
			return c
		}
	}
	c.Issue = "session_identity_missing"
	return c
}

func snapshotCursor(ctx context.Context, path string, budget *int64) (SourceCursor, string) {
	r, closeReader, err := openTranscript(path)
	if err != nil {
		return SourceCursor{}, "source_unreadable"
	}
	defer closeReader()
	limit := min(int64(MaxInputBytes), *budget)
	if limit <= 0 {
		return SourceCursor{}, "discovery_size_limit"
	}
	limited := &io.LimitedReader{R: r, N: limit + 1}
	reader := bufio.NewReaderSize(limited, 64<<10)
	hash := sha256.New()
	result := SourceCursor{}
	for {
		if ctx.Err() != nil {
			return result, "discovery_cancelled"
		}
		line, ended, err := readLine(reader)
		*budget -= int64(len(line))
		if limited.N == 0 || errors.Is(err, errLineLimit) {
			return result, "source_cursor_limit"
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return result, "source_cursor_unreadable"
		}
		if ended {
			result.Lines++
			result.Bytes += int64(len(line))
			hash.Write(line)
		}
		if err != nil {
			result.SHA256, result.Valid = hex.EncodeToString(hash.Sum(nil)), true
			return result, ""
		}
	}
}

type SelectOptions struct {
	Workdir   string
	SessionID string // explicit native identity, including resume
	Path      string // explicit transcript; no directory heuristic
	StartedAt time.Time
	EndedAt   time.Time
}

type Selection struct {
	Sources []SelectedSource `json:"sources"`
	Status  Status           `json:"status"`
	Issues  []Issue          `json:"issues"`
}

type SelectedSource struct {
	Candidate
	AfterLine       int64         `json:"after_line"`
	Binding         string        `json:"binding"`
	BindingEvidence []string      `json:"binding_evidence"`
	ResumeCursor    *SourceCursor `json:"resume_cursor,omitempty"`
}

// SelectSources never chooses by mtime. Without a native identity, only one new
// root session with matching cwd and a source timestamp in the run window can
// match. A resumed session requires an explicit identity and a verified prefix.
func SelectSources(ctx context.Context, before, after Inventory, opts SelectOptions) Selection {
	result := Selection{Status: NoInput, Sources: []SelectedSource{}, Issues: []Issue{}}
	if before.Harness != after.Harness || before.Root != after.Root || before.CatalogRoot != after.CatalogRoot {
		result.Status = Failed
		result.Issues = append(result.Issues, Issue{Code: "discovery_scope_changed"})
		return result
	}
	if (!before.Complete || !after.Complete) && opts.Path == "" {
		result.Status = Ambiguous
		result.Issues = append(result.Issues, Issue{Code: "discovery_incomplete"})
		return result
	}
	if !before.Complete || !after.Complete {
		result.Issues = append(result.Issues, Issue{Code: "discovery_incomplete"})
	}
	prior := map[string]Candidate{}
	type sessionIdentity struct{ session, agent string }
	priorIdentity := map[sessionIdentity]bool{}
	for _, c := range before.Candidates {
		prior[c.Path] = c
		priorIdentity[sessionIdentity{c.SessionID, c.AgentID}] = true
	}
	explicit := opts.Path != "" || opts.SessionID != ""
	var roots []Candidate
	for _, c := range after.Candidates {
		if c.Issue != "" {
			continue
		}
		if opts.Path != "" {
			want, err := filepath.Abs(opts.Path)
			if err != nil || c.Path != want {
				continue
			}
		}
		if opts.SessionID != "" && c.SessionID != opts.SessionID {
			continue
		}
		if !explicit {
			if _, existed := prior[c.Path]; existed || c.ParentSessionID != "" || c.AgentID != "" ||
				!sameWorkdir(c.Workdir, opts.Workdir) || !within(c.CreatedAt, opts.StartedAt, opts.EndedAt) {
				continue
			}
		}
		roots = append(roots, c)
	}
	if len(roots) != 1 {
		if len(roots) > 1 {
			result.Status = Ambiguous
			result.Issues = append(result.Issues, Issue{Code: "multiple_session_candidates"})
		} else if len(after.Candidates) > 0 {
			result.Status = Ambiguous
			result.Issues = append(result.Issues, Issue{Code: "session_binding_not_proven"})
		}
		return result
	}
	binding, evidence := "matched", []string{"unique_new_session", "source_workdir", "source_creation_within_run"}
	if explicit {
		binding, evidence = "explicit", []string{"user_selected_session"}
		if opts.Path != "" {
			evidence = append(evidence, "user_selected_file")
		}
	}
	root := roots[0]
	queue, seen := []Candidate{root}, map[string]bool{}
	for len(queue) > 0 {
		c := queue[0]
		queue = queue[1:]
		if seen[c.Path] {
			continue
		}
		seen[c.Path] = true
		selected := SelectedSource{Candidate: c, Binding: binding, BindingEvidence: append([]string{}, evidence...)}
		if c.Path != root.Path {
			if binding != "matched" {
				selected.Binding = "exact"
			}
			selected.BindingEvidence = append(selected.BindingEvidence, "source_parent_session_id", "bound_parent:"+c.ParentSessionID)
		}
		if old, exists := prior[c.Path]; exists {
			if old.SessionID != c.SessionID || !old.Cursor.Valid || !cursorMatches(ctx, c.Path, old.Cursor) {
				result.Status = Ambiguous
				result.Issues = append(result.Issues, Issue{Code: "source_changed_before_resume"})
				result.Sources = nil
				return result
			}
			selected.AfterLine = old.Cursor.Lines
			cursor := old.Cursor
			selected.ResumeCursor = &cursor
			selected.BindingEvidence = append(selected.BindingEvidence, "verified_source_prefix:"+old.Cursor.SHA256)
		} else if priorIdentity[sessionIdentity{c.SessionID, c.AgentID}] {
			// A moved or migrated log has no verified boundary in this capture.
			// Its old history must not become current execution by changing paths.
			result.Status = Ambiguous
			result.Issues = append(result.Issues, Issue{Code: "source_moved_before_resume"})
			result.Sources = nil
			return result
		}
		result.Sources = append(result.Sources, selected)
		children := map[string][]Candidate{}
		for _, child := range after.Candidates {
			if child.Issue == "" && child.ParentSessionID == c.SessionID && child.SessionID != c.SessionID {
				if _, existed := prior[child.Path]; !existed && !within(child.CreatedAt, opts.StartedAt, opts.EndedAt) {
					continue
				}
				children[child.SessionID] = append(children[child.SessionID], child)
			}
		}
		for _, copies := range children {
			if len(copies) != 1 {
				result.Issues = append(result.Issues, Issue{Code: "duplicate_child_session_sources"})
				continue
			}
			if seen[copies[0].Path] {
				result.Issues = append(result.Issues, Issue{Code: "session_parent_cycle"})
				continue
			}
			queue = append(queue, copies[0])
		}
	}
	sort.SliceStable(result.Sources, func(i, j int) bool { return result.Sources[i].Path < result.Sources[j].Path })
	result.Status = OK
	if len(result.Issues) > 0 {
		result.Status = Partial
	}
	return result
}

func (s SelectedSource) ParseOptions(harness string) ParseOptions {
	return ParseOptions{Harness: harness, Path: s.Path, SessionID: s.SessionID,
		ParentSessionID: s.ParentSessionID, AgentID: s.AgentID, Binding: s.Binding,
		BindingEvidence: s.BindingEvidence, AfterLine: s.AfterLine, Cursor: s.ResumeCursor}
}

// Check the prefix again on the same stream the parser consumes, so a file
// replaced after discovery cannot silently move a resume cursor to other data.
type prefixReader struct {
	r         io.Reader
	hash      hash.Hash
	remaining int64
}

func (r *prefixReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	checked := min(int64(n), r.remaining)
	if checked > 0 {
		r.hash.Write(p[:checked])
		r.remaining -= checked
	}
	return n, err
}

func (r *prefixReader) matches(cursor SourceCursor) bool {
	return r.remaining == 0 && hex.EncodeToString(r.hash.Sum(nil)) == cursor.SHA256
}

func cursorMatches(ctx context.Context, path string, cursor SourceCursor) bool {
	if !cursor.Valid || cursor.Bytes < 0 || cursor.Bytes > MaxInputBytes || ctx.Err() != nil {
		return false
	}
	r, closeReader, err := openTranscript(path)
	if err != nil {
		return false
	}
	defer closeReader()
	hash := sha256.New()
	n, err := io.CopyN(hash, r, cursor.Bytes)
	return err == nil && n == cursor.Bytes && hex.EncodeToString(hash.Sum(nil)) == cursor.SHA256
}

func within(ts string, start, end time.Time) bool {
	t, err := time.Parse(time.RFC3339Nano, ts)
	return err == nil && !start.IsZero() && !end.IsZero() && !t.Before(start) && !t.After(end)
}

func sameWorkdir(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	canonical := func(p string) string {
		p, err := filepath.Abs(p)
		if err != nil {
			return ""
		}
		if resolved, err := filepath.EvalSymlinks(p); err == nil {
			return resolved
		}
		return filepath.Clean(p)
	}
	return canonical(a) == canonical(b)
}
