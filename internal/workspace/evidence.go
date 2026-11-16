//go:build linux || darwin

package workspace

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/substrate/state"
	"golang.org/x/sys/unix"
)

func fileEntry(path string, data []byte, mode fs.FileMode) state.FileEntry {
	return state.FileEntry{Path: path, Hash: digestBytes(data), SizeBytes: int64(len(data)), Mode: mode.String()}
}

func changes(before, after Snapshot) []Change {
	old, current := map[string]Entry{}, map[string]Entry{}
	for _, e := range before.Entries {
		old[e.Path] = e
	}
	for _, e := range after.Entries {
		current[e.Path] = e
	}
	paths := map[string]bool{}
	for p := range old {
		paths[p] = true
	}
	for p := range current {
		paths[p] = true
	}
	var out []Change
	for p := range paths {
		a, aok := old[p]
		b, bok := current[p]
		if aok && bok && a.FileEntry == b.FileEntry && a.Directory == b.Directory {
			continue
		}
		c := Change{Path: p, Kind: "modified"}
		if aok {
			v := a.FileEntry
			c.Before = &v
		}
		if bok {
			v := b.FileEntry
			c.After = &v
		}
		switch {
		case !aok:
			c.Kind = "added"
		case !bok:
			c.Kind = "deleted"
		case a.Hash == b.Hash && a.Mode != b.Mode:
			c.Kind = "mode_changed"
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func payload(value any) (map[string]any, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	err = d.Decode(&result)
	return result, err
}

func putContent(objects provenance.ObjectStore, run, id string, data []byte, limit int64, syncRefs map[string]bool) (Content, error) {
	content := Content{SourceSHA256: digestBytes(data), SourceBytes: int64(len(data))}
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		content.State = "binary_omitted"
		return content, nil
	}
	c, err := objects.PutTextContent(provenance.TextContentInput{RunID: run, SourceID: id, Text: string(data), MaxBytes: limit})
	if err != nil {
		return Content{}, err
	}
	syncRefs[c.Ref] = true
	for _, part := range c.Chunks {
		syncRefs[part.Ref] = true
	}
	content.State, content.Ref, content.StoredSHA256, content.Redacted = "stored", c.Ref, c.SHA256, c.Redacted
	return content, nil
}

// Sync content-addressed objects before the FULL-synchronous database commit.
// This augments ObjectStore's existing atomic rename without changing that API.
func syncEvidence(ctx context.Context, tx *sql.Tx, refs map[string]bool, root string) error {
	dirs := map[string]bool{}
	for ref := range refs {
		var path string
		if err := tx.QueryRowContext(ctx, `SELECT path FROM provenance_objects WHERE hash=?`, ref).Scan(&path); err != nil {
			return err
		}
		if !within(root, path) {
			return ErrUnsafePath
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		err = f.Sync()
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		for p := filepath.Dir(path); within(root, p); p = filepath.Dir(p) {
			dirs[p] = true
			if p == root {
				break
			}
		}
	}
	// Children precede their containing directories, including a newly made root.
	paths := make([]string, 0, len(dirs))
	for p := range dirs {
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool { return len(paths[i]) > len(paths[j]) })
	for _, p := range paths {
		f, err := openDir(p)
		if err != nil {
			return err
		}
		err = f.Sync()
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	parent, err := openDir(filepath.Dir(root))
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}

func (w *Workspace) commit(ctx context.Context, dir *os.File, s *journal, observed observation, r Receipt, advance bool, result *ExecutionResult) error {
	if s.Pending != nil {
		r.PlannedManifest = s.Pending.PlannedDigest
	}
	next := *s
	next.Pending = nil
	if advance {
		if next.View.Binding.Revision == ^uint64(0) {
			return ErrLimit
		}
		next.View.Binding.Revision++
	}
	next.View.Snapshot = observed.Snapshot
	next.View.Snapshot.Entries = append([]Entry(nil), observed.Entries...)
	next.View.Binding.ManifestDigest = observed.Digest
	r.OutputRevision = next.View.Binding.Revision
	r.OutputManifest = observed.Digest
	r.EndedAt = time.Now().UTC().Format(time.RFC3339Nano)
	r.Changes = changes(s.View.Snapshot, observed.Snapshot)
	if result != nil {
		r.Record = result.Record
		r.ExitCode = &result.ExitCode
		if r.Record != nil {
			if r.Record.RunID != w.config.RunID || !validID(r.Record.RolloutID) || !validID(r.Record.AttemptID) || !validID(r.Record.BaseSnapshotID) {
				return ErrInvalid
			}
			var count int
			err := w.config.Objects.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM fork_attempts a JOIN rollouts r ON r.id=a.rollout_id JOIN snapshots sn ON sn.id=a.snapshot_id
				WHERE a.id=? AND r.id=? AND r.run_id=? AND sn.id=? AND a.workspace_path=?`, r.Record.AttemptID, r.Record.RolloutID, r.Record.RunID, r.Record.BaseSnapshotID, w.config.Binding.Root).Scan(&count)
			if err != nil {
				return err
			}
			if count != 1 {
				return fmt.Errorf("%w: record reference does not match workspace/run", ErrInvalid)
			}
		}
	}
	err := store.WithWriteTx(ctx, w.config.Objects.DB, func(tx *sql.Tx) error {
		var synchronous int
		if err := tx.QueryRowContext(ctx, `PRAGMA synchronous`).Scan(&synchronous); err != nil {
			return err
		}
		if synchronous < 2 {
			return fmt.Errorf("%w: evidence database requires synchronous=FULL", ErrInvalid)
		}
		objects := w.config.Objects
		objects.Tx = tx
		syncRefs := map[string]bool{}
		parents := []string{}
		for i := range next.View.Snapshot.Entries {
			e := &next.View.Snapshot.Entries[i]
			if e.Directory {
				e.Content = Content{State: "directory"}
				continue
			}
			previous := findEntry(s.View.Snapshot, e.Path)
			if previous != nil && previous.Hash == e.Hash && !previous.Directory {
				e.Content = previous.Content
			} else {
				c, err := putContent(objects, w.config.RunID, "workspace/"+w.config.Binding.WorkspaceID+"/"+r.ID+"/"+e.Path, observed.data[e.Path], s.Limits.FileBytes, syncRefs)
				if err != nil {
					return err
				}
				e.Content = c
			}
			if e.Content.Ref != "" {
				parents = append(parents, e.Content.Ref)
			}
		}
		if advance || next.View.Binding.ManifestRef == "" {
			body, err := payload(struct {
				Schema        string           `json:"schema"`
				Binding       WorkspaceBinding `json:"binding"`
				Revision      uint64           `json:"revision"`
				Snapshot      Snapshot         `json:"snapshot"`
				Limits        Limits           `json:"limits"`
				PathSemantics string           `json:"path_semantics"`
				Excluded      []string         `json:"excluded_components"`
			}{SchemaVersion, configBinding(next.View.Binding), next.View.Binding.Revision, next.View.Snapshot, s.Limits, "relative_exact_spelling_no_links_casefold_collisions_rejected", []string{".git", ".agentprov"}})
			if err != nil {
				return err
			}
			if s.View.Binding.ManifestRef != "" {
				parents = append(parents, s.View.Binding.ManifestRef)
			}
			obj, err := objects.PutExternalObject(provenance.ExternalObjectInput{RunID: w.config.RunID, Type: "workspace_manifest", SourceID: "workspace/" + w.config.Binding.WorkspaceID + "/" + r.ID + "/manifest", Parents: parents, Payload: body})
			if err != nil {
				return err
			}
			next.View.Binding.ManifestRef = obj.Hash
			syncRefs[obj.Hash] = true
		}
		r.OutputManifestRef = next.View.Binding.ManifestRef
		if result != nil && r.Stdout.State != "limit_omitted" {
			var err error
			r.Stdout, err = putContent(objects, w.config.RunID, r.ID+"/stdout", result.Stdout, s.Limits.OutputBytes, syncRefs)
			if err != nil {
				return err
			}
			r.Stderr, err = putContent(objects, w.config.RunID, r.ID+"/stderr", result.Stderr, s.Limits.OutputBytes, syncRefs)
			if err != nil {
				return err
			}
		}
		parents = nil
		for _, ref := range []string{s.View.Binding.EvidenceRef, r.InputManifestRef, r.OutputManifestRef, r.Stdout.Ref, r.Stderr.Ref} {
			if ref != "" {
				parents = append(parents, ref)
			}
		}
		body, err := payload(struct {
			Schema  string           `json:"schema"`
			Binding WorkspaceBinding `json:"binding"`
			Receipt Receipt          `json:"receipt"`
		}{SchemaVersion, configBinding(next.View.Binding), r})
		if err != nil {
			return err
		}
		obj, err := objects.PutExternalObject(provenance.ExternalObjectInput{RunID: w.config.RunID, Type: "workspace_operation", SourceID: "workspace/" + w.config.Binding.WorkspaceID + "/" + r.ID, Parents: parents, Payload: body})
		if err != nil {
			return err
		}
		r.Ref = obj.Hash
		syncRefs[obj.Hash] = true
		return syncEvidence(ctx, tx, syncRefs, objects.Paths.Provenance)
	})
	if err != nil {
		return err
	}
	if err := w.checkpoint("after_evidence"); err != nil {
		return err
	}
	next.View.Binding.EvidenceRef = r.Ref
	next.View.LastReceipt = r
	if err := saveJournal(dir, next); err != nil {
		return err
	}
	*s = next
	return w.checkpoint("after_head")
}

func validateHead(ctx context.Context, objects provenance.ObjectStore, s journal) error {
	for _, ref := range []string{s.View.Binding.ManifestRef, s.View.Binding.EvidenceRef} {
		var path string
		if err := objects.DB.QueryRowContext(ctx, `SELECT path FROM provenance_objects WHERE hash=? AND run_id=?`, ref, s.RunID).Scan(&path); err != nil {
			return err
		}
		if !within(objects.Paths.Provenance, path) {
			return ErrUnsafePath
		}
		dir, err := openDir(filepath.Dir(path))
		if err != nil {
			return err
		}
		f, err := openAt(dir, filepath.Base(path), unix.O_RDONLY, 0)
		dir.Close()
		if err != nil {
			return err
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > maxJournalBytes {
			f.Close()
			return ErrLimit
		}
		raw, err := io.ReadAll(io.LimitReader(f, maxJournalBytes+1))
		f.Close()
		if err != nil {
			return err
		}
		if len(raw) > maxJournalBytes {
			return ErrLimit
		}
		if "sha256:"+digestBytes(raw) != ref || !strings.HasPrefix(ref, "sha256:") {
			return ErrRecovery
		}
	}
	return nil
}
