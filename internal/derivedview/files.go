package derivedview

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

type entry struct {
	name string
	size int64
	open func() (io.ReadCloser, error)
}

type pathNode struct {
	name     string
	dir      bool
	explicit bool
}

type pathSet struct {
	limits Limits
	nodes  map[string]pathNode
}

// Preserve exact UTF-8 paths for hashing, but reject names that alias on common
// receiving filesystems. ZIP directory records may complete implicit parents.
func (s *pathSet) add(name string, dir bool) error {
	if !fs.ValidPath(name) || name == "." || !utf8.ValidString(name) || strings.ContainsAny(name, `\:`) {
		return fmt.Errorf("%w: invalid path %q", ErrUnsafe, name)
	}
	if len(name) > s.limits.MaxPathBytes || strings.Count(name, "/")+1 > s.limits.MaxPathDepth {
		return fmt.Errorf("%w: path dimensions", ErrLimit)
	}
	if s.nodes == nil {
		s.nodes = map[string]pathNode{}
	}
	parts := strings.Split(name, "/")
	for i, part := range parts {
		if strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return fmt.Errorf("%w: nonportable path %q", ErrUnsafe, name)
		}
		for _, c := range part {
			if unicode.IsControl(c) || strings.ContainsRune(`<>"|?*`, c) {
				return fmt.Errorf("%w: nonportable path %q", ErrUnsafe, name)
			}
		}
		base := strings.TrimRight(strings.ToUpper(strings.SplitN(part, ".", 2)[0]), " ")
		baseRunes := []rune(base)
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" ||
			(len(baseRunes) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && strings.ContainsRune("123456789\u00b9\u00b2\u00b3", baseRunes[3])) {
			return fmt.Errorf("%w: reserved device path %q", ErrUnsafe, name)
		}
		prefix := strings.Join(parts[:i+1], "/")
		key := foldedPath(prefix)
		last := i == len(parts)-1
		if i == 0 && (key == foldedPath(ManifestPath) || key == foldedPath(SignaturePath)) &&
			(!last || dir || (prefix != ManifestPath && prefix != SignaturePath)) {
			return fmt.Errorf("%w: reserved metadata path %q", ErrUnsafe, name)
		}
		old, exists := s.nodes[key]
		if exists {
			if old.name != prefix || !old.dir || (last && (!dir || old.explicit)) {
				return fmt.Errorf("%w: duplicate, aliased or conflicting path %q", ErrUnsafe, name)
			}
			if last {
				old.explicit = true
				s.nodes[key] = old
			}
		} else {
			if len(s.nodes) >= s.limits.MaxEntries {
				return fmt.Errorf("%w: path tree entries", ErrLimit)
			}
			s.nodes[key] = pathNode{name: prefix, dir: !last || dir, explicit: last}
		}
	}
	return nil
}

func foldedPath(name string) string {
	return strings.Map(func(r rune) rune {
		min := r
		for c := unicode.SimpleFold(r); c != r; c = unicode.SimpleFold(c) {
			if c < min {
				min = c
			}
		}
		return min
	}, norm.NFC.String(name))
}

func effectiveLimits(input Limits) (Limits, error) {
	defaults := DefaultLimits()
	for _, field := range []struct{ value, fallback *int }{
		{&input.MaxEntries, &defaults.MaxEntries}, {&input.MaxPathBytes, &defaults.MaxPathBytes}, {&input.MaxPathDepth, &defaults.MaxPathDepth},
	} {
		if *field.value < 0 {
			return Limits{}, fmt.Errorf("%w: negative limit", ErrLimit)
		}
		if *field.value == 0 {
			*field.value = *field.fallback
		}
	}
	for _, field := range []struct{ value, fallback *int64 }{
		{&input.MaxFileBytes, &defaults.MaxFileBytes}, {&input.MaxTotalBytes, &defaults.MaxTotalBytes},
		{&input.MaxManifestBytes, &defaults.MaxManifestBytes}, {&input.MaxSignatureBytes, &defaults.MaxSignatureBytes},
		{&input.MaxZIPBytes, &defaults.MaxZIPBytes}, {&input.MaxZIPMetadataBytes, &defaults.MaxZIPMetadataBytes},
	} {
		if *field.value < 0 || *field.value == math.MaxInt64 {
			return Limits{}, fmt.Errorf("%w: invalid byte limit", ErrLimit)
		}
		if *field.value == 0 {
			*field.value = *field.fallback
		}
	}
	return input, nil
}

type inventory struct {
	paths   pathSet
	entries map[string]entry
	count   int
	bytes   int64
}

func newInventory(limits Limits) *inventory {
	return &inventory{paths: pathSet{limits: limits}, entries: map[string]entry{}}
}

func (s *inventory) add(e entry, dir bool) error {
	s.count++
	l := s.paths.limits
	if s.count > l.MaxEntries {
		return fmt.Errorf("%w: entry count", ErrLimit)
	}
	if err := s.paths.add(e.name, dir); err != nil {
		return err
	}
	if dir {
		if e.size != 0 {
			return fmt.Errorf("%w: directory has payload %q", ErrUnsafe, e.name)
		}
		return nil
	}
	limit := l.MaxFileBytes
	if e.name == ManifestPath && l.MaxManifestBytes < limit {
		limit = l.MaxManifestBytes
	}
	if e.name == SignaturePath && l.MaxSignatureBytes < limit {
		limit = l.MaxSignatureBytes
	}
	if e.size < 0 || e.size > limit || e.size > l.MaxTotalBytes-s.bytes {
		return fmt.Errorf("%w: bytes for %q", ErrLimit, e.name)
	}
	s.bytes += e.size
	s.entries[e.name] = e
	return nil
}

func scanFS(ctx context.Context, fsys fs.FS, limits Limits) (*inventory, error) {
	s := newInventory(limits)
	var visit func(string, fs.FileInfo) error
	visit = func(name string, expected fs.FileInfo) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		f, err := openChecked(fsys, name, expected)
		if err != nil {
			return err
		}
		defer f.Close()
		dir, ok := f.(fs.ReadDirFile)
		if !ok {
			return fmt.Errorf("%w: FS must support batched ReadDir", ErrUnsafe)
		}
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			children, readErr := dir.ReadDir(128)
			for _, child := range children {
				if err := ctx.Err(); err != nil {
					return err
				}
				if !fs.ValidPath(child.Name()) || strings.Contains(child.Name(), "/") || child.Name() == "." {
					return fmt.Errorf("%w: invalid directory member", ErrUnsafe)
				}
				path := child.Name()
				if name != "." {
					path = name + "/" + path
				}
				info, err := child.Info()
				if err != nil {
					return err
				}
				if info.Mode().Type() != 0 && info.Mode().Type() != fs.ModeDir {
					return fmt.Errorf("%w: nonregular entry %q", ErrUnsafe, path)
				}
				e := entry{name: path, size: info.Size(), open: func() (io.ReadCloser, error) {
					return openChecked(fsys, path, info)
				}}
				if info.IsDir() {
					e.size = 0
				}
				if err := s.add(e, info.IsDir()); err != nil {
					return err
				}
				if info.IsDir() {
					if err := visit(path, info); err != nil {
						return err
					}
				}
			}
			if readErr == io.EOF {
				return ctx.Err()
			}
			if readErr != nil {
				return readErr
			}
			if len(children) == 0 {
				return io.ErrNoProgress
			}
		}
	}
	if err := visit(".", nil); err != nil {
		return nil, err
	}
	return s, nil
}

// A supplied FS must be an immutable snapshot with lstat-style DirEntry.Info.
// The check also catches replacement of ordinary OS files before any bytes are
// read. VerifyDirectory supplies a descriptor-relative implementation on Unix.
func openChecked(fsys fs.FS, name string, expected fs.FileInfo) (fs.File, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	actual, err := f.Stat()
	if err == nil && actual.Mode().Type() != 0 && actual.Mode().Type() != fs.ModeDir {
		err = fmt.Errorf("%w: nonregular open %q", ErrUnsafe, name)
	}
	if err == nil && expected != nil {
		if actual.Mode().Type() != expected.Mode().Type() || (!actual.IsDir() && actual.Size() != expected.Size()) {
			err = fmt.Errorf("%w: changed entry %q", ErrUnsafe, name)
		}
		if _, isOSFile := f.(*os.File); isOSFile && !os.SameFile(expected, actual) {
			err = fmt.Errorf("%w: replaced entry %q", ErrUnsafe, name)
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func streamEntry(ctx context.Context, e entry, dst io.Writer) (digest string, err error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	f, err := e.open()
	if err != nil {
		return "", err
	}
	defer func() {
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
	}()
	h := sha256.New()
	var out io.Writer = h
	if dst != nil {
		out = io.MultiWriter(h, dst)
	}
	n, err := io.CopyBuffer(out, io.LimitReader(contextReader{ctx: ctx, r: f}, e.size+1), make([]byte, 32<<10))
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if n != e.size {
		return "", fmt.Errorf("%w: entry length changed %q", ErrInvalid, e.name)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// InventoryFS hashes an existing, immutable payload. It never writes an export.
// Only the two reserved root metadata files are excluded. A ReplayInventory can
// instead be mapped directly to []File, with export-inventory.json added.
func InventoryFS(ctx context.Context, fsys fs.FS, limits Limits) ([]File, error) {
	l, err := effectiveLimits(limits)
	if err != nil {
		return nil, err
	}
	s, err := scanFS(ctx, fsys, l)
	if err != nil {
		return nil, err
	}
	files := []File{}
	for _, name := range sortedNames(s.entries) {
		if name == ManifestPath || name == SignaturePath {
			continue
		}
		e := s.entries[name]
		digest, err := streamEntry(ctx, e, nil)
		if err != nil {
			return nil, err
		}
		files = append(files, File{Path: name, SHA256: digest, Bytes: e.size})
	}
	return files, ctx.Err()
}

func sortedNames(entries map[string]entry) []string {
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
