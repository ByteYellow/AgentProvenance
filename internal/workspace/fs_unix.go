//go:build linux || darwin

package workspace

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/byteyellow/agentprovenance/internal/substrate/state"
	"golang.org/x/sys/unix"
)

type fileIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

func identity(f *os.File) (fileIdentity, error) {
	var st unix.Stat_t
	err := unix.Fstat(int(f.Fd()), &st)
	return fileIdentity{uint64(st.Dev), uint64(st.Ino)}, err
}

func openAt(dir *os.File, name string, flags int, mode uint32) (*os.File, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, mode)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func openDir(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrUnsafePath
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), "/")
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		next, err := openAt(dir, part, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		dir.Close()
		if err != nil {
			return nil, fmt.Errorf("%w: directory component: %v", ErrUnsafePath, err)
		}
		dir = next
	}
	return dir, nil
}

func validatePath(path string) error {
	if path == "" || len(path) > 4096 || !utf8.ValidString(path) || strings.ContainsAny(path, "\\\x00\r\n") || strings.HasPrefix(path, "/") {
		return ErrUnsafePath
	}
	parts := strings.Split(path, "/")
	if len(parts) > 64 {
		return ErrLimit
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || excluded(part) {
			return ErrUnsafePath
		}
	}
	return nil
}

func excluded(name string) bool {
	return strings.EqualFold(name, ".git") || strings.EqualFold(name, ".agentprov")
}

func parentDir(root *os.File, path string) (*os.File, string, error) {
	if err := validatePath(path); err != nil {
		return nil, "", err
	}
	dir, err := openAt(root, ".", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, "", err
	}
	parts := strings.Split(path, "/")
	for _, part := range parts[:len(parts)-1] {
		next, err := openAt(dir, part, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		dir.Close()
		if err != nil {
			return nil, "", fmt.Errorf("%w: %v", ErrUnsafePath, err)
		}
		dir = next
	}
	return dir, parts[len(parts)-1], nil
}

type observation struct {
	Snapshot
	data map[string][]byte
	mode map[string]fs.FileMode
}

func digestBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Only source metadata participates in revision identity, never storage refs.
func snapshotDigest(entries []Entry) string {
	files := make([]struct {
		state.FileEntry
		Directory bool
	}, len(entries))
	for i, e := range entries {
		files[i].FileEntry, files[i].Directory = e.FileEntry, e.Directory
	}
	raw, _ := json.Marshal(files)
	return digestBytes(raw)
}

func scan(ctx context.Context, root *os.File, limits Limits) (observation, error) {
	o := observation{Snapshot: Snapshot{Entries: []Entry{}}, data: map[string][]byte{}, mode: map[string]fs.FileMode{}}
	rootID, err := identity(root)
	if err != nil {
		return o, err
	}
	names := map[string]bool{}
	visited := 0
	var walk func(*os.File, string, int) error
	walk = func(parent *os.File, prefix string, depth int) error {
		if depth > 64 {
			return ErrLimit
		}
		dir, err := openAt(parent, ".", unix.O_RDONLY|unix.O_DIRECTORY, 0)
		if err != nil {
			return err
		}
		defer dir.Close()
		before, err := dir.Stat()
		if err != nil {
			return err
		}
		for {
			batch, readErr := dir.ReadDir(64)
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				return readErr
			}
			for _, de := range batch {
				if err := ctx.Err(); err != nil {
					return err
				}
				visited++
				if visited > limits.Entries {
					return ErrLimit
				}
				if excluded(de.Name()) {
					continue
				}
				path := prefix + de.Name()
				if err := validatePath(path); err != nil {
					return err
				}
				fold := strings.ToLower(path)
				if names[fold] {
					return fmt.Errorf("%w: case-fold collision", ErrUnsafePath)
				}
				names[fold] = true
				var st unix.Stat_t
				if err := unix.Fstatat(int(dir.Fd()), de.Name(), &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
					return err
				}
				isDir := st.Mode&unix.S_IFMT == unix.S_IFDIR
				if uint64(st.Dev) != rootID.Device || (st.Mode&unix.S_IFMT != unix.S_IFREG && !isDir) || (!isDir && st.Nlink != 1) || st.Mode&0o7000 != 0 {
					return fmt.Errorf("%w: unsupported entry %q", ErrUnsafePath, path)
				}
				flags := unix.O_RDONLY
				if isDir {
					flags |= unix.O_DIRECTORY
				}
				f, err := openAt(dir, de.Name(), flags, 0)
				if err != nil {
					return fmt.Errorf("%w: %v", ErrUnsafePath, err)
				}
				err = func() error {
					defer f.Close()
					id, err := identity(f)
					if err != nil {
						return err
					}
					info, err := f.Stat()
					if err != nil {
						return err
					}
					if id != (fileIdentity{uint64(st.Dev), uint64(st.Ino)}) || info.IsDir() != isDir {
						return ErrChanged
					}
					entry := Entry{FileEntry: state.FileEntry{Path: path, Mode: info.Mode().String()}, Directory: isDir}
					o.mode[path] = info.Mode().Perm()
					if isDir {
						o.Entries = append(o.Entries, entry)
						return walk(f, path+"/", depth+1)
					}
					limit := min(limits.FileBytes, limits.TotalBytes-o.Bytes)
					if info.Size() > limit {
						return ErrLimit
					}
					data, err := io.ReadAll(io.LimitReader(f, limit+1))
					if err != nil {
						return err
					}
					if int64(len(data)) > limit {
						return ErrLimit
					}
					after, err := f.Stat()
					if err != nil {
						return err
					}
					var current unix.Stat_t
					if err := unix.Fstatat(int(dir.Fd()), de.Name(), &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
						return ErrChanged
					}
					if !sameObservation(info, after) || int64(len(data)) != info.Size() || current.Ino != st.Ino || current.Dev != st.Dev || current.Nlink != 1 || current.Mode != st.Mode {
						return ErrChanged
					}
					entry.Hash, entry.SizeBytes = digestBytes(data), int64(len(data))
					o.Entries = append(o.Entries, entry)
					o.data[path] = data
					o.Bytes += int64(len(data))
					return nil
				}()
				if err != nil {
					return err
				}
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
		}
		after, err := dir.Stat()
		if err != nil {
			return err
		}
		if !sameObservation(before, after) {
			return ErrChanged
		}
		return nil
	}
	if err := walk(root, "", 0); err != nil {
		return o, err
	}
	sort.Slice(o.Entries, func(i, j int) bool { return o.Entries[i].Path < o.Entries[j].Path })
	o.Digest = snapshotDigest(o.Entries)
	return o, nil
}

func sameObservation(a, b fs.FileInfo) bool {
	return os.SameFile(a, b) && a.Size() == b.Size() && a.Mode() == b.Mode() && a.ModTime().Equal(b.ModTime())
}

func acquire(ctx context.Context, dir *os.File) (*os.File, error) {
	f, err := openAt(dir, "lock", unix.O_RDWR|unix.O_CREAT, 0o600)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		f.Close()
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || int(st.Uid) != os.Geteuid() || st.Mode&0o077 != 0 {
		f.Close()
		return nil, ErrUnsafePath
	}
	for {
		if err := ctx.Err(); err != nil {
			f.Close()
			return nil, err
		}
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			f.Close()
			return nil, err
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			f.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func atomicWrite(dir *os.File, name, temp string, data []byte, mode fs.FileMode, createOnly bool) error {
	f, err := openAt(dir, temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer unix.Unlinkat(int(dir.Fd()), temp, 0)
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if createOnly {
		err = renameNoReplace(int(dir.Fd()), temp, int(dir.Fd()), name)
	} else {
		err = unix.Renameat(int(dir.Fd()), temp, int(dir.Fd()), name)
	}
	if err != nil {
		return err
	}
	return dir.Sync()
}

type mutation struct {
	kind              Operation
	path, destination string
	data              []byte
	mode              fs.FileMode
	create            bool
}

func apply(root *os.File, m mutation, id string) error {
	src, name, err := parentDir(root, m.path)
	if err != nil {
		return err
	}
	defer src.Close()
	switch m.kind {
	case Write, Edit, Chmod:
		return atomicWrite(src, name, ".w01-"+id, m.data, m.mode, m.create)
	case Delete:
		if err := unix.Unlinkat(int(src.Fd()), name, 0); err != nil {
			return err
		}
		return src.Sync()
	case Rename:
		dst, dest, err := parentDir(root, m.destination)
		if err != nil {
			return err
		}
		defer dst.Close()
		if err := renameNoReplace(int(src.Fd()), name, int(dst.Fd()), dest); err != nil {
			return err
		}
		return errors.Join(src.Sync(), dst.Sync())
	}
	return ErrInvalid
}
