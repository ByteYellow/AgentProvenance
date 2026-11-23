// Package companion locates the optional, release-matched local CLI tools.
package companion

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// Digest is injected into the core binary after the tools binary is built.
var Digest string

var Required = errors.New("this operation requires agentprov-tools from the same release archive, or a build with -tags agentprov_tools")

func Path() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "", err
	}
	return verify(filepath.Dir(exe), Digest)
}

// Exec forwards the original CLI after Cobra has validated its flags. The
// helper replaces this process, so interactive signals and exit codes survive.
func Exec() error {
	path, err := Path()
	if err != nil {
		return err
	}
	return syscall.Exec(path, append([]string{path}, os.Args[1:]...), os.Environ())
}

func verify(dir, digest string) (string, error) {
	if len(digest) != 64 {
		return "", Required
	}
	path := filepath.Join(dir, "agentprov-tools")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("%w: %s", Required, path)
	}
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return "", fmt.Errorf("invalid tools executable: %s", path)
	}
	// Do not dispatch from a shared writable installation directory. Release
	// users can extract into a private directory below /tmp or install in bin.
	parent, err := os.Stat(dir)
	if err != nil {
		return "", err
	}
	if parent.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0022 != 0 {
		return "", fmt.Errorf("tools executable and its directory must not be group- or world-writable: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	if fmt.Sprintf("%x", h.Sum(nil)) != digest {
		return "", fmt.Errorf("agentprov-tools checksum mismatch: reinstall both binaries from the same release")
	}
	return path, nil
}
