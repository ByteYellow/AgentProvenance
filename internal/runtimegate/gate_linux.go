//go:build linux

// Package runtimegate implements the private FD entry used by the runsc adapter.
package runtimegate

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
)

const Entry = "__runtime-gate"

// Run is called before the CLI starts. The operator passes this executable by
// FD and owns the other end of FD 3. No workload runs until its identity has
// reached the authoritative checkpoint and the operator releases the pipe.
func Run(args []string) (bool, error) {
	if len(args) < 2 || args[1] != Entry {
		return false, nil
	}
	if len(args) < 3 || args[2] == "" {
		return true, fmt.Errorf("runtime gate: missing command")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	gate := os.NewFile(3, "runtime-start-gate")
	if gate == nil {
		return true, fmt.Errorf("runtime gate: missing control pipe")
	}
	defer gate.Close()
	info, err := gate.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		return true, fmt.Errorf("runtime gate: invalid control pipe")
	}
	var release [1]byte
	if _, err := io.ReadFull(gate, release[:]); err != nil || release[0] != 0xa5 {
		return true, fmt.Errorf("runtime gate: launch not authorized")
	}
	if err := gate.Close(); err != nil {
		return true, fmt.Errorf("runtime gate: close control pipe")
	}
	name := args[2]
	if !strings.ContainsRune(name, '/') {
		name, err = exec.LookPath(name)
		if err != nil {
			return true, fmt.Errorf("runtime gate: executable unavailable")
		}
	}
	if err := syscall.Exec(name, args[2:], os.Environ()); err != nil {
		return true, fmt.Errorf("runtime gate: workload exec failed")
	}
	panic("successful exec returned")
}
