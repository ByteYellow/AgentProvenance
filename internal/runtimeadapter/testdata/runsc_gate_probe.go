// The opt-in runtime probe passes this executable by FD; it is not installed
// in the workload image. Production integration is separately reviewed.
package main

import (
	"io"
	"os"
	"runtime"
	"syscall"
)

func main() {
	runtime.LockOSThread()
	if len(os.Args) < 2 {
		os.Exit(125)
	}
	gate := os.NewFile(3, "owned-start-gate")
	var release [1]byte
	if _, err := io.ReadFull(gate, release[:]); err != nil || release[0] != 0xa5 {
		os.Exit(125)
	}
	_ = gate.Close()
	if err := syscall.Exec(os.Args[1], os.Args[1:], os.Environ()); err != nil {
		os.Exit(126)
	}
}
