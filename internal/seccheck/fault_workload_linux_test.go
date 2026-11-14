//go:build linux && (amd64 || arm64)

package seccheck

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The acceptance driver controls phases through its own isolated bind mount.
func TestSecCheckLiveFaultWorkload(t *testing.T) {
	if os.Getenv("AGENTPROV_SECCHECK_CHILD") != "1" {
		t.Skip("gVisor child only")
	}
	deadline := time.Now().Add(90 * time.Second)
	ack := func(phase string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join("/control", phase+".done"), []byte("done"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	wait := func(phase string) {
		t.Helper()
		for time.Now().Before(deadline) {
			if _, err := os.Stat(filepath.Join("/control", phase)); err == nil {
				return
			} else if !os.IsNotExist(err) {
				t.Fatal(err)
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("phase deadline: %s", phase)
	}
	ack("ready")
	wait("burst")
	for i := 0; i < 8000; i++ {
		fd, err := unix.Open(fmt.Sprintf("/tmp/seccheck-burst-%06d", i), unix.O_RDONLY, 0)
		if err != unix.ENOENT {
			unix.Close(fd)
			t.Fatalf("burst open: %v", err)
		}
	}
	ack("burst")
	for _, phase := range []string{"after-burst", "queued", "disconnected", "reconnected"} {
		wait(phase)
		for i := 0; i < 32; i++ {
			if err := os.WriteFile(fmt.Sprintf("/tmp/seccheck-%s-%02d", phase, i), []byte(phase), 0600); err != nil {
				t.Fatal(err)
			}
			time.Sleep(10 * time.Millisecond)
		}
		ack(phase)
	}
	wait("finish")
	t.Log("SECCHECK_FAULT_OK")
}
