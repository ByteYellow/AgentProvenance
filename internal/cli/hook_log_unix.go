//go:build darwin || linux

package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
)

func appendHookLog(path string, data []byte, limit int64) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	// The size check and append must share a lock across independent hooks.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("hook log must be a regular file")
	}
	marker := append(agentcontext.HookCaptureDiagnostic("hook_log_limit"), '\n')
	if info.Size() >= int64(len(marker)) {
		tail := make([]byte, len(marker))
		if _, err := f.ReadAt(tail, info.Size()-int64(len(tail))); err != nil {
			return err
		}
		if bytes.Equal(tail, marker) {
			return nil
		}
	}
	if info.Size()+int64(len(data)+len(marker)) > limit {
		if info.Size()+int64(len(marker)) > limit {
			return fmt.Errorf("hook log exceeds capture limit")
		}
		data = marker
	}
	n, err := f.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}
