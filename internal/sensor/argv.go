package sensor

import (
	"bytes"
	"strings"
)

// These limits mirror ARG_SLOT/MAX_ARGS in exec.c. Reaching either boundary
// means argv may be truncated; the current ABI cannot prove the original length.
func capturedArgs(b []byte) ([]string, bool) {
	const slot, maxArgs = 32, 16
	parts := make([]string, 0, maxArgs)
	limited := false
	for i := 0; i < maxArgs; i++ {
		start := i * slot
		if start >= len(b) {
			break
		}
		end := min(start+slot, len(b))
		arg := b[start:end]
		if n := bytes.IndexByte(arg, 0); n >= 0 {
			arg = arg[:n]
		}
		if len(arg) == 0 {
			break
		}
		parts = append(parts, string(arg))
		limited = limited || len(arg) >= slot-1 || end-start < slot
	}
	return parts, limited || len(parts) == maxArgs
}

func joinArgs(b []byte) string {
	argv, _ := capturedArgs(b)
	return strings.Join(argv, " ")
}
