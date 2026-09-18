//go:build !linux || (!amd64 && !arm64)

// Package sensor is the self-owned system-telemetry sensor. On Linux it loads
// eBPF probes (execve/connect/file_open) and emits normalized telemetry events;
// on other platforms it is a stub so the module still builds.
package sensor

import (
	"fmt"
	"io"
)

// RunWithOptions is unavailable off Linux (eBPF requires a Linux kernel).
func RunWithOptions(_ io.Writer, _ Options) error {
	return fmt.Errorf("agentprov sensor requires Linux amd64 or arm64 (eBPF)")
}
