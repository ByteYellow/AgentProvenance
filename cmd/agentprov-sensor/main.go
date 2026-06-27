// Command agentprov-sensor is the self-owned eBPF system-telemetry sensor. It
// attaches kernel probes and emits normalized telemetry events as JSONL on
// stdout, which `agentprov telemetry ingest`-style consumers feed into the
// correlation engine. Linux-only; requires root/CAP_BPF.
package main

import (
	"fmt"
	"os"

	"github.com/byteyellow/agentprovenance/internal/sensor"
)

func main() {
	if err := sensor.Run(os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "agentprov-sensor:", err)
		os.Exit(1)
	}
}
