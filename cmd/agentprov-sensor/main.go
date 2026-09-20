// Command agentprov-sensor is the self-owned eBPF system-telemetry sensor. It
// attaches kernel probes and emits normalized telemetry events as JSONL on
// stdout, which `agentprov telemetry ingest`-style consumers feed into the
// correlation engine. Linux-only; requires root/CAP_BPF.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/byteyellow/agentprovenance/internal/sensor"
)

func main() {
	// AGENTPROV_SSL_LIB=/path/to/libssl.so.3 enables OpenSSL TLS plaintext
	// capture via SSL_write/read and SSL_write_ex/read_ex uprobes.
	opts := sensor.Options{AutoTLS: os.Getenv("AGENTPROV_AUTO_TLS") != "false",
		SSLLib:   os.Getenv("AGENTPROV_SSL_LIB"),
		GoTLSBin: os.Getenv("AGENTPROV_GO_TLS_BIN"),
		LibcLib:  os.Getenv("AGENTPROV_LIBC_LIB"),
		OnReady: func() {
			fmt.Fprintln(os.Stderr, "agentprov-sensor: ready")
		},
	}
	flag.BoolVar(&opts.AutoTLS, "auto-tls", opts.AutoTLS, "discover and track visible container OpenSSL and Go TLS executables")
	flag.DurationVar(&opts.TLSScanInterval, "tls-scan-interval", 2*time.Second, "interval between bounded TLS process scans")
	flag.IntVar(&opts.TLSMaxTargets, "tls-max-targets", 128, "maximum concurrently tracked TLS file identities (hard limit 1024)")
	flag.IntVar(&opts.TLSMaxProcesses, "tls-max-processes", 4096, "process directory entries examined per TLS scan (hard limit 65536)")
	flag.Parse()
	if err := sensor.RunWithOptions(os.Stdout, opts); err != nil {
		fmt.Fprintln(os.Stderr, "agentprov-sensor:", err)
		os.Exit(1)
	}
}
