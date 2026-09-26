// Command agentprov-sensor captures Linux eBPF telemetry as JSONL. Human
// diagnostics can be localized independently of events and readiness markers.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/i18n"
	"github.com/byteyellow/agentprovenance/internal/sensor"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, sensor.RunWithOptions)) }

func run(args []string, stdout, stderr io.Writer, capture func(io.Writer, sensor.Options) error) int {
	lang := sensorLanguage(args)
	opts := sensor.Options{
		AutoTLS: os.Getenv("AGENTPROV_AUTO_TLS") != "false",
		SSLLib:  os.Getenv("AGENTPROV_SSL_LIB"), GoTLSBin: os.Getenv("AGENTPROV_GO_TLS_BIN"),
		LibcLib: os.Getenv("AGENTPROV_LIBC_LIB"), Diagnostics: stderr,
		OnReady: func() { fmt.Fprintln(stderr, "agentprov-sensor: ready") },
	}
	flags := flag.NewFlagSet("agentprov-sensor", flag.ContinueOnError)
	// Return parser diagnostics once, through the same language boundary.
	flags.SetOutput(io.Discard)
	flags.Func("lang", "interface language: en or zh-CN", func(value string) error {
		parsed, ok := i18n.Parse(value)
		if !ok {
			return i18n.Errorf("unsupported language %q (choose en or zh-CN)", value)
		}
		lang = parsed
		return nil
	})
	flags.BoolVar(&opts.AutoTLS, "auto-tls", opts.AutoTLS, "discover and track visible container OpenSSL and Go TLS executables")
	flags.DurationVar(&opts.TLSScanInterval, "tls-scan-interval", 2*time.Second, "interval between bounded TLS process scans")
	flags.IntVar(&opts.TLSMaxTargets, "tls-max-targets", 128, "maximum concurrently tracked TLS file identities (hard limit 1024)")
	flags.IntVar(&opts.TLSMaxProcesses, "tls-max-processes", 4096, "process directory entries examined per TLS scan (hard limit 65536)")
	flags.Usage = func() {
		fmt.Fprint(stderr, i18n.T(lang, "Usage: agentprov-sensor [options]\n"))
		fmt.Fprint(stderr, i18n.T(lang, "Capture requires Linux amd64/arm64 and root or CAP_BPF + CAP_PERFMON.\n"))
		flags.VisitAll(func(f *flag.Flag) {
			name, _ := flag.UnquoteUsage(f)
			if lang == i18n.Chinese {
				switch name {
				case "int":
					name = "整数"
				case "duration":
					name = "时长"
				case "value":
					name = "值"
				}
			}
			def := f.DefValue
			if f.Name == "lang" {
				name = i18n.T(lang, "language")
				def = "en"
			}
			fmt.Fprintf(stderr, i18n.T(lang, "  -%s %s\n      %s (default: %s)\n"), f.Name, name, i18n.T(lang, f.Usage), def)
		})
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "agentprov-sensor:", i18n.ErrorText(lang, err))
		return 2
	}
	opts.Language = lang
	if err := capture(stdout, opts); err != nil {
		fmt.Fprintln(stderr, "agentprov-sensor:", i18n.ErrorText(lang, err))
		return 1
	}
	return 0
}

// Read a valid explicit choice before parsing so --help --lang zh-CN works too.
// Skip known value arguments, and stop at -- or the first positional argument.
func sensorLanguage(args []string) i18n.Locale {
	lang := i18n.English
	for i := 0; i < len(args); i++ {
		raw := args[i]
		if raw == "--" || !strings.HasPrefix(raw, "-") {
			break
		}
		key, value, equals := strings.Cut(strings.TrimLeft(raw, "-"), "=")
		if key == "lang" {
			if !equals && i+1 < len(args) {
				i++
				value = args[i]
			}
			if choice, ok := i18n.Parse(value); ok {
				lang = choice
			}
		} else if !equals && (key == "tls-scan-interval" || key == "tls-max-targets" || key == "tls-max-processes") {
			i++
		}
	}
	return lang
}
