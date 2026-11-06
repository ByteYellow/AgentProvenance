package sensor

import (
	"fmt"
	"io"

	"github.com/byteyellow/agentprovenance/internal/i18n"
)

// PrintCapabilities renders a snapshot without rewriting fields that consumers
// persist as evidence. It also works with reports loaded from previous runs.
func PrintCapabilities(out io.Writer, report CapabilityReport, lang i18n.Locale) {
	yesNo := func(value bool) string {
		if value {
			return i18n.T(lang, "yes")
		}
		return i18n.T(lang, "no")
	}
	fmt.Fprintf(out, i18n.T(lang, "Sensor status: %s; ready: %s\n"), i18n.T(lang, report.Status), yesNo(report.Ready))
	if report.Reason != "" {
		fmt.Fprintf(out, i18n.T(lang, "Reason: %s\n"), i18n.RuntimeDiagnostics.Text(lang, report.Reason))
	}
	for _, p := range report.Probes {
		fmt.Fprintf(out, i18n.T(lang, "Probe %s [%s]: %s; required: %s; target: %s\n"), p.Name, i18n.T(lang, p.Category), i18n.T(lang, p.Status), yesNo(p.Required), p.Target)
		if p.Reason != "" {
			fmt.Fprintf(out, i18n.T(lang, "  Reason: %s\n"), i18n.RuntimeDiagnostics.Text(lang, p.Reason))
		}
	}
	d := report.TLSDiscovery
	fmt.Fprintf(out, i18n.T(lang, "TLS discovery: %s; scan complete: %s; interval: %d ms; active targets: %d/%d; processes scanned: %d/%d\n"), yesNo(d.Enabled), yesNo(d.ScanComplete), d.ScanIntervalMS, d.ActiveTargets, d.MaxTargets, d.ProcessesScanned, d.MaxProcessesPerScan)
	fmt.Fprintf(out, i18n.T(lang, "TLS gaps: unreadable processes=%d unresolved mounts=%d truncated maps=%d skipped targets=%d unsupported executables=%d\n"), d.UnreadableProcesses, d.UnresolvedMounts, d.TruncatedMaps, d.SkippedTargets, d.UnsupportedExecutables)
	if e := d.EventDiscovery; e != nil {
		fmt.Fprintf(out, i18n.T(lang, "TLS event discovery: hints=%d coalesced=%d queue drops=%d process scans=%d retry scans=%d attached targets=%d max attach latency=%d ms\n"), e.Hints, e.Coalesced, e.QueueDrops, e.ProcessScans, e.RetryScans, e.AttachedTargets, e.MaxAttachLatencyMS)
	}
	if d.Reason != "" {
		fmt.Fprintf(out, i18n.T(lang, "  Reason: %s\n"), i18n.RuntimeDiagnostics.Text(lang, d.Reason))
	}
	for _, limit := range d.Limitations {
		fmt.Fprintf(out, i18n.T(lang, "  Limitation: %s\n"), i18n.T(lang, limit))
	}
}
