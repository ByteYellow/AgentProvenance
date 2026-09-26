//go:build linux && (amd64 || arm64)

package sensor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/byteyellow/agentprovenance/internal/i18n"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type tlsLink interface{ Close() error }

type tlsAttachment struct {
	target      tlsTarget
	links       []tlsLink
	probes      []ProbeCapability
	lastAttempt time.Time
}

func (a *tlsAttachment) close() {
	for _, l := range a.links {
		_ = l.Close()
	}
	a.links = nil
}

func attachTLSTarget(target tlsTarget, objs *sensorbpfObjects, skip map[string]bool) *tlsAttachment {
	a := &tlsAttachment{target: target, lastAttempt: time.Now()}
	// Pin the file descriptor while resolving symbols and attaching every probe.
	// A container exit/PID reuse or atomic library replacement must not attach
	// a different inode under the identity discovered in the preceding scan.
	stablePath := target.Path
	file, openErr := os.Open(target.Path)
	if target.Reason != "" {
		if file != nil {
			file.Close()
		}
		file = nil
		openErr = fmt.Errorf("%s", target.Reason)
	}
	if openErr == nil {
		defer file.Close()
		stablePath = fmt.Sprintf("/proc/self/fd/%d", file.Fd())
		identity, err := tlsFileIdentity(stablePath)
		if err != nil {
			openErr = err
		} else if target.Key != target.Kind+":"+identity {
			openErr = i18n.Errorf("TLS target changed since discovery; retrying on the next scan")
		}
	}
	var ex *link.Executable
	if openErr == nil {
		openErr = validateELFMetadata(stablePath)
	}
	if openErr == nil {
		ex, openErr = link.OpenExecutable(stablePath)
	}
	attach := func(name string, enter, ret *ebpf.Program) {
		if skip[name] {
			return
		}
		probe := ProbeCapability{Name: name, Category: "tls", Target: target.Path, Status: "attached"}
		if openErr != nil {
			probe.Status = "failed"
			probe.Reason = capabilityFailure(openErr)
			a.probes = append(a.probes, probe)
			return
		}
		up, err := ex.Uprobe(name, enter, nil)
		if err == nil && ret != nil {
			var out link.Link
			out, err = ex.Uretprobe(name, ret, nil)
			if err != nil {
				_ = up.Close()
			} else {
				a.links = append(a.links, out)
			}
		}
		if err != nil {
			probe.Status = "failed"
			probe.Reason = capabilityFailure(err)
		} else {
			a.links = append(a.links, up)
		}
		a.probes = append(a.probes, probe)
	}
	if target.Kind == "openssl" {
		attach("SSL_write", objs.HandleSslWrite, nil)
		attach("SSL_write_ex", objs.HandleSslWriteEx, nil)
		attach("SSL_read", objs.HandleSslReadEnter, objs.HandleSslReadExit)
		attach("SSL_read_ex", objs.HandleSslReadExEnter, objs.HandleSslReadExExit)
	} else {
		attach("crypto/tls.(*Conn).Write", goTLSWriteProgram(objs), nil)
		if skip["crypto/tls.(*Conn).Read"] {
			return a
		}
		probe := ProbeCapability{Name: "crypto/tls.(*Conn).Read", Category: "tls", Target: target.Path, Status: "attached"}
		var links []link.Link
		err := openErr
		if err == nil {
			links, err = attachGoTLSRead(ex, stablePath, objs)
		}
		if err != nil {
			probe.Status = "unsupported"
			probe.Reason = capabilityFailure(err)
		} else {
			for _, l := range links {
				a.links = append(a.links, l)
			}
		}
		a.probes = append(a.probes, probe)
	}
	return a
}

type tlsTracker struct {
	maxTargets int
	entries    map[string]*tlsAttachment
	pinned     map[string]tlsTarget
	attach     func(tlsTarget, map[string]bool) *tlsAttachment
}

func newTLSTracker(maxTargets int, attach func(tlsTarget, map[string]bool) *tlsAttachment) *tlsTracker {
	return &tlsTracker{maxTargets: maxTargets, entries: map[string]*tlsAttachment{}, pinned: map[string]tlsTarget{}, attach: attach}
}
func (t *tlsTracker) close() {
	for _, a := range t.entries {
		a.close()
	}
}

func (t *tlsTracker) reconcile(observed map[string]tlsTarget, complete bool, now time.Time) int {
	if complete {
		for key, entry := range t.entries {
			if _, ok := observed[key]; ok {
				continue
			}
			if _, ok := t.pinned[key]; ok {
				continue
			}
			entry.close()
			delete(t.entries, key)
		}
	}
	all := make(map[string]tlsTarget, len(observed)+len(t.pinned))
	for key, target := range observed {
		all[key] = target
	}
	for key, target := range t.pinned {
		all[key] = target
	}
	keys := make([]string, 0, len(all))
	for key := range all {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		_, ip := t.pinned[keys[i]]
		_, jp := t.pinned[keys[j]]
		if ip != jp {
			return ip
		}
		return keys[i] < keys[j]
	})
	skipped := 0
	for _, key := range keys {
		target := all[key]
		if old := t.entries[key]; old != nil {
			// Retry only failed probes. Reattaching working probes, even briefly,
			// produces duplicate TLS plaintext and corrupts message reassembly.
			skip := map[string]bool{}
			failed := false
			for _, p := range old.probes {
				if p.Status == "attached" {
					skip[p.Name] = true
				} else {
					failed = true
				}
			}
			pathChanged := old.target.Path != target.Path
			old.target = target
			for i := range old.probes {
				old.probes[i].Target = target.Path
			}
			if !failed || (!pathChanged && now.Sub(old.lastAttempt) < 30*time.Second) {
				continue
			}
			retry := t.attach(target, skip)
			old.links = append(old.links, retry.links...)
			for _, updated := range retry.probes {
				for i := range old.probes {
					if old.probes[i].Name == updated.Name {
						old.probes[i] = updated
						break
					}
				}
			}
			old.lastAttempt = now
			continue
		}
		// A revision change on the SAME inode replaces old links even when a
		// large /proc sweep is incomplete; otherwise touching/rebuilding the
		// file could leave duplicate probes until the sweep finishes.
		parts := strings.SplitN(key, ":", 4)
		if len(parts) == 4 && parts[1] != "path" {
			prefix := strings.Join(parts[:3], ":") + ":"
			for oldKey, old := range t.entries {
				if strings.HasPrefix(oldKey, prefix) && oldKey != key {
					old.close()
					delete(t.entries, oldKey)
				}
			}
		}
		if len(t.entries) >= t.maxTargets {
			skipped++
			continue
		}
		t.entries[key] = t.attach(target, nil)
	}
	return skipped
}

func tlsDefaults(opts Options) Options {
	if opts.TLSScanInterval <= 0 {
		opts.TLSScanInterval = 2 * time.Second
	}
	if opts.TLSScanInterval < 100*time.Millisecond {
		opts.TLSScanInterval = 100 * time.Millisecond
	}
	if opts.TLSMaxTargets <= 0 {
		opts.TLSMaxTargets = 128
	}
	if opts.TLSMaxTargets > 1024 {
		opts.TLSMaxTargets = 1024
	}
	if opts.TLSMaxProcesses <= 0 {
		opts.TLSMaxProcesses = 4096
	}
	if opts.TLSMaxProcesses > 65536 {
		opts.TLSMaxProcesses = 65536
	}
	return opts
}

func runTLSDiscovery(ctx context.Context, objs *sensorbpfObjects, opts Options, reporter *capabilityReporter, initialized chan<- struct{}, wake <-chan struct{}) {
	opts = tlsDefaults(opts)
	tracker := newTLSTracker(opts.TLSMaxTargets, func(target tlsTarget, skip map[string]bool) *tlsAttachment {
		return attachTLSTarget(target, objs, skip)
	})
	defer tracker.close()
	scanner := newTLSProcessScanner("/proc", opts.TLSMaxProcesses, opts.TLSMaxTargets)
	defer scanner.close()
	explicit := []tlsTarget{}
	if opts.SSLLib != "" {
		explicit = append(explicit, tlsTarget{Path: opts.SSLLib, Kind: "openssl"})
	}
	if opts.GoTLSBin != "" {
		explicit = append(explicit, tlsTarget{Path: opts.GoTLSBin, Kind: "go"})
	}
	publish := func(scan TLSDiscoveryReport) {
		scan.Enabled = opts.AutoTLS
		scan.ScanIntervalMS = opts.TLSScanInterval.Milliseconds()
		scan.MaxTargets = opts.TLSMaxTargets
		scan.MaxProcessesPerScan = opts.TLSMaxProcesses
		scan.ActiveTargets = len(tracker.entries)
		scan.Limitations = []string{
			"processes must be visible in the sensor PID namespace; container roots/maps must be readable",
			"polling can miss TLS activity before attachment and processes shorter than the scan interval",
			"stripped Go binaries, unsupported Go ABIs, custom/static TLS implementations may not be covered",
		}
		probes := []ProbeCapability{}
		if !opts.AutoTLS {
			probes = append(probes, ProbeCapability{Name: "container_tls_discovery", Category: "tls", Status: "disabled", Reason: "automatic discovery disabled"})
		}
		for _, attachment := range tracker.entries {
			probes = append(probes, attachment.probes...)
		}
		reporter.updateTLS(probes, scan)
	}
	scan := func() {
		// Refresh explicit paths too: replacing a configured executable/library
		// atomically must not leave uprobes pinned to its old inode forever.
		pinned := map[string]tlsTarget{}
		for _, target := range explicit {
			abs, err := filepath.Abs(target.Path)
			if err == nil {
				var backing string
				backing, err = tlsBackingPath("/proc/self", target.Path, abs)
				if err == nil {
					target.Path = backing
				}
			}
			if err != nil {
				target.Reason = capabilityFailure(err)
			}
			identity, err := tlsFileIdentity(target.Path)
			if err != nil {
				identity = "path:" + target.Path
			}
			target.Key = target.Kind + ":" + identity
			pinned[target.Key] = target
		}
		tracker.pinned = pinned
		observed := map[string]tlsTarget{}
		status := TLSDiscoveryReport{ScanComplete: true}
		if opts.AutoTLS {
			observed, status = scanner.scan()
		}
		status.SkippedTargets += tracker.reconcile(observed, status.ScanComplete, time.Now())
		publish(status)
	}
	scan()
	close(initialized)
	lastScan := time.Now()
	minimumInterval := 250 * time.Millisecond
	if opts.TLSScanInterval < minimumInterval {
		minimumInterval = opts.TLSScanInterval
	}
	ticker := time.NewTicker(opts.TLSScanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-wake:
		}
		if delay := time.Until(lastScan.Add(minimumInterval)); delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
		scan()
		lastScan = time.Now()
	}
}

func capabilityFailure(reason error) string {
	if reason == nil {
		return ""
	}
	// Kernel errors can include verbose verifier data; keep reports bounded.
	s := strings.TrimSpace(fmt.Sprint(reason))
	if len(s) > 2048 {
		return s[:2048] + " (truncated)"
	}
	return s
}
