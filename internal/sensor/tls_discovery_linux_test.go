//go:build linux && (amd64 || arm64)

package sensor

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fakeTLSProcess(t *testing.T, root, pid, source string) string {
	t.Helper()
	lib := filepath.Join(root, pid, "root/usr/lib/libssl.so.3")
	if err := os.MkdirAll(filepath.Dir(lib), 0755); err != nil {
		t.Fatal(err)
	}
	if source == "" {
		if err := os.WriteFile(lib, []byte("fixture"), 0644); err != nil {
			t.Fatal(err)
		}
	} else if err := os.Link(source, lib); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, pid, "mountinfo"), []byte("1 0 8:1 / / rw - ext4 /dev/root rw\n"), 0644); err != nil {
		t.Fatal(err)
	}
	maps := "1000-2000 r-xp 00000000 08:01 1 /usr/lib/libssl.so.3\n2000-3000 rw-p 00001000 08:01 1 /usr/lib/libssl.so.3\n"
	if err := os.WriteFile(filepath.Join(root, pid, "maps"), []byte(maps), 0644); err != nil {
		t.Fatal(err)
	}
	return lib
}

func completeTLSScan(t *testing.T, s *tlsProcessScanner) (map[string]tlsTarget, TLSDiscoveryReport) {
	t.Helper()
	for i := 0; i < 100; i++ {
		targets, stats := s.scan()
		if stats.ScanComplete {
			return targets, stats
		}
	}
	t.Fatal("bounded scanner never completed its sweep")
	return nil, TLSDiscoveryReport{}
}

func TestTLSProcessScannerUsesContainerRootsAndDeduplicatesInodes(t *testing.T) {
	root := t.TempDir()
	first := fakeTLSProcess(t, root, "101", "")
	fakeTLSProcess(t, root, "102", first)
	s := newTLSProcessScanner(root, 1, 8)
	defer s.close()
	targets, stats := completeTLSScan(t, s)
	if len(targets) != 1 || stats.ProcessesScanned != 2 {
		t.Fatalf("targets=%v stats=%+v", targets, stats)
	}
	for _, target := range targets {
		if target.Kind != "openssl" {
			t.Fatalf("target=%+v", target)
		}
	}
	if err := os.RemoveAll(filepath.Join(root, "101")); err != nil {
		t.Fatal(err)
	}
	targets, stats = completeTLSScan(t, s)
	if len(targets) != 1 || stats.ProcessesScanned != 1 {
		t.Fatalf("live duplicate was lost: %v %+v", targets, stats)
	}
}

func TestTLSProcessScannerBoundsTargetsAndRevisitsLaterPIDs(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 5; i++ {
		fakeTLSProcess(t, root, fmt.Sprint(100+i), "")
	}
	s := newTLSProcessScanner(root, 1, 2)
	defer s.close()
	_, first := s.scan()
	if first.ProcessesScanned > 1 || first.ScanComplete {
		t.Fatalf("scan budget not honored: %+v", first)
	}
	targets, stats := completeTLSScan(t, s)
	if stats.ProcessesScanned != 5 || len(targets) != 2 || stats.SkippedTargets != 3 {
		t.Fatalf("bounded sweep: targets=%d stats=%+v", len(targets), stats)
	}
}

func TestTLSFileIdentityChangesAfterAtomicReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tls")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	before, err := tlsFileIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".new", []byte("new"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".new", path); err != nil {
		t.Fatal(err)
	}
	after, err := tlsFileIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("replacement reused the old attachment identity")
	}
}

type countingTLSLink struct{ closed int }

func (l *countingTLSLink) Close() error { l.closed++; return nil }

func TestTLSTrackerReleasesDepartedTargetsAndDoesNotDuplicateActiveProbe(t *testing.T) {
	var created []*countingTLSLink
	attach := func(target tlsTarget, skip map[string]bool) *tlsAttachment {
		if skip["SSL_write"] {
			t.Fatal("successful target should not be reattached")
		}
		l := &countingTLSLink{}
		created = append(created, l)
		return &tlsAttachment{target: target, links: []tlsLink{l}, lastAttempt: time.Now(), probes: []ProbeCapability{{Name: "SSL_write", Status: "attached"}}}
	}
	tracker := newTLSTracker(2, attach)
	one := tlsTarget{Key: "inode1", Path: "/proc/1/root/libssl", Kind: "openssl"}
	tracker.reconcile(map[string]tlsTarget{one.Key: one}, true, time.Now())
	one.Path = "/proc/2/root/libssl"
	tracker.reconcile(map[string]tlsTarget{one.Key: one}, true, time.Now().Add(time.Hour))
	if len(created) != 1 {
		t.Fatalf("duplicate inode attachment: %d", len(created))
	}
	tracker.reconcile(nil, false, time.Now())
	if created[0].closed != 0 {
		t.Fatal("partial sweep detached an unseen live target")
	}
	two := tlsTarget{Key: "inode2", Path: "/proc/3/root/libssl", Kind: "openssl"}
	tracker.reconcile(map[string]tlsTarget{two.Key: two}, true, time.Now())
	if created[0].closed != 1 || len(tracker.entries) != 1 || len(created) != 2 {
		t.Fatalf("stale attachment survived: %+v", tracker.entries)
	}
	tracker.close()
	if created[1].closed != 1 {
		t.Fatal("shutdown leaked a TLS link")
	}
}

func TestTLSTrackerRetriesOnlyFailedProbes(t *testing.T) {
	calls := 0
	tracker := newTLSTracker(1, func(target tlsTarget, skip map[string]bool) *tlsAttachment {
		calls++
		if calls == 1 {
			return &tlsAttachment{target: target, lastAttempt: time.Now().Add(-time.Hour), probes: []ProbeCapability{{Name: "SSL_write", Status: "attached"}, {Name: "SSL_read", Status: "failed"}}}
		}
		if !skip["SSL_write"] || skip["SSL_read"] {
			t.Fatalf("retry would duplicate active probe: %v", skip)
		}
		return &tlsAttachment{target: target, probes: []ProbeCapability{{Name: "SSL_read", Status: "attached"}}}
	})
	target := tlsTarget{Key: "file", Path: "fixture"}
	observed := map[string]tlsTarget{target.Key: target}
	tracker.reconcile(observed, true, time.Now())
	tracker.reconcile(observed, true, time.Now())
	tracker.reconcile(observed, true, time.Now().Add(time.Hour))
	if calls != 2 {
		t.Fatalf("retry count=%d", calls)
	}
}

func TestTLSTrackerKeepsExplicitTargetsAndBoundsResources(t *testing.T) {
	tracker := newTLSTracker(1, func(target tlsTarget, _ map[string]bool) *tlsAttachment {
		return &tlsAttachment{target: target, probes: []ProbeCapability{{Name: "test", Status: "attached"}}}
	})
	target := tlsTarget{Key: "z", Path: "explicit"}
	tracker.pinned[target.Key] = target
	if skipped := tracker.reconcile(map[string]tlsTarget{"b": {Key: "b"}}, true, time.Now()); skipped != 1 {
		t.Fatalf("skipped=%d", skipped)
	}
	tracker.reconcile(nil, true, time.Now())
	if len(tracker.entries) != 1 || tracker.entries["z"] == nil {
		t.Fatalf("explicit attachment lost: %v", tracker.entries)
	}
}
