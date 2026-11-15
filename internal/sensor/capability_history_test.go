package sensor

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func historyReport(revision uint64, status string) CapabilityReport {
	at := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC).Add(time.Duration(revision) * time.Second).Format(time.RFC3339Nano)
	return CapabilityReport{SchemaVersion: "agentprovenance.sensor_capabilities/v1", CollectorID: "sensor-fixture", Revision: revision,
		ChangedAt: at, UpdatedAt: at, Status: status, Ready: status == "ready",
		Producer: &CapabilityProducer{Name: "agentprov-sensor", Version: "fixture", Commit: "fixture-sha", Architecture: "arm64", OS: "linux", Placement: "guest_kernel", PlacementBasis: "operator_configuration"}}
}

func TestCapabilityRevisionExcludesCountersButRetainsGaps(t *testing.T) {
	var reports []CapabilityReport
	cp := NewCheckpointer()
	r := newCapabilityReporter(Options{Placement: "guest_kernel", Checkpointer: cp, Diagnostics: io.Discard,
		OnCapabilities: func(c CapabilityReport) { reports = append(reports, c) }})
	r.publish(true)
	d := TLSDiscoveryReport{Enabled: true, ScanComplete: true, SweepPasses: 1, EventDiscovery: &TLSEventDiscoveryReport{Hints: 1}}
	r.updateTLS(nil, d)
	d.SweepPasses++
	d.EventDiscovery = &TLSEventDiscoveryReport{Hints: 2}
	r.updateTLS(nil, d)
	d.EventDiscovery = &TLSEventDiscoveryReport{Hints: 3, QueueDrops: 1}
	r.updateTLS(nil, d)
	d.EventDiscovery = &TLSEventDiscoveryReport{Hints: 4, QueueDrops: 2}
	r.updateTLS(nil, d)
	var revisions []uint64
	for _, c := range reports {
		revisions = append(revisions, c.Revision)
		if c.CollectorID != cp.epoch || c.Producer.Placement != "guest_kernel" {
			t.Fatal("identity was not retained")
		}
	}
	if !reflect.DeepEqual(revisions, []uint64{1, 2, 2, 3, 3}) {
		t.Fatalf("capability revisions: %v", revisions)
	}
	if reports[1].ChangedAt != reports[2].ChangedAt || reports[3].ChangedAt != reports[4].ChangedAt {
		t.Fatal("counter changed capability interval")
	}
	other := newCapabilityReporter(Options{})
	if other.collectorID == r.collectorID {
		t.Fatal("new collector reused identity")
	}
}

func TestCapabilityHistoryRangeAndImmutableRetry(t *testing.T) {
	dir := t.TempDir()
	first, middle, last := historyReport(1, "ready"), historyReport(2, "degraded"), historyReport(3, "ready")
	for _, c := range []CapabilityReport{first, middle, last} {
		if err := SaveCapabilityChange(dir, c); err != nil {
			t.Fatal(err)
		}
	}
	path, _ := capabilityPath(dir, middle.CollectorID, middle.Revision)
	original, _ := os.ReadFile(path)
	middle.ProcfsIdentity = &ProcfsIdentityReport{Mode: "test", TranslatedEvents: 1}
	if err := SaveCapabilityChange(dir, middle); err == nil {
		t.Fatal("same revision changed capability state")
	}
	last.TLSDiscovery.SweepPasses = 9007199254740993
	if err := SaveCapabilityChange(dir, last); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(original) {
		t.Fatal("existing revision overwritten")
	}
	start, _ := time.Parse(time.RFC3339Nano, first.ChangedAt)
	end, _ := time.Parse(time.RFC3339Nano, last.ChangedAt)
	var statuses []string
	range_, err := WalkCapabilityChanges(context.Background(), dir, first, last, start.Add(time.Millisecond), end.Add(time.Second), func(c CapabilityReport, from, until time.Time) error {
		if from.After(until) {
			t.Fatal("negative interval")
		}
		statuses = append(statuses, c.Status)
		return nil
	})
	if err != nil || range_.Status != "recorded" || range_.Saved != 3 || !reflect.DeepEqual(statuses, []string{"ready", "degraded", "ready"}) || !reflect.DeepEqual(range_.Issues, []string{"probe_coverage_degraded"}) {
		t.Fatalf("history: %+v %v %v", range_, statuses, err)
	}
}

func TestCapabilityHistoryRejectsBrokenRanges(t *testing.T) {
	for _, mode := range []string{"missing", "corrupt", "identity", "collector", "clock", "cancelled", "visitor", "oversize", "first-state", "last-state"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			first, last := historyReport(1, "ready"), historyReport(3, "ready")
			for _, c := range []CapabilityReport{first, historyReport(2, "degraded"), last} {
				if err := SaveCapabilityChange(dir, c); err != nil {
					t.Fatal(err)
				}
			}
			path, _ := capabilityPath(dir, first.CollectorID, 2)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				if err := os.WriteFile(path, []byte(strings.Repeat(" ", MaxCapabilityBytes+1)), 0600); err != nil {
					t.Fatal(err)
				}
			case "identity":
				raw, _ := os.ReadFile(path)
				if err := os.WriteFile(path, []byte(strings.ReplaceAll(string(raw), "sensor-fixture", "other")), 0600); err != nil {
					t.Fatal(err)
				}
			case "collector":
				last.CollectorID = "other"
			case "clock":
				raw, _ := os.ReadFile(path)
				if err := os.WriteFile(path, []byte(strings.ReplaceAll(string(raw), "00:00:02", "00:00:09")), 0600); err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				cancel()
			case "first-state":
				first.Status = "failed"
			case "last-state":
				last.Status = "failed"
			}
			start, _ := time.Parse(time.RFC3339Nano, first.ChangedAt)
			end, _ := time.Parse(time.RFC3339Nano, last.ChangedAt)
			r, err := WalkCapabilityChanges(ctx, dir, first, last, start, end, func(CapabilityReport, time.Time, time.Time) error {
				if mode == "visitor" {
					return errors.New("disk failure")
				}
				return nil
			})
			if err == nil || r.Status != "incomplete" || r.Error == "" {
				t.Fatalf("broken %s reported complete: %+v %v", mode, r, err)
			}
		})
	}
}

func TestCapabilityHistoryConcurrentRetryAndLimits(t *testing.T) {
	dir, report := t.TempDir(), historyReport(1, "ready")
	var group sync.WaitGroup
	for i := 0; i < 12; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := SaveCapabilityChange(dir, report); err != nil {
				t.Error(err)
			}
		}()
	}
	group.Wait()
	report.Revision++
	report.Reason = strings.Repeat("x", MaxCapabilityBytes)
	if err := SaveCapabilityChange(dir, report); err == nil {
		t.Fatal("oversized capability accepted")
	}
	for _, id := range []string{"../escape", "a/b", "", ".", "sensor\x00bad"} {
		if _, err := ReadCapabilityChange(context.Background(), dir, id, 1); err == nil {
			t.Fatalf("invalid identity %q accepted", id)
		}
	}
	legacy, err := WalkCapabilityChanges(context.Background(), dir, CapabilityReport{}, CapabilityReport{}, time.Time{}, time.Time{}, nil)
	if err != nil || legacy.Status != "not_recorded" {
		t.Fatalf("legacy history invented: %+v %v", legacy, err)
	}
}
