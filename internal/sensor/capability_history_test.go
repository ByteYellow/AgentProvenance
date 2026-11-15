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

func TestCapabilityHistoryClipsDelayedChangesToReceiveWindow(t *testing.T) {
	for _, tc := range []struct {
		name      string
		changes   []int
		statuses  []string
		start     int
		end       int
		intervals [][2]int
		wantIssue bool
		wantError bool
	}{
		{"delayed", []int{1, 2}, []string{"degraded", "ready"}, 3, 4, [][2]int{{3, 3}, {3, 4}}, false, false},
		{"several delayed", []int{1, 2, 3}, []string{"degraded", "degraded", "ready"}, 4, 5, [][2]int{{4, 4}, {4, 4}, {4, 5}}, false, false},
		{"boundary", []int{1, 3}, []string{"degraded", "ready"}, 3, 5, [][2]int{{3, 3}, {3, 5}}, false, false},
		{"delayed and current", []int{1, 2, 4}, []string{"degraded", "ready", "degraded"}, 3, 5, [][2]int{{3, 3}, {3, 4}, {4, 5}}, true, false},
		{"equal change times", []int{1, 2, 2}, []string{"degraded", "degraded", "ready"}, 3, 4, [][2]int{{3, 3}, {3, 3}, {3, 4}}, false, false},
		{"reversed before window", []int{1, 2, 1}, []string{"ready", "ready", "ready"}, 3, 4, nil, false, true},
		{"after window", []int{1, 5}, []string{"ready", "ready"}, 3, 4, nil, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			base := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
			at := func(seconds int) time.Time { return base.Add(time.Duration(seconds) * time.Second) }
			reports := make([]CapabilityReport, len(tc.changes))
			originals := make([][]byte, len(reports))
			for i, seconds := range tc.changes {
				report := historyReport(uint64(i+1), tc.statuses[i])
				report.ChangedAt, report.UpdatedAt = at(seconds).Format(time.RFC3339Nano), at(seconds).Format(time.RFC3339Nano)
				reports[i] = report
				if err := SaveCapabilityChange(dir, report); err != nil {
					t.Fatal(err)
				}
				path, _ := capabilityPath(dir, report.CollectorID, report.Revision)
				var err error
				originals[i], err = os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			var visited []CapabilityReport
			var intervals [][2]int
			r, err := WalkCapabilityChanges(context.Background(), dir, reports[0], reports[len(reports)-1], at(tc.start), at(tc.end),
				func(report CapabilityReport, from, until time.Time) error {
					visited = append(visited, report)
					intervals = append(intervals, [2]int{int(from.Sub(base) / time.Second), int(until.Sub(base) / time.Second)})
					return nil
				})
			if tc.wantError {
				if err == nil || r.Status != "incomplete" || r.Error == "" {
					t.Fatalf("unordered changes accepted: %+v %v", r, err)
				}
			} else {
				if err != nil || r.Status != "recorded" || r.Saved != uint64(len(reports)) {
					t.Fatalf("history: %+v %v", r, err)
				}
				if !reflect.DeepEqual(visited, reports) || !reflect.DeepEqual(intervals, tc.intervals) {
					t.Fatalf("changed evidence or receive window: %+v %+v", visited, intervals)
				}
				if tc.wantIssue != (len(r.Issues) > 0) {
					t.Fatalf("coverage includes out-of-window degradation: %+v", r)
				}
			}
			for i, report := range reports {
				path, _ := capabilityPath(dir, report.CollectorID, report.Revision)
				raw, err := os.ReadFile(path)
				if err != nil || string(raw) != string(originals[i]) {
					t.Fatal("original capability revision changed")
				}
			}
		})
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
