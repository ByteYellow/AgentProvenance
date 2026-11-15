package sensor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

const MaxCapabilityBytes = 1 << 20

type CapabilityHistoryRange struct {
	CollectorID string   `json:"collector_id,omitempty"`
	First       uint64   `json:"first_revision,omitempty"`
	Last        uint64   `json:"last_revision,omitempty"`
	Saved       uint64   `json:"saved_observations"`
	Status      string   `json:"status"`
	Error       string   `json:"error,omitempty"`
	Issues      []string `json:"issues,omitempty"`
	Limitations []string `json:"limitations,omitempty"`
}

func capabilityPath(dir, collector string, revision uint64) (string, error) {
	if collector == "" || len(collector) > 128 || revision == 0 || strings.Trim(collector, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != "" {
		return "", fmt.Errorf("invalid capability history identity")
	}
	return filepath.Join(dir, "sensor-capabilities", collector, fmt.Sprintf("%020d.json", revision)), nil
}

func validateCapabilityChange(report CapabilityReport) error {
	if report.SchemaVersion != "agentprovenance.sensor_capabilities/v1" {
		return fmt.Errorf("invalid capability schema")
	}
	if _, err := capabilityPath("", report.CollectorID, report.Revision); err != nil {
		return err
	}
	changed, err := time.Parse(time.RFC3339Nano, report.ChangedAt)
	if err != nil {
		return fmt.Errorf("invalid capability change timestamp")
	}
	updated, err := time.Parse(time.RFC3339Nano, report.UpdatedAt)
	if err != nil || updated.Before(changed) {
		return fmt.Errorf("invalid capability observation timestamp")
	}
	if report.Producer != nil {
		if report.Producer.Name != "agentprov-sensor" || report.Producer.Version == "" || report.Producer.Commit == "" || report.Producer.Architecture == "" || ValidatePlacement(report.Producer.Placement) != nil {
			return fmt.Errorf("invalid capability producer")
		}
	}
	return nil
}

// SaveCapabilityChange keeps the first observation of each capability revision.
// Publishing uses a hard link so a retry cannot overwrite an existing revision.
// The latest health snapshot is written separately by the supervisor.
func SaveCapabilityChange(dir string, report CapabilityReport) error {
	if err := validateCapabilityChange(report); err != nil {
		return err
	}
	path, _ := capabilityPath(dir, report.CollectorID, report.Revision)
	checkExisting := func() error {
		old, err := ReadCapabilityChange(context.Background(), dir, report.CollectorID, report.Revision)
		if err != nil {
			return err
		}
		a, _ := capabilityState(old)
		b, _ := capabilityState(report)
		if old.ChangedAt != report.ChangedAt || !bytes.Equal(a, b) {
			return fmt.Errorf("capability history revision conflict")
		}
		return syncCapabilityDirs(dir, path)
	}
	if err := checkExisting(); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	if len(raw) > MaxCapabilityBytes {
		return fmt.Errorf("capability snapshot exceeds %d bytes", MaxCapabilityBytes)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".capability-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Link(f.Name(), path); err != nil {
		if os.IsExist(err) {
			return checkExisting()
		}
		return err
	}
	return syncCapabilityDirs(dir, path)
}

func syncCapabilityDirs(dir, path string) error {
	for _, name := range []string{filepath.Dir(path), filepath.Join(dir, "sensor-capabilities"), dir} {
		d, err := os.Open(name)
		if err != nil {
			return err
		}
		err = d.Sync()
		closeErr := d.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func ReadCapabilityChange(ctx context.Context, dir, collector string, revision uint64) (CapabilityReport, error) {
	var report CapabilityReport
	if err := ctx.Err(); err != nil {
		return report, err
	}
	path, err := capabilityPath(dir, collector, revision)
	if err != nil {
		return report, err
	}
	f, err := os.Open(path)
	if err != nil {
		return report, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, MaxCapabilityBytes+1))
	if err != nil {
		return report, err
	}
	if len(raw) > MaxCapabilityBytes {
		return report, fmt.Errorf("capability snapshot exceeds %d bytes", MaxCapabilityBytes)
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		return report, err
	}
	if report.CollectorID != collector || report.Revision != revision {
		return report, fmt.Errorf("capability history identity mismatch at revision %s", strconv.FormatUint(revision, 10))
	}
	return report, validateCapabilityChange(report)
}

// WalkCapabilityChanges streams one complete observed revision range. Missing
// revisions, collector changes and clock reversals remain explicit errors.
func WalkCapabilityChanges(ctx context.Context, dir string, first, last CapabilityReport, start, end time.Time, visit func(CapabilityReport, time.Time, time.Time) error) (CapabilityHistoryRange, error) {
	r := CapabilityHistoryRange{CollectorID: first.CollectorID, First: first.Revision, Last: last.Revision, Status: "incomplete"}
	fail := func(err error) (CapabilityHistoryRange, error) { r.Error = err.Error(); return r, err }
	if first.CollectorID == "" && last.CollectorID == "" && first.Revision == 0 && last.Revision == 0 {
		r.Status = "not_recorded"
		return r, nil
	}
	if err := validateCapabilityChange(first); err != nil {
		return fail(err)
	}
	if err := validateCapabilityChange(last); err != nil {
		return fail(err)
	}
	if first.CollectorID != last.CollectorID || first.Revision > last.Revision || start.IsZero() || end.Before(start) {
		return fail(fmt.Errorf("capability history boundaries changed"))
	}
	current, err := ReadCapabilityChange(ctx, dir, first.CollectorID, first.Revision)
	if err != nil {
		return fail(err)
	}
	firstState, _ := capabilityState(first)
	currentState, _ := capabilityState(current)
	if !bytes.Equal(firstState, currentState) || first.ChangedAt != current.ChangedAt {
		return fail(fmt.Errorf("capability start observation mismatch"))
	}
	from := start
	changed, _ := time.Parse(time.RFC3339Nano, current.ChangedAt)
	if changed.After(start) {
		return fail(fmt.Errorf("capability start observation is after capture boundary"))
	}
	for revision := first.Revision; ; revision++ {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		until := end
		var next CapabilityReport
		if revision < last.Revision {
			next, err = ReadCapabilityChange(ctx, dir, first.CollectorID, revision+1)
			if err != nil {
				return fail(err)
			}
			until, _ = time.Parse(time.RFC3339Nano, next.ChangedAt)
			if until.Before(from) || until.After(end) {
				return fail(fmt.Errorf("capability history timestamps are outside ordered capture interval"))
			}
		} else {
			lastState, _ := capabilityState(last)
			state, _ := capabilityState(current)
			if !bytes.Equal(lastState, state) || last.ChangedAt != current.ChangedAt {
				return fail(fmt.Errorf("capability end observation mismatch"))
			}
		}
		if err := visit(current, from, until); err != nil {
			return fail(err)
		}
		if until.After(from) {
			if !current.Ready {
				r.Issues = append(r.Issues, "probe_coverage_degraded")
			}
			if current.TLSDiscovery.HasGaps() {
				r.Limitations = append(r.Limitations, "tls_discovery_partial")
			}
			for _, probe := range current.Probes {
				if probe.Status == "failed" || probe.Status == "unsupported" {
					if probe.Required {
						r.Issues = append(r.Issues, "required_probe_unavailable")
					} else {
						r.Limitations = append(r.Limitations, "optional_probe_unavailable")
					}
				}
			}
			slices.Sort(r.Issues)
			r.Issues = slices.Compact(r.Issues)
			slices.Sort(r.Limitations)
			r.Limitations = slices.Compact(r.Limitations)
		}
		r.Saved++
		if revision == last.Revision {
			break
		}
		current, from = next, until
	}
	r.Status = "recorded"
	return r, nil
}
