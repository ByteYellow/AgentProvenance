package dashboard

import (
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/capturemanifest"
	"github.com/byteyellow/agentprovenance/internal/derivedview"
	"github.com/byteyellow/agentprovenance/internal/observability"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/sensor"
	"github.com/byteyellow/agentprovenance/internal/staticdata"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func readReplayCapture(t *testing.T, files map[string][]byte, run string) ([]capturemanifest.Record, string) {
	t.Helper()
	wrapper := string(files["assets/catalog.js"])
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(wrapper, `window.AgentProvOfflineCatalog="`), `";`))
	if err != nil {
		t.Fatal(err)
	}
	var catalog struct {
		Runs map[string]struct {
			Capture *struct {
				Schema string `json:"schema_version"`
				Scope  string `json:"scope"`
				Pages  []struct {
					Count int            `json:"count"`
					Data  staticdata.Ref `json:"data"`
				} `json:"pages"`
			} `json:"capture_manifest"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &catalog); err != nil {
		t.Fatal(err)
	}
	index := catalog.Runs[run].Capture
	if index == nil || index.Schema != "agentprovenance.replay_capture_manifest/v1" {
		t.Fatal("offline capture manifest is missing")
	}
	records := []capturemanifest.Record{}
	for _, page := range index.Pages {
		var values []capturemanifest.Record
		if err := json.Unmarshal(files[strings.TrimSuffix(page.Data.Path, ".json.gz")+".js"], &values); err != nil {
			t.Fatal(err)
		}
		if len(values) != page.Count {
			t.Fatal("capture shard count mismatch")
		}
		records = append(records, values...)
	}
	return records, index.Scope
}

func TestCaptureManifestExportEnumeratesAllPages(t *testing.T) {
	_, db, objects := artifactStore(t)
	for i := 0; i < 260; i++ {
		_, err := objects.PutExternalObject(provenance.ExternalObjectInput{RunID: "many-captures", Type: "runtime_capture", SourceID: fmt.Sprint(i),
			Payload: map[string]any{"schema_version": observability.RuntimeCaptureSchema, "run_id": "many-captures", "issues": []string{fmt.Sprint(i)}}})
		if err != nil {
			t.Fatal(err)
		}
	}
	writer := &staticdata.Writer{Root: t.TempDir()}
	index, err := (Server{DB: db}).exportCaptureManifest(context.Background(), "many-captures", writer)
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Pages) != 6 {
		t.Fatalf("truncated pages: %d", len(index.Pages))
	}
	seen := map[string]bool{}
	for _, p := range index.Pages {
		f, err := os.Open(filepath.Join(writer.Root, p.Data.Path))
		if err != nil {
			t.Fatal(err)
		}
		z, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			t.Fatal(err)
		}
		var records []capturemanifest.Record
		err = json.NewDecoder(z).Decode(&records)
		z.Close()
		f.Close()
		if err != nil || len(records) != p.Count {
			t.Fatalf("capture shard: %v", err)
		}
		if records[0].ID != p.First || records[len(records)-1].ID != p.Last {
			t.Fatal("capture page bounds mismatch")
		}
		for _, r := range records {
			if seen[r.ID] {
				t.Fatal("duplicate capture observation")
			}
			if r.Observation.RuleVersion != capturemanifest.ObservationRuleVersion || r.Observation.Layer != "unknown" ||
				len(r.Observation.EvidenceRefs) != 1 || r.Observation.EvidenceRefs[0] != r.EvidenceRef {
				t.Fatalf("offline capture observation changed: %+v", r.Observation)
			}
			seen[r.ID] = true
		}
	}
	if len(seen) != 260 {
		t.Fatalf("missing capture observations: %d", len(seen))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (Server{DB: db}).exportCaptureManifest(ctx, "many-captures", writer); err == nil {
		t.Fatal("export cancellation ignored")
	}
}

func TestOfflineCaptureManifestFrozenSelection(t *testing.T) {
	paths, db, _ := artifactStore(t)
	ctx := context.Background()
	for _, session := range []string{"selected", "private"} {
		body := "capture manifest " + session
		_, err := (agentcontext.Service{DB: db, Paths: paths}).Save(ctx, "capture-run",
			agentcontext.Source{Harness: "fixture", SessionID: session, ParserVersion: "fixture/v1", ApplicationVersion: session + "-version", Binding: "explicit"},
			[]agentcontext.Record{{Key: "message", Kind: "message", Role: "user", Body: &body}}, agentcontext.Coverage{Status: agentcontext.OK})
		if err != nil {
			t.Fatal(err)
		}
	}
	report := observability.RuntimeCaptureReport{SchemaVersion: observability.RuntimeCaptureSchema, RunID: "capture-run", Status: "partial", KernelState: "observed",
		NodeCounterDelta: map[string]int64{"kernel_dropped_events": 9007199254740993},
		CapabilitiesStart: &sensor.CapabilityReport{SchemaVersion: "agentprovenance.sensor_capabilities/v1", Ready: true,
			ObservationLimits: sensor.NativeObservationLimits(),
			Probes:            []sensor.ProbeCapability{{Name: "file_open", Status: "attached", Target: "CAPTURE-PRIVATE-PROBE"}}}}
	if err := observability.SaveRuntimeCapture(db, paths, &report); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	c := *report.CapabilitiesStart
	c.CollectorID, c.Revision, c.ChangedAt, c.UpdatedAt = "capture-history-private", 1, at.Format(time.RFC3339Nano), at.Format(time.RFC3339Nano)
	if err := sensor.SaveCapabilityChange(paths.Logs, c); err != nil {
		t.Fatal(err)
	}
	if _, err := observability.SaveCapabilityHistory(ctx, db, paths, "capture-run", c, c, at, at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := store.WithWriteTx(ctx, db, func(tx *sql.Tx) error {
		return observability.NativeCaptureObserver(db, paths)(ctx, tx, "capture-run", telemetry.NativeCaptureWindow{
			SchemaVersion: telemetry.NativeCaptureWindowSchema, BatchID: "private-batch", StreamID: "private-stream",
			StartedAt: at, EndedAt: at.Add(time.Second), First: c, Last: c})
	}); err != nil {
		t.Fatal(err)
	}
	want, err := (capturemanifest.Service{DB: db}).List(ctx, capturemanifest.Options{RunID: "capture-run"})
	if err != nil || want.HasMore {
		t.Fatalf("capture: %+v %v", want, err)
	}
	prepared := map[string]*PreparedReplay{}
	for _, selection := range []ReplaySelection{
		{RunID: "capture-run", Scope: "whole_run"},
		{RunID: "capture-run", Scope: "session", Harness: "fixture", SessionID: "selected"},
	} {
		p, err := (Server{DB: db}).PrepareSelectedOfflineReplay(ctx, selection)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { p.Close() })
		prepared[selection.Scope] = p
		wantCoverage := derivedview.CoverageUnknown
		if selection.Scope == "whole_run" {
			wantCoverage = derivedview.CoverageGaps
		}
		if p.coverage.State != wantCoverage {
			t.Fatalf("coverage escaped its selected scope: %s %+v", selection.Scope, p.coverage)
		}
	}
	report.CapabilitiesStart.Probes[0].Target = "LATE-PROBE"
	if err := observability.SaveRuntimeCapture(db, paths, &report); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(paths.Provenance, paths.Provenance+"-unavailable"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for name, p := range prepared {
		t.Run(name, func(t *testing.T) {
			files, _ := replayZIPData(t, p)
			got, scope := readReplayCapture(t, files, "capture-run")
			if name == "whole_run" {
				if scope != "whole_run" || !reflect.DeepEqual(got, want.Records) {
					t.Fatalf("frozen capture changed: %s %+v", scope, got)
				}
			} else {
				if scope != "selected_evidence" || len(got) == 0 {
					t.Fatalf("missing selection boundary: %s %+v", scope, got)
				}
				for _, r := range got {
					if r.Source == "agentprov_sensor" || (r.Source == "agent_context" && r.Identity["session_id"] != "selected") {
						t.Fatalf("excluded capture evidence: %+v", r)
					}
				}
			}
			savedLimits := false
			for path, raw := range files {
				if strings.HasPrefix(path, "data/") && strings.Contains(string(raw), `"mechanism":"io_uring"`) && strings.Contains(string(raw), `"mechanism":"rustls"`) {
					savedLimits = true
				}
				if strings.Contains(string(raw), "LATE-PROBE") || (name == "session" && (strings.Contains(string(raw), "CAPTURE-PRIVATE-PROBE") || strings.Contains(string(raw), "private-version"))) {
					t.Fatal("excluded or late capture metadata leaked")
				}
			}
			if savedLimits != (name == "whole_run") {
				t.Fatalf("native limits in %s selection: %t", name, savedLimits)
			}
			if root := os.Getenv("AGENTPROV_CAPTURE_REPLAY_OUTPUT"); root != "" {
				if err := os.MkdirAll(root, 0700); err != nil {
					t.Fatal(err)
				}
				file, err := os.OpenFile(filepath.Join(root, name+".zip"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				writeErr := p.WriteZIP(ctx, file)
				closeErr := file.Close()
				if writeErr != nil || closeErr != nil {
					t.Fatalf("ZIP: %v %v", writeErr, closeErr)
				}
			}
		})
	}
}

func TestReplayCaptureCoverageKeepsCounterScope(t *testing.T) {
	zero, lost := int64(0), int64(9)
	for _, test := range []struct {
		name   string
		status string
		run    *int64
		node   int64
		want   derivedview.CoverageState
	}{
		{"unmeasured", "ok", nil, 0, derivedview.CoverageUnknown},
		{"node_loss_not_allocated", "ok", &zero, 400, derivedview.CoverageUnknown},
		{"run_loss", "ok", &lost, 0, derivedview.CoverageGaps},
		{"partial_report", "partial", nil, 0, derivedview.CoverageGaps},
	} {
		t.Run(test.name, func(t *testing.T) {
			paths, db, _ := artifactStore(t)
			report := observability.RuntimeCaptureReport{SchemaVersion: observability.RuntimeCaptureSchema,
				RunID: "coverage", Status: test.status, RunDroppedEvents: test.run,
				NodeCounterDelta: map[string]int64{"kernel_dropped_events": test.node}}
			if err := observability.SaveRuntimeCapture(db, paths, &report); err != nil {
				t.Fatal(err)
			}
			index, err := (Server{DB: db}).exportCaptureManifest(context.Background(), "coverage", &staticdata.Writer{Root: t.TempDir()})
			if err != nil || index.coverage.State != test.want {
				t.Fatalf("coverage: %+v %v", index, err)
			}
			for _, gap := range index.coverage.Gaps {
				if gap.Count != 1 {
					t.Fatalf("observation count became a loss estimate: %+v", gap)
				}
			}
		})
	}
}
