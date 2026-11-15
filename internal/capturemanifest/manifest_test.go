package capturemanifest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/handoff"
	"github.com/byteyellow/agentprovenance/internal/observability"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/record"
	"github.com/byteyellow/agentprovenance/internal/seccheck"
	"github.com/byteyellow/agentprovenance/internal/sensor"
	"github.com/byteyellow/agentprovenance/internal/store"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func testStore(t *testing.T) (*sql.DB, store.Paths) {
	t.Helper()
	p, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, p
}

func put(t *testing.T, db *sql.DB, paths store.Paths, run, kind, id string, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&payload); err != nil {
		t.Fatal(err)
	}
	obj, err := (provenance.ObjectStore{DB: db, Paths: paths}).PutExternalObject(provenance.ExternalObjectInput{RunID: run, Type: kind, SourceID: id, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	return obj.Hash
}

func all(t *testing.T, db *sql.DB, run string, limit int) []Record {
	t.Helper()
	items, cursor := []Record{}, ""
	for {
		page, err := (Service{DB: db}).List(context.Background(), Options{RunID: run, Limit: limit, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, page.Records...)
		if !page.HasMore {
			break
		}
		if page.NextCursor == "" || page.NextCursor == cursor {
			t.Fatal("invalid continuation")
		}
		cursor = page.NextCursor
	}
	return items
}

func caps(at time.Time, status string) sensor.CapabilityReport {
	return sensor.CapabilityReport{SchemaVersion: "agentprovenance.sensor_capabilities/v1", UpdatedAt: timestamp(at), Ready: status == "attached", Status: "degraded",
		Probes: []sensor.ProbeCapability{{Name: "sys_enter_openat", Category: "file", Status: status}, {Name: "SSL_read", Category: "tls", Target: "/captured/libssl.so", Status: "unsupported"}, {Name: "getaddrinfo", Category: "dns", Status: "disabled"}}}
}

func TestSavedCapabilitiesKeepUnknownSeparateFromDisabled(t *testing.T) {
	db, paths := testStore(t)
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	before, after := caps(now, "attached"), caps(now.Add(time.Second), "detached")
	r := observability.RuntimeCaptureReport{SchemaVersion: observability.RuntimeCaptureSchema, RunID: "r", Status: "partial", KernelState: "observed", Scope: "node_capture_during_run",
		StartedAt: timestamp(now), EndedAt: timestamp(now.Add(time.Second)), CapabilitiesStart: &before, CapabilitiesEnd: &after,
		NodeCounterDelta: map[string]int64{"kernel_dropped_events": 7}, Issues: []string{"node_loss_during_capture"}}
	put(t, db, paths, "r", "runtime_capture", "capture/r", r)
	if _, err := db.Exec(`INSERT INTO telemetry_native_counters(name,value) VALUES ('kernel_dropped_events',99999)`); err != nil {
		t.Fatal(err)
	}
	got := all(t, db, "r", 1)
	if len(got) != 1 || got[0].IntervalBasis != "boundary_samples" || got[0].ProducerVersion != "unknown" || got[0].Placement != "local_kernel" {
		t.Fatalf("manifest: %+v", got)
	}
	p := got[0]
	if len(p.Snapshots) != 2 || p.Loss[0].Value != nil || p.Loss[1].Scope != "node" || *p.Loss[1].Value != "7" {
		t.Fatalf("counter scope lost: %+v", p)
	}
	features := p.Snapshots[0].Features
	if features[0].Enabled == nil || !*features[0].Enabled || features[1].Supported == nil || *features[1].Supported || features[2].Supported != nil || *features[2].Enabled {
		t.Fatalf("support and enabled merged: %+v", features)
	}
	if all(t, db, "other", 1) == nil || len(all(t, db, "other", 1)) != 0 {
		t.Fatal("foreign run included")
	}
	unknown := sensorSnapshot("start", sensor.CapabilityReport{Ready: true, Probes: before.Probes})
	if unknown.Ready != nil || len(unknown.Features) != 0 || unknown.Status != "unknown" {
		t.Fatalf("legacy snapshot upgraded: %+v", unknown)
	}
}

func TestCaptureManifestKeepsAllSourcesAndRevisions(t *testing.T) {
	db, paths := testStore(t)
	for i := 0; i < 260; i++ {
		p, _ := agentcontext.NewCapturePolicy("basic", nil)
		c := agentcontext.Coverage{SchemaVersion: agentcontext.SchemaVersion, ID: fmt.Sprintf("coverage-%d", i), RunID: "r", Status: agentcontext.Partial,
			Source: agentcontext.Source{ID: fmt.Sprintf("source-%d", i), Harness: "notebook", SessionID: "same", ParserVersion: "notebook/v1",
				Notebook: &agentcontext.NotebookScope{ProducerID: "p", Namespace: "n", InstanceID: "i", Generation: fmt.Sprint(i), NotebookID: "nb", KernelID: "k", KernelSessionID: "ks"}},
			CapturePolicy: &p, Counts: agentcontext.Counts{Truncated: ptr(int64(3))}}
		put(t, db, paths, "r", "agent_context_coverage", c.ID, c)
	}
	got := all(t, db, "r", 17)
	if len(got) != 260 {
		t.Fatalf("sources truncated: %d", len(got))
	}
	seen := map[string]bool{}
	for _, r := range got {
		if seen[r.ID] || r.Identity["session_id"] != "same" || r.IdentityDomain != "notebook" || len(r.Retention) != 5 || *r.Retention[0].Enabled {
			t.Fatalf("merged identity or retained basic body: %+v", r)
		}
		seen[r.ID] = true
	}
	page, err := (Service{db}).List(context.Background(), Options{RunID: "r", Limit: 1})
	if err != nil || page.NextCursor == "" {
		t.Fatalf("cursor: %+v %v", page, err)
	}
	if _, err := (Service{db}).List(context.Background(), Options{RunID: "other", Cursor: page.NextCursor}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cross-run cursor: %v", err)
	}
	for _, opts := range []Options{{}, {RunID: "r", Limit: 201}, {RunID: "r", Cursor: "bad"}, {RunID: "r\x00"}} {
		if _, err := (Service{db}).List(context.Background(), opts); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid options accepted: %+v %v", opts, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (Service{db}).List(ctx, Options{RunID: "r"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

func TestNativeCheckpointPreservesGenerationAndCollectorBoundary(t *testing.T) {
	db, paths := testStore(t)
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	for _, generation := range []string{"original", "clone"} {
		c := handoff.Checkpoint{SchemaVersion: handoff.SchemaVersion, AttemptID: "attempt-" + generation, Revision: 1, At: now,
			Source: handoff.Source{ProducerID: "caller", Namespace: "n", RunID: "upstream", Harness: "claude", SessionID: "session", ToolCallID: "call"},
			Target: handoff.Target{ProducerID: "guest", InstanceID: "i", Generation: generation}, State: handoff.State{Capture: handoff.Incomplete},
			Scope: &record.ExecutionScope{RunID: "r", CgroupID: "42", ScopeKind: "cgroup"},
			Capture: &handoff.NativeCaptureReport{SchemaVersion: "agentprovenance.execution_native_capture/v2", Issues: []string{"shared_collector_loss"},
				Start:         &handoff.NativeCapturePoint{Scope: record.ExecutionScope{RunID: "r"}, Capabilities: caps(now, "attached"), Sensor: sensor.CaptureBoundary{CollectorID: "a", ObservedAt: now, KernelDrops: 9007199254740993}},
				End:           &handoff.NativeCapturePoint{Scope: record.ExecutionScope{RunID: "r"}, Capabilities: caps(now, "attached"), Sensor: sensor.CaptureBoundary{CollectorID: "b", ObservedAt: now.Add(time.Second)}},
				ScopeProgress: &telemetry.NativePrefixProgress{Dropped: 2, Pending: 3}}}
		c.Capture.Start.Capabilities.Producer = &sensor.CapabilityProducer{Name: "agentprov-sensor", Version: "captured", Commit: "captured-sha", Placement: "guest_kernel"}
		put(t, db, paths, "r", "execution_checkpoint", c.AttemptID, c)
	}
	got := all(t, db, "r", 1)
	if len(got) != 2 || got[0].Identity["generation"] == got[1].Identity["generation"] {
		t.Fatalf("clone merged: %+v", got)
	}
	for _, r := range got {
		if r.Identity["producer_id"] != "guest" || r.Identity["sensor_name"] != "agentprov-sensor" || r.Placement != "guest_kernel" {
			t.Fatalf("executor identity replaced by sensor metadata: %+v", r)
		}
		if r.IntervalBasis != "boundary_samples" || *r.Loss[0].Value != "9007199254740993" || !strings.Contains(strings.Join(r.Issues, ","), "collector_changed") ||
			r.Snapshots[0].Identity["collector_id"] != "a" || r.Snapshots[1].Identity["collector_id"] != "b" || r.Loss[0].ScopeID != "a" || r.Loss[3].ScopeID != "b" {
			t.Fatalf("source evidence changed: %+v", r)
		}
	}
}

func TestSentryManifestKeepsDeclaredAndObservedDistinct(t *testing.T) {
	db, paths := testStore(t)
	_ = paths
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	for _, generation := range []string{"a", "b"} {
		caps := seccheck.ReceiverCapabilities()
		caps.ProducerVersion, caps.ProducerCommit = "captured-version", "captured-commit"
		r := seccheck.Record{Kind: "stream", Reason: "connected", ConnectionID: "connection", Sequence: 1, ReceivedAt: now,
			Registration: seccheck.Registration{Namespace: "n", InstanceID: "i", Generation: generation, SandboxID: "s", ContainerID: "c"},
			Capabilities: &caps}
		e, err := telemetry.MapSecCheckRecord("r", r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := telemetry.IngestFiltered(db, e); err != nil {
			t.Fatal(err)
		}
	}
	got := all(t, db, "r", 1)
	if len(got) != 2 || got[0].Identity["generation"] == got[1].Identity["generation"] {
		t.Fatalf("Sentry lifetime merged: %+v", got)
	}
	for _, r := range got {
		if r.ProducerVersion != "captured-version" || r.Placement != "host_receiver" || r.IdentityDomain != "sentry" || r.Loss[0].Value != nil {
			t.Fatalf("Sentry facts: %+v", r)
		}
		if f := r.Snapshots[0].Features[0]; f.Supported == nil || !*f.Supported || f.Enabled != nil {
			t.Fatalf("support advertised as enabled: %+v", f)
		}
	}
	if _, err := db.Exec(`UPDATE events SET container_id='tampered' WHERE run_id='r'`); err != nil {
		t.Fatal(err)
	}
	if _, err := (Service{db}).List(context.Background(), Options{RunID: "r"}); err == nil {
		t.Fatal("invalid Sentry identity accepted")
	}
}

func TestSignedManifestFactsSurviveImportWithoutSourceStore(t *testing.T) {
	db, paths := testStore(t)
	policy, _ := agentcontext.NewCapturePolicy("basic", nil)
	_, err := (agentcontext.Service{DB: db, Paths: paths, CapturePolicy: &policy}).Save(context.Background(), "r",
		agentcontext.Source{Harness: "fixture", SessionID: "s", ParserVersion: "test/v1", Binding: "explicit"}, nil, agentcontext.Coverage{Status: agentcontext.Empty})
	if err != nil {
		t.Fatal(err)
	}
	c := observability.RuntimeCaptureReport{SchemaVersion: observability.RuntimeCaptureSchema, RunID: "r", KernelState: "disabled", Status: "disabled"}
	if err := observability.SaveRuntimeCapture(db, paths, &c); err != nil {
		t.Fatal(err)
	}
	before := all(t, db, "r", 50)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key}).ExportBundle("r")
	if err != nil {
		t.Fatal(err)
	}
	if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, pub); err != nil {
		t.Fatal(err)
	}
	dst, destPaths := testStore(t)
	if _, err := (forensics.Service{DB: dst, Paths: destPaths}).ImportBundle(bundle.Path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(paths.Provenance, paths.Provenance+"-unavailable"); err != nil {
		t.Fatal(err)
	}
	after := all(t, dst, "r", 1)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("manifest changed after signed import:\n%+v\n%+v", before, after)
	}
	dst.Close()
	if _, err := (Service{dst}).List(context.Background(), Options{RunID: "r"}); err == nil {
		t.Fatal("closed database reported empty success")
	}
}

func TestManifestRejectsMismatchedOrInvalidEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, kind string
		value      any
	}{
		{"run", "runtime_capture", observability.RuntimeCaptureReport{SchemaVersion: observability.RuntimeCaptureSchema, RunID: "foreign"}},
		{"policy", "context_capture_policy", agentcontext.CapturePolicy{Version: agentcontext.CapturePolicyVersion, Preset: "basic", History: true}},
		{"settings", "run_capture_settings", observability.CaptureSettings{Version: observability.CaptureSettingsVersion}},
		{"context", "agent_context_coverage", agentcontext.Coverage{SchemaVersion: agentcontext.SchemaVersion, ID: "c", RunID: "foreign"}},
		{"embedded-policy", "agent_context_coverage", agentcontext.Coverage{SchemaVersion: agentcontext.SchemaVersion, ID: "c", RunID: "r", CapturePolicy: &agentcontext.CapturePolicy{Preset: "invalid"}}},
		{"conflicting-domain", "agent_context_coverage", agentcontext.Coverage{SchemaVersion: agentcontext.SchemaVersion, ID: "c", RunID: "r", Source: agentcontext.Source{Browser: &agentcontext.BrowserScope{}, Notebook: &agentcontext.NotebookScope{}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, paths := testStore(t)
			put(t, db, paths, "r", tc.kind, tc.name, tc.value)
			if _, err := (Service{db}).List(context.Background(), Options{RunID: "r"}); err == nil {
				t.Fatal("invalid saved evidence accepted")
			}
		})
	}
}

func TestManifestRejectsCorruptObject(t *testing.T) {
	db, paths := testStore(t)
	ref := put(t, db, paths, "r", "runtime_capture", "capture", observability.RuntimeCaptureReport{SchemaVersion: observability.RuntimeCaptureSchema, RunID: "r"})
	var path string
	if err := db.QueryRow(`SELECT path FROM provenance_objects WHERE run_id='r' AND hash=?`, ref).Scan(&path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"payload":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Service{db}).List(context.Background(), Options{RunID: "r"}); err == nil {
		t.Fatal("corrupt object reported as capture evidence")
	}
}

func TestCaptureCapabilityIntervalsSignedRoundTrip(t *testing.T) {
	db, paths := testStore(t)
	start := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	var first, last sensor.CapabilityReport
	for i, status := range []string{"ready", "degraded", "ready"} {
		at := timestamp(start.Add(time.Duration(i) * time.Second))
		c := sensor.CapabilityReport{SchemaVersion: "agentprovenance.sensor_capabilities/v1", CollectorID: "collector-signed", Revision: uint64(i + 1), ChangedAt: at, UpdatedAt: at, Ready: true, Status: status,
			Producer: &sensor.CapabilityProducer{Name: "agentprov-sensor", Version: "captured-version", Commit: "captured-commit", Architecture: "arm64", OS: "linux", Placement: "guest_kernel", PlacementBasis: "operator_configuration"}}
		if err := sensor.SaveCapabilityChange(paths.Logs, c); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = c
		}
		last = c
	}
	history, err := observability.SaveCapabilityHistory(context.Background(), db, paths, "history", first, last, start, start.Add(3*time.Second))
	if err != nil || history.Saved != 3 {
		t.Fatalf("save: %+v %v", history, err)
	}
	before := all(t, db, "history", 1)
	if len(before) != 3 {
		t.Fatalf("missing intervals: %d", len(before))
	}
	for _, r := range before {
		if r.ProducerVersion != "captured-version" || r.ProducerCommit != "captured-commit" || r.Placement != "guest_kernel" || r.IntervalBasis != "recorded_capability_changes" || r.Identity["collector_id"] != "collector-signed" || len(r.Snapshots) != 1 {
			t.Fatalf("changed capture provenance: %+v", r)
		}
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := (forensics.Service{DB: db, Paths: paths, SignKey: key}).ExportBundle("history")
	if err != nil {
		t.Fatal(err)
	}
	if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, pub); err != nil {
		t.Fatal(err)
	}
	dst, destPaths := testStore(t)
	if _, err := (forensics.Service{DB: dst, Paths: destPaths}).ImportBundle(bundle.Path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(paths.Provenance, paths.Provenance+"-held"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(paths.Logs, paths.Logs+"-held"); err != nil {
		t.Fatal(err)
	}
	if got := all(t, dst, "history", 2); !reflect.DeepEqual(got, before) {
		t.Fatalf("import changed intervals: %+v", got)
	}
}
