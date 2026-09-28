package forensics_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/agentcontext"
	"github.com/byteyellow/agentprovenance/internal/forensics"
	"github.com/byteyellow/agentprovenance/internal/observability"
	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/sensor"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestSignedRuntimeCoverageSurvivesOfflineHTTPQuery(t *testing.T) {
	pathsA := mustInit(t, filepath.Join(t.TempDir(), "capture"))
	dbA := mustOpen(t, pathsA)
	defer dbA.Close()
	s := agentcontext.Service{DB: dbA, Paths: pathsA}
	if _, err := s.Save(context.Background(), "run", agentcontext.Source{Harness: "deepseek", SessionID: "s", ParserVersion: "test/v1", Binding: "explicit"}, nil, agentcontext.Coverage{Status: agentcontext.Empty}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	before := observability.CaptureSnapshot{ObservedAt: now,
		Native:       &telemetry.NativeStreamStatus{Counters: map[string]int64{"kernel_dropped_events": 10}},
		Capabilities: &sensor.CapabilityReport{SchemaVersion: "agentprovenance.sensor_capabilities/v1", UpdatedAt: now.Format(time.RFC3339Nano), Ready: true, Status: "ready", Probes: []sensor.ProbeCapability{}}}
	after := observability.CaptureSnapshot{ObservedAt: now.Add(time.Second),
		Native:       &telemetry.NativeStreamStatus{Counters: map[string]int64{"kernel_dropped_events": 12}},
		Capabilities: &sensor.CapabilityReport{SchemaVersion: "agentprovenance.sensor_capabilities/v1", UpdatedAt: now.Add(time.Second).Format(time.RFC3339Nano), Status: "stopped", Probes: []sensor.ProbeCapability{}}}
	capture := observability.BuildRuntimeCapture("run", "observed", before, after, true)
	if err := observability.SaveRuntimeCapture(dbA, pathsA, &capture); err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := (forensics.Service{DB: dbA, Paths: pathsA, SignKey: key}).ExportBundle("run")
	if err != nil {
		t.Fatal(err)
	}
	if err := forensics.VerifyBundleAttestation(bundle.Path, bundle.AttestationPath, pub); err != nil {
		t.Fatal(err)
	}
	pathsB := mustInit(t, filepath.Join(t.TempDir(), "replay"))
	dbB := mustOpen(t, pathsB)
	defer dbB.Close()
	if info, err := (forensics.Service{DB: dbB, Paths: pathsB}).ImportBundle(bundle.Path); err != nil || info.Omitted != 0 {
		t.Fatalf("import: %+v %v", info, err)
	}
	if err := os.Rename(pathsA.Provenance, pathsA.Provenance+"-offline"); err != nil {
		t.Fatal(err)
	}
	if _, err := dbB.Exec(`INSERT INTO telemetry_native_counters(name,value) VALUES ('kernel_dropped_events',5000)`); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	(agentcontext.Service{DB: dbB, Paths: pathsB}).ReadHandler().ServeHTTP(w, httptest.NewRequest("GET", "/context/overview?run=run", nil))
	var output map[string]json.RawMessage
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &output) != nil {
		t.Fatalf("public replay API: %d %s", w.Code, w.Body.Bytes())
	}
	var got observability.RuntimeCoverage
	if err := json.Unmarshal(output["runtime_coverage"], &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Capture, capture) || got.Capture.NodeCounterDelta["kernel_dropped_events"] != 2 || got.Capture.RunDroppedEvents != nil {
		t.Fatalf("historical capture altered: %+v", got.Capture)
	}
	if result, err := provenance.Verify(dbB, "run"); err != nil || result.ErrorCount != 0 {
		t.Fatalf("offline graph: %+v %v", result, err)
	}
}
