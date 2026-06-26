package daemon

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/signals"
	"github.com/byteyellow/agentprovenance/internal/store"
)

// testServer builds a Server backed by a temp SQLite store, bypassing NewServer
// (which requires a Docker driver). The signals endpoint only needs s.DB.
func testServer(t *testing.T) Server {
	t.Helper()
	paths, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return Server{DB: db, Paths: paths, writeMu: &sync.Mutex{}}
}

func TestSignalsEndpointReturnsVersionedSet(t *testing.T) {
	s := testServer(t)
	if _, err := signals.Record(s.DB, signals.Signal{
		Dimension: signals.Security, Type: "policy_violation", RunID: "run-d",
		GraphRefKind: "process", GraphRefID: "p1", Severity: "high", ProducedBy: "security.policy",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := signals.Record(s.DB, signals.Signal{
		Dimension: signals.Quality, Type: "task_success", RunID: "run-d", Label: "pass", Value: 0.9, ProducedBy: "evaluator:x",
	}); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/signals?run=run-d")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var set signals.SignalSet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		t.Fatal(err)
	}
	if set.SchemaVersion != "agentprovenance.signals/v1" {
		t.Fatalf("schema version = %q", set.SchemaVersion)
	}
	if set.Count != 2 || set.Counts["security"] != 1 || set.Counts["quality"] != 1 {
		t.Fatalf("unexpected set: count=%d counts=%v", set.Count, set.Counts)
	}
}

func TestSignalsEndpointFiltersByDimension(t *testing.T) {
	s := testServer(t)
	for _, sig := range []signals.Signal{
		{Dimension: signals.Security, Type: "a", RunID: "run-d", ProducedBy: "x"},
		{Dimension: signals.Quality, Type: "b", RunID: "run-d", ProducedBy: "x"},
	} {
		if _, err := signals.Record(s.DB, sig); err != nil {
			t.Fatal(err)
		}
	}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/signals?run=run-d&dimension=quality")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct {
		Signals []signals.Signal `json:"signals"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Signals) != 1 || body.Signals[0].Type != "b" {
		t.Fatalf("dimension filter wrong: %+v", body.Signals)
	}

	// Invalid dimension is a 400.
	bad, err := http.Get(srv.URL + "/v1/signals?run=run-d&dimension=bogus")
	if err != nil {
		t.Fatal(err)
	}
	bad.Body.Close()
	if bad.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad dimension status = %d, want 400", bad.StatusCode)
	}
}

func TestSignalsEndpointRequiresRun(t *testing.T) {
	s := testServer(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/v1/signals")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing run status = %d, want 400", resp.StatusCode)
	}
}

// TestRecordEndpointRunsAndReturnsRunID covers the daemon record hot-path used
// by high-frequency RL callers to avoid CLI fork-per-trajectory.
func TestRecordEndpointRunsAndReturnsRunID(t *testing.T) {
	s := testServer(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	body, _ := json.Marshal(map[string]any{
		"name":    "daemon-record-test",
		"workdir": t.TempDir(),
		"command": []string{"true"},
	})
	resp, err := http.Post(srv.URL+"/v1/record", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result["run_id"] == nil || result["run_id"] == "" {
		t.Fatalf("missing run_id in record result: %v", result)
	}
	if result["status"] == nil {
		t.Fatalf("missing status in record result: %v", result)
	}
}

func TestRecordEndpointRequiresCommand(t *testing.T) {
	s := testServer(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/v1/record", "application/json", bytes.NewReader([]byte(`{"name":"x"}`)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}
