package dashboard

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/byteyellow/agentprovenance/internal/staticdata"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestTLSMetadataInLiveAndStaticReplay(t *testing.T) {
	db := newDashboardTestDB(t)
	s := Server{DB: db}
	const run = "tls-metadata-replay"
	input := filepath.Join(t.TempDir(), "capture.jsonl")
	raw := `{"event_type":"tls_read","protocol":"h2","stream_id":3,"headers_decoded":true,"status":200,"content_type":"text/event-stream","model":"m","data":"{}","length":2,"time":"2026-10-17T00:00:00Z"}`
	if err := os.WriteFile(input, []byte(raw+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := telemetry.IngestJSONL(db, telemetry.JSONLIngestOptions{Format: "native", Path: input, RunID: run})
	if err != nil || result.Ingested != 1 {
		t.Fatalf("ingest %+v %v", result, err)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/api/events?run="+run, nil))
	if rr.Code != 200 {
		t.Fatalf("events status %d: %s", rr.Code, rr.Body.String())
	}
	var live struct {
		Events []telemetry.EventRecord `json:"events"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &live); err != nil {
		t.Fatal(err)
	}
	if len(live.Events) != 1 {
		t.Fatalf("live event response: %s", rr.Body.String())
	}
	for _, field := range []string{`"protocol":"h2"`, `"stream_id":3`, `"status":200`, `"is_stream":true`, `"headers_decoded":true`} {
		if !strings.Contains(live.Events[0].Payload, field) {
			t.Fatalf("missing %s in live payload %s", field, live.Events[0].Payload)
		}
	}
	root := t.TempDir()
	replay, err := s.ExportReplay(context.Background(), run, &staticdata.Writer{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(root, replay.Events.Path))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	var saved []telemetry.EventRecord
	if err := json.NewDecoder(gz).Decode(&saved); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(saved, live.Events) {
		t.Fatalf("metadata changed in static replay: live=%+v saved=%+v", live.Events, saved)
	}
}
