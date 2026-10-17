package forensics_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/byteyellow/agentprovenance/internal/provenance"
	"github.com/byteyellow/agentprovenance/internal/telemetry"
)

func TestNativeTLSNormalizationAndPairing(t *testing.T) {
	for _, captureBody := range []string{"0", "1"} {
		t.Run("body="+captureBody, func(t *testing.T) {
			t.Setenv("AGENTPROV_TLS_CAPTURE_BODY", captureBody)
			paths := mustInit(t, filepath.Join(t.TempDir(), "capture"))
			db := mustOpen(t, paths)
			defer db.Close()
			var data []byte
			// Deliberately out of ingestion order, with two streams on one
			// connection and the same stream number on another connection.
			for _, item := range []struct {
				conn           string
				stream, second int
				typ            string
			}{
				{"a", 3, 4, "tls_read"}, {"b", 1, 5, "tls_read"},
				{"a", 1, 0, "tls_write"}, {"a", 3, 1, "tls_write"},
				{"b", 1, 2, "tls_write"}, {"a", 1, 6, "tls_read"},
			} {
				raw := map[string]any{"source": "agentprov_ebpf", "event_type": item.typ, "pid": 100, "tgid": 100,
					"cgroup_id": "12", "process_instance_id": "12345678-1234-1234-1234-123456789abc:100:800",
					"protocol": "h2", "headers_decoded": true, "stream_id": item.stream,
					"connection_id": fmt.Sprintf("tls-v1:%x", sha256.Sum256([]byte(item.conn))),
					"timestamp":     time.Date(2026, 1, 1, 0, 0, item.second, 0, time.UTC).Format(time.RFC3339Nano),
					"data":          `{"model":"test-model"}`, "length": 22}
				if item.typ == "tls_write" {
					raw["method"], raw["host"], raw["path"] = "POST", "llm.example", "/v1/messages"
				} else {
					raw["status"] = 200
				}
				line, err := json.Marshal(raw)
				if err != nil {
					t.Fatal(err)
				}
				data = append(append(data, line...), '\n')
			}
			input := filepath.Join(t.TempDir(), "native.jsonl")
			if err := os.WriteFile(input, data, 0600); err != nil {
				t.Fatal(err)
			}
			result, err := telemetry.IngestJSONL(db, telemetry.JSONLIngestOptions{Format: "native", Path: input, RunID: "tls-run"})
			if err != nil || result.Ingested != 6 {
				t.Fatalf("ingest: %+v %v", result, err)
			}
			if n, err := provenance.MaterializeLLMCalls(provenance.ObjectStore{DB: db, Paths: paths}, db, "tls-run"); err != nil || n != 3 {
				t.Fatalf("pairs=%d err=%v", n, err)
			}
			rows, err := db.Query(`SELECT q.payload,r.payload FROM graph_edges g JOIN events q ON g.from_id='runtime_event/'||q.id JOIN events r ON g.to_id='runtime_event/'||r.id WHERE g.edge_type='llm_call'`)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			for rows.Next() {
				var q, r string
				if err := rows.Scan(&q, &r); err != nil {
					t.Fatal(err)
				}
				var request, response struct {
					Content string `json:"content"`
					HTTP    struct {
						Conn   string `json:"connection_id"`
						Stream int    `json:"stream_id"`
					} `json:"http"`
				}
				if json.Unmarshal(unwrapTLSTestPayload(t, q), &request) != nil || json.Unmarshal(unwrapTLSTestPayload(t, r), &response) != nil {
					t.Fatal("invalid payload")
				}
				if request.HTTP != response.HTTP || request.HTTP.Conn == "" {
					t.Fatalf("crossed pair: %s / %s", q, r)
				}
				if (request.Content != "") != (captureBody == "1") {
					t.Fatalf("body setting changed: %s", q)
				}
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func unwrapTLSTestPayload(t *testing.T, payload string) []byte {
	t.Helper()
	data := []byte(payload)
	for depth := 0; depth < 4; depth++ {
		var body struct{ Payload, Raw json.RawMessage }
		if err := json.Unmarshal(data, &body); err != nil {
			t.Fatal(err)
		}
		if len(body.Payload) > 0 {
			data = body.Payload
		} else if len(body.Raw) > 0 {
			data = body.Raw
		} else {
			return data
		}
	}
	t.Fatal("unexpected nested payload")
	return nil
}

// Uses the saved output of scripts/accept_sensor_live.py, without running the
// historical commands again. The default test suite needs no external fixture.
func TestRecordedNativeTLSExchangePairing(t *testing.T) {
	input := os.Getenv("AGENTPROV_TLS_PAIRING_JSONL")
	if input == "" {
		t.Skip("set AGENTPROV_TLS_PAIRING_JSONL to a native live-acceptance JSONL capture")
	}
	t.Setenv("AGENTPROV_TLS_CAPTURE_BODY", "1")
	paths := mustInit(t, filepath.Join(t.TempDir(), "recorded"))
	db := mustOpen(t, paths)
	defer db.Close()
	result, err := telemetry.IngestJSONL(db, telemetry.JSONLIngestOptions{Format: "native", Path: input, RunID: "recorded-tls"})
	if err != nil || result.Failed != 0 {
		t.Fatalf("ingest: %+v %v", result, err)
	}
	n, err := provenance.MaterializeLLMCalls(provenance.ObjectStore{DB: db, Paths: paths}, db, "recorded-tls")
	if err != nil || n != 3 {
		t.Fatalf("Python + C legacy/ex pairs=%d err=%v, want 3", n, err)
	}
	var unpaired int
	if err := db.QueryRow(`SELECT count(*) FROM events e WHERE e.event_type='tls_write' AND NOT EXISTS (SELECT 1 FROM graph_edges g WHERE g.from_id='runtime_event/'||e.id AND g.edge_type='llm_call')`).Scan(&unpaired); err != nil || unpaired != 1 {
		t.Fatalf("Go write-only evidence=%d err=%v, want 1", unpaired, err)
	}
	t.Logf("saved native capture: %d events, %d OpenSSL exchanges, %d unpaired Go request", result.Ingested, n, unpaired)
}
